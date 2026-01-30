#!/usr/bin/env python3
# MRET: requires_args
# MRET: args_info: scan (select & decompile APK) | code (select codebase via dialog)
"""
Semgrep Android Security Scanner

Usage:
    semgrep_scan.py scan     - Show APK selection, decompile with jadx, and scan
    semgrep_scan.py code     - Open file dialog to select existing source code

Features:
- APK selection with fuzzy search
- Automatic APK decompilation using jadx-cli
- Automatically clones mindedsecurity/semgrep-rules-android-security
- GUI prompts for directory/file selection
- Runs semgrep against the target using Android-specific security rules
- Generates both JSON and HTML reports with syntax highlighting
- Cleans up temporary files after scanning

Requires:
- git
- semgrep (CLI) in PATH
- jadx (CLI) in PATH (for APK scanning)
"""

import argparse
import glob
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import queue
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    HAS_TK = True
except ImportError:
    HAS_TK = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.live import Live
    from rich.panel import Panel
    from prompt_toolkit import prompt as pt_prompt
    from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
    from prompt_toolkit.formatted_text import HTML as PT_HTML
    from prompt_toolkit.validation import Validator, ValidationError
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

RULES_REPO = "https://github.com/mindedsecurity/semgrep-rules-android-security.git"
HERE = Path(__file__).resolve().parent

# Initialize rich console if available
console = Console() if HAS_RICH else None

if not console:
    class FakeConsole:
        def print(self, *args, **kwargs):
            import re
            text = str(args[0]) if args else ""
            text = re.sub(r'\[.*?\]', '', text)
            print(text)
    console = FakeConsole()


# =============================================================================
# Utility Functions
# =============================================================================

def get_toolkit_root() -> Path:
    """Get the root directory of the Mobile-RE-Toolkit."""
    for parent in HERE.parents:
        if (parent / "main.py").exists():
            return parent
    return Path.cwd()


def get_default_apk_dirs() -> List[Path]:
    """Get default directories to scan for APKs."""
    workspace = get_toolkit_root()
    return [
        workspace / "src",
        workspace / "src" / "output" / "pulled_apks",
        workspace / "src" / "pulled_apks",
    ]


def _run(cmd, cwd=None):
    """Execute a command and return (returncode, stdout, stderr)."""
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr


# =============================================================================
# APK Selection with Fuzzy Search
# =============================================================================

def scan_apks_worker(dirs: List[Path], out_q: queue.Queue):
    """Background worker to scan for APK files."""
    apks = []
    for d in dirs:
        if not d.exists():
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if f.endswith('.apk'):
                    apks.append(Path(root) / f)
    apks.sort(key=lambda p: p.name.lower())
    out_q.put(apks)


class APKCompleter(Completer):
    """Completer that supports both number and fuzzy name matching."""
    def __init__(self, apk_paths: List[Path]):
        self.apk_paths = apk_paths
        self.filenames = [p.name for p in apk_paths]

    def get_completions(self, document, complete_event):
        text = document.text.strip()
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.apk_paths):
                yield Completion(text, start_position=-len(text), display=f"#{idx} -> {self.filenames[idx-1]}")
            return
        lower = text.lower()
        matches = []
        for name in self.filenames:
            if not text or self._fuzzy_match(lower, name.lower()):
                matches.append(name)
        matches.sort(key=lambda n: (not n.lower().startswith(lower), len(n), n.lower()))
        for name in matches:
            yield Completion(name, start_position=-len(text), display=name)

    @staticmethod
    def _fuzzy_match(pattern: str, text: str) -> bool:
        i = 0
        for ch in text:
            if i < len(pattern) and ch == pattern[i]:
                i += 1
        return i == len(pattern)


class NumberOrNameValidator(Validator):
    """Validator that accepts either a valid number or a filename."""
    def __init__(self, count: int, names: List[str]):
        self.count = count
        self.names = set(names)

    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message='Type a number or start typing a name')
        if t.isdigit():
            idx = int(t)
            if 1 <= idx <= self.count:
                return
            raise ValidationError(message=f'Number must be 1..{self.count}')
        return


def select_apk_interactive() -> Optional[Path]:
    """Interactive APK selection with table and fuzzy search."""
    if not HAS_RICH:
        console.print("[!] APK selection requires 'rich' and 'prompt_toolkit' packages.")
        return None
    
    console.print("[bold cyan]📱 Semgrep Android Security Scanner[/bold cyan]")
    console.print("[dim]APK selection mode - select an APK to decompile and scan[/dim]\n")
    
    # Check for jadx
    jadx_path = find_jadx_cli()
    if not jadx_path:
        console.print('[red]❌ jadx (CLI) not found in PATH[/red]')
        console.print('[yellow]💡 Please install JADX:[/yellow]')
        console.print('   • macOS: [cyan]brew install jadx[/cyan]')
        console.print('   • Or download from: [cyan]https://github.com/skylot/jadx/releases[/cyan]')
        return None
    
    console.print(f'[green]✅ jadx found: {jadx_path}[/green]')
    console.print('[cyan]🔍 Scanning for APKs...[/cyan]')
    
    # Scan for APKs in background
    dirs = get_default_apk_dirs()
    q = queue.Queue()
    t = threading.Thread(target=scan_apks_worker, args=(dirs, q), daemon=True)
    t.start()
    apks: List[Path] = q.get()
    
    if not apks:
        console.print('[red]❌ No APKs found in the following directories:[/red]')
        for d in dirs:
            exists = "✅" if d.exists() else "❌"
            console.print(f'  {exists} {d}')
        return None
    
    console.print(f'[green]📦 Found {len(apks)} APK files[/green]\n')
    
    # Show table
    table = Table(title='Available APK Files', show_header=True, header_style='bold magenta')
    table.add_column('Index', justify='center', style='cyan', no_wrap=True, width=8)
    table.add_column('APK Name', style='green', min_width=20)
    table.add_column('Full Path', style='dim', overflow='ellipsis')
    
    for i, apk in enumerate(apks, 1):
        table.add_row(str(i), apk.name, str(apk))
    console.print(table)
    
    names = [p.name for p in apks]
    completer = FuzzyCompleter(APKCompleter(apks))
    validator = NumberOrNameValidator(len(apks), names)
    
    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print("  • Start typing an APK name for fuzzy search")
    console.print("  • Use Tab for autocompletion\n")
    
    try:
        answer = pt_prompt(
            PT_HTML('<cyan>Enter # or start typing name:</cyan> '),
            completer=completer,
            complete_while_typing=True,
            validator=validator,
            validate_while_typing=True
        ).strip()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Selection cancelled[/yellow]")
        return None
    
    # Resolve selection
    if answer.isdigit():
        choice = int(answer)
        apk_path = apks[choice - 1]
    else:
        lower = answer.lower()
        best = None
        best_key = (True, 10**9, '')
        for p in apks:
            name_l = p.name.lower()
            def fuzzy_ok(pat, txt):
                i = 0
                for ch in txt:
                    if i < len(pat) and ch == pat[i]:
                        i += 1
                return i == len(pat)
            if fuzzy_ok(lower, name_l):
                key = (not name_l.startswith(lower), len(p.name), name_l)
                if key < best_key:
                    best_key = key
                    best = p
        apk_path = best if best else apks[0]
    
    console.print(f"\n[green]🎯 Selected:[/green] {apk_path.name}")
    console.print(f"[dim]Path: {apk_path}[/dim]")
    
    if not apk_path.exists():
        console.print(f"[red]❌ APK file not found: {apk_path}[/red]")
        return None
    
    return apk_path


# =============================================================================
# JADX Decompilation
# =============================================================================

def find_jadx_cli() -> Optional[str]:
    """Find jadx (CLI) executable in PATH or common installation locations."""
    jadx_path = shutil.which('jadx')
    if jadx_path and os.access(jadx_path, os.X_OK):
        return jadx_path
    
    common_paths = [
        '/opt/homebrew/bin/jadx',
        '/usr/local/bin/jadx',
        '/usr/bin/jadx',
        os.path.expanduser('~/bin/jadx'),
        os.path.expanduser('~/jadx/bin/jadx'),
    ]
    
    tools_dirs = [
        os.path.expanduser('~/LocalDocuments/Tools/jadx-*/bin/jadx'),
        os.path.expanduser('~/Tools/jadx-*/bin/jadx'),
        os.path.expanduser('~/Documents/Tools/jadx-*/bin/jadx'),
    ]
    for pattern in tools_dirs:
        matches = glob.glob(pattern)
        if matches:
            common_paths.extend(matches)
    
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    return None


def decompile_apk(apk_path: Path, output_dir: Path, jadx_path: str) -> Optional[Path]:
    """Decompile an APK using jadx-cli."""
    decompiled_dir = output_dir / "sources"
    
    console.print(f"[cyan]📦 Decompiling APK: {apk_path.name}[/cyan]")
    console.print(f"[dim]Output: {decompiled_dir}[/dim]")
    
    os.makedirs(decompiled_dir, exist_ok=True)
    
    # Check if already decompiled
    if decompiled_dir.exists() and any(decompiled_dir.iterdir()):
        console.print(f"[yellow]Using existing decompiled sources: {decompiled_dir}[/yellow]")
        return decompiled_dir
    
    cmd = [jadx_path, "-d", str(decompiled_dir), "--deobf", str(apk_path)]
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Check if output directory has files (jadx may return non-zero but still work)
        has_output = False
        if decompiled_dir.exists():
            for root, dirs, files in os.walk(decompiled_dir):
                if files:
                    has_output = True
                    break
        
        if result.returncode == 0 or has_output:
            console.print(f"[green]✅ Decompilation complete[/green]")
            if result.stderr and result.returncode != 0:
                console.print(f"[yellow]⚠️ Warnings: {result.stderr[:500]}[/yellow]")
            return decompiled_dir
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            console.print(f"[red]❌ Decompilation failed (exit code {result.returncode})[/red]")
            console.print(f"[red]Error: {error_msg[:1000]}[/red]")
            return None
    except subprocess.TimeoutExpired:
        console.print("[red]❌ Decompilation timed out (10 min limit)[/red]")
        return None
    except FileNotFoundError:
        console.print(f"[red]❌ jadx executable not found at: {jadx_path}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]❌ Decompilation error: {e}[/red]")
        return None


# =============================================================================
# GUI Dialogs
# =============================================================================

def pick_directory(title: str, initial_dir: str = None) -> Optional[str]:
    """Open a GUI dialog to pick a directory."""
    if not HAS_TK:
        console.print("[red]Error: tkinter not available for GUI dialog[/red]")
        return None
    
    root = tk.Tk()
    root.withdraw()
    root.update()
    
    if initial_dir is None:
        default_output = get_toolkit_root() / "src" / "output"
        if default_output.exists():
            initial_dir = str(default_output)
    
    path = filedialog.askdirectory(title=title, mustexist=True, initialdir=initial_dir)
    root.destroy()
    return path


def show_completion_dialog(title: str, message: str):
    """Show a GUI completion dialog."""
    if not HAS_TK:
        return
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(title, message)
    root.destroy()


# =============================================================================
# HTML Report Generation
# =============================================================================

def clean_rule_id(check_id: str) -> str:
    """Clean up the Semgrep rule ID to remove temp path prefixes."""
    if not check_id:
        return "unknown"
    
    parts = check_id.split(".")
    
    for part in parts:
        if part.startswith("MSTG-") or part.startswith("CWE-"):
            return part
    
    if "rules" in parts:
        rules_idx = parts.index("rules")
        if rules_idx + 1 < len(parts):
            return ".".join(parts[rules_idx:])
    
    meaningful_parts = []
    skip_prefixes = ["var", "folders", "T", "semgrep", "android", "security"]
    
    for part in reversed(parts):
        if part.lower() in skip_prefixes or part.startswith("semgrep_android_rules_"):
            break
        if len(part) > 2:
            meaningful_parts.insert(0, part)
    
    if meaningful_parts:
        return ".".join(meaningful_parts[-3:])
    
    return parts[-1] if parts else "unknown"


def get_code_snippet(finding: dict, max_lines: int = 10) -> str:
    """Extract code snippet from finding, with fallback to reading the file directly."""
    lines = finding.get("extra", {}).get("lines", "")
    
    if lines and lines.strip() and lines.strip().lower() not in ["requires login", "n/a", "none"]:
        return lines
    
    file_path = finding.get("path", "")
    start_info = finding.get("start", {})
    end_info = finding.get("end", {})
    
    start_line = start_info.get("line", 0)
    end_line = end_info.get("line", start_line)
    
    if file_path and os.path.exists(file_path) and start_line > 0:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                all_lines = f.readlines()
            
            start_idx = max(0, start_line - 1)
            end_idx = min(len(all_lines), end_line)
            
            if end_idx - start_idx > max_lines:
                end_idx = start_idx + max_lines
            
            snippet_lines = all_lines[start_idx:end_idx]
            return "".join(snippet_lines).rstrip()
        except Exception:
            pass
    
    return f"[Code at {file_path}:{start_line}-{end_line}]" if file_path else "[Code not available]"


def generate_html_report(json_path: str, html_path: str, target_dir: str) -> bool:
    """Generate an HTML report from the Semgrep JSON output."""
    try:
        data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[!] Could not parse JSON for HTML report: {e}")
        return False
    
    results = data.get("results", [])
    errors = data.get("errors", [])
    
    severity_order = ["HIGH", "MEDIUM", "LOW"]
    by_severity = defaultdict(list)
    for r in results:
        metadata = r.get("extra", {}).get("metadata", {})
        impact = metadata.get("impact", "").upper()
        
        if impact in severity_order:
            sev = impact
        else:
            raw_sev = r.get("extra", {}).get("severity", "INFO").upper()
            sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(raw_sev, "MEDIUM")
        
        by_severity[sev].append(r)
    
    by_rule = defaultdict(list)
    for r in results:
        rule_id = clean_rule_id(r.get("check_id", "unknown"))
        by_rule[rule_id].append(r)
    
    severity_counts = {sev: len(by_severity.get(sev, [])) for sev in severity_order}
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Semgrep Android Security Scan Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/java.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/kotlin.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/xml.min.js"></script>
    <style>
        :root {{
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --bg-code: #0f0f23;
            --text-primary: #eaeaea;
            --text-secondary: #a0a0a0;
            --accent-red: #e94560;
            --accent-orange: #f39c12;
            --accent-yellow: #f1c40f;
            --accent-green: #2ecc71;
            --accent-blue: #3498db;
            --border-color: #2d3748;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-dark) 100%);
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }}
        header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-green));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        header .subtitle {{ color: var(--text-secondary); font-size: 1.1rem; }}
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
            text-align: left;
            padding: 20px;
            background: var(--bg-code);
            border-radius: 8px;
        }}
        .meta-info div {{ padding: 10px; }}
        .meta-info strong {{ color: var(--accent-blue); }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }}
        .card h3 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .card.high h3 {{ color: var(--accent-red); }}
        .card.medium h3 {{ color: var(--accent-orange); }}
        .card.low h3 {{ color: var(--accent-blue); }}
        .card.total h3 {{ color: var(--accent-green); }}
        .card p {{ color: var(--text-secondary); text-transform: uppercase; font-size: 0.85rem; letter-spacing: 1px; }}
        .section {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid var(--border-color);
        }}
        .section h2 {{
            color: var(--accent-blue);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }}
        .finding {{
            background: var(--bg-code);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--accent-blue);
        }}
        .finding.severity-high {{ border-left-color: var(--accent-red); }}
        .finding.severity-medium {{ border-left-color: var(--accent-orange); }}
        .finding.severity-low {{ border-left-color: var(--accent-blue); }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }}
        .finding-title {{ font-weight: 600; font-size: 1.1rem; color: var(--text-primary); }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        .severity-badge.high {{ background: rgba(233, 69, 96, 0.2); color: var(--accent-red); }}
        .severity-badge.medium {{ background: rgba(243, 156, 18, 0.2); color: var(--accent-orange); }}
        .severity-badge.low {{ background: rgba(52, 152, 219, 0.2); color: var(--accent-blue); }}
        .finding-header-row {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-bottom: 10px; }}
        .finding-location {{ color: var(--text-secondary); font-size: 0.9rem; word-break: break-all; flex: 1; }}
        .finding-location strong {{ color: var(--accent-green); }}
        .finding-badges {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .confidence-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
        .confidence-badge.high {{ background: rgba(46, 204, 113, 0.2); color: var(--accent-green); }}
        .confidence-badge.medium {{ background: rgba(241, 196, 15, 0.2); color: var(--accent-yellow); }}
        .confidence-badge.low, .confidence-badge.unknown {{ background: rgba(149, 165, 166, 0.2); color: #95a5a6; }}
        .owasp-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; background: rgba(155, 89, 182, 0.2); color: #9b59b6; }}
        .finding-message {{ color: var(--text-secondary); margin-bottom: 15px; font-style: italic; }}
        .code-block-wrapper {{
            display: flex;
            background: #282c34;
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
            font-size: 0.85rem;
            line-height: 1.6;
        }}
        .line-numbers {{
            background: #21252b;
            padding: 12px 10px;
            text-align: right;
            user-select: none;
            border-right: 1px solid var(--border-color);
            min-width: 45px;
        }}
        .line-numbers pre {{ margin: 0; color: #636d83; font-size: 0.85rem; line-height: 1.6; }}
        .code-content {{ flex: 1; overflow-x: auto; padding: 12px 15px; }}
        .code-content pre {{ margin: 0; background: transparent !important; padding: 0 !important; }}
        .code-content code {{ background: transparent !important; padding: 0 !important; font-size: 0.85rem; line-height: 1.6; }}
        .code-content .hljs {{ background: transparent !important; padding: 0 !important; }}
        .collapsible {{ cursor: pointer; user-select: none; }}
        .collapsible::before {{ content: '▶ '; display: inline-block; transition: transform 0.2s; }}
        .collapsible.active::before {{ transform: rotate(90deg); }}
        .collapsible-content {{ display: none; padding-top: 15px; }}
        .collapsible-content.show {{ display: block; }}
        .rule-group {{ margin-bottom: 20px; }}
        .rule-header {{
            background: var(--bg-code);
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .rule-count {{ background: var(--accent-blue); color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; }}
        .no-findings {{ text-align: center; padding: 40px; color: var(--text-secondary); }}
        .no-findings .icon {{ font-size: 4rem; margin-bottom: 20px; }}
        footer {{ text-align: center; padding: 30px; color: var(--text-secondary); font-size: 0.9rem; }}
        footer a {{ color: var(--accent-blue); text-decoration: none; }}
        footer a:hover {{ text-decoration: underline; }}
        @media (max-width: 768px) {{
            header h1 {{ font-size: 1.8rem; }}
            .finding-header {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Semgrep Android Security Scan</h1>
            <p class="subtitle">Automated security analysis using Android-specific rules</p>
            <div class="meta-info">
                <div><strong>Target:</strong> {html.escape(target_dir)}</div>
                <div><strong>Scan Time:</strong> {scan_time}</div>
                <div><strong>Rules Source:</strong> mindedsecurity/semgrep-rules-android-security</div>
                <div><strong>Total Findings:</strong> {len(results)}</div>
            </div>
        </header>
        
        <div class="summary-cards">
            <div class="card high"><h3>{severity_counts.get("HIGH", 0)}</h3><p>High Impact</p></div>
            <div class="card medium"><h3>{severity_counts.get("MEDIUM", 0)}</h3><p>Medium Impact</p></div>
            <div class="card low"><h3>{severity_counts.get("LOW", 0)}</h3><p>Low Impact</p></div>
            <div class="card total"><h3>{len(results)}</h3><p>Total Findings</p></div>
        </div>
'''

    if results:
        html_content += '''
        <div class="section">
            <h2>📋 Findings by Rule</h2>
'''
        for rule_id, findings in sorted(by_rule.items()):
            metadata = findings[0].get("extra", {}).get("metadata", {})
            impact = metadata.get("impact", "").upper()
            
            if impact in ["HIGH", "MEDIUM", "LOW"]:
                sev = impact
            else:
                raw_sev = findings[0].get("extra", {}).get("severity", "INFO").upper()
                sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(raw_sev, "MEDIUM")
            
            sev_class = sev.lower()
            
            html_content += f'''
            <div class="rule-group">
                <div class="rule-header collapsible" onclick="toggleCollapsible(this)">
                    <span class="finding-title">{html.escape(rule_id)}</span>
                    <div>
                        <span class="severity-badge {sev_class}">{sev}</span>
                        <span class="rule-count">{len(findings)} finding(s)</span>
                    </div>
                </div>
                <div class="collapsible-content">
'''
            for finding in findings:
                file_path = finding.get("path", "unknown")
                start_line = finding.get("start", {}).get("line", 0)
                end_line = finding.get("end", {}).get("line", start_line)
                message = finding.get("extra", {}).get("message", "No description available")
                
                finding_metadata = finding.get("extra", {}).get("metadata", {})
                confidence = finding_metadata.get("confidence", "N/A").upper()
                owasp_mobile = finding_metadata.get("owasp-mobile", "")
                
                code_lines = get_code_snippet(finding)
                
                display_path = file_path
                if target_dir and file_path.startswith(target_dir):
                    display_path = file_path[len(target_dir):].lstrip("/\\")
                
                file_ext = file_path.split(".")[-1].lower() if "." in file_path else ""
                hljs_lang = "java"
                if file_ext == "xml":
                    hljs_lang = "xml"
                elif file_ext == "kt":
                    hljs_lang = "kotlin"
                
                line_numbers_html = ""
                code_only = ""
                if code_lines and code_lines.strip():
                    lines_list = code_lines.split("\n")
                    for i, line in enumerate(lines_list):
                        line_num = start_line + i
                        line_numbers_html += f'{line_num}\n'
                        code_only += f'{line}\n' if line else '\n'
                else:
                    line_numbers_html = str(start_line)
                    code_only = "[Code not available]"
                
                conf_class = confidence.lower() if confidence in ["HIGH", "MEDIUM", "LOW"] else "unknown"
                
                html_content += f'''
                    <div class="finding severity-{sev_class}">
                        <div class="finding-header-row">
                            <div class="finding-location">
                                <strong>{html.escape(display_path)}</strong> : Lines {start_line}-{end_line}
                            </div>
                            <div class="finding-badges">
                                <span class="confidence-badge {conf_class}" title="Confidence">🎯 {confidence}</span>
                                {f'<span class="owasp-badge" title="OWASP Mobile">{owasp_mobile}</span>' if owasp_mobile else ''}
                            </div>
                        </div>
                        <div class="finding-message">{html.escape(message)}</div>
                        <div class="code-block-wrapper">
                            <div class="line-numbers"><pre>{line_numbers_html}</pre></div>
                            <div class="code-content"><pre><code class="language-{hljs_lang}">{html.escape(code_only)}</code></pre></div>
                        </div>
                    </div>
'''
            html_content += '''
                </div>
            </div>
'''
        html_content += '''
        </div>
'''
    else:
        html_content += '''
        <div class="section">
            <div class="no-findings">
                <div class="icon">✅</div>
                <h3>No Security Issues Found</h3>
                <p>The scan completed successfully with no findings.</p>
            </div>
        </div>
'''

    if errors:
        html_content += f'''
        <div class="section">
            <h2>⚠️ Scan Errors ({len(errors)})</h2>
'''
        for error in errors[:20]:
            error_msg = str(error.get("message", error))
            html_content += f'''
            <div class="finding severity-warning">
                <div class="code-block"><code>{html.escape(error_msg)}</code></div>
            </div>
'''
        if len(errors) > 20:
            html_content += f'''
            <p style="text-align: center; color: var(--text-secondary);">
                ... and {len(errors) - 20} more errors (see JSON report for full details)
            </p>
'''
        html_content += '''
        </div>
'''

    html_content += '''
        <footer>
            <p>Generated by <strong>Mobile-RE-Toolkit</strong> Semgrep Scanner</p>
            <p>Rules: <a href="https://github.com/mindedsecurity/semgrep-rules-android-security" target="_blank">mindedsecurity/semgrep-rules-android-security</a></p>
        </footer>
    </div>
    
    <script>
        function toggleCollapsible(element) {
            element.classList.toggle('active');
            const content = element.nextElementSibling;
            content.classList.toggle('show');
            if (content.classList.contains('show')) {
                content.querySelectorAll('pre code').forEach((block) => {
                    if (!block.classList.contains('hljs')) {
                        hljs.highlightElement(block);
                    }
                });
            }
        }
        document.addEventListener('DOMContentLoaded', function() {
            hljs.configure({ ignoreUnescapedHTML: true, languages: ['java', 'kotlin', 'xml'] });
            const collapsibles = document.querySelectorAll('.collapsible');
            collapsibles.forEach((elem, index) => {
                if (index < 3) {
                    elem.classList.add('active');
                    elem.nextElementSibling.classList.add('show');
                }
            });
            document.querySelectorAll('.collapsible-content.show pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        });
    </script>
</body>
</html>
'''
    
    try:
        Path(html_path).write_text(html_content, encoding="utf-8")
        return True
    except Exception as e:
        console.print(f"[!] Failed to write HTML report: {e}")
        return False


# =============================================================================
# Semgrep Scanning
# =============================================================================

def run_command_with_spinner(cmd: list, description: str, verbose: bool = False) -> tuple:
    """Run a command with a spinner progress indicator."""
    if verbose:
        console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")
    
    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task(description, total=None)
            result = subprocess.run(cmd, capture_output=True, text=True)
            progress.update(task, completed=True)
        return result.returncode, result.stdout, result.stderr
    else:
        print(f"[*] {description}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr


def run_semgrep_scan(target_dir: str, json_path: str, html_path: str, verbose: bool = False) -> int:
    """Run the Semgrep scan on the target directory."""
    tmp_dir = tempfile.mkdtemp(prefix="semgrep_android_rules_")
    repo_dir = os.path.join(tmp_dir, "semgrep-rules-android-security")

    try:
        for bin_name in ("git", "semgrep"):
            if shutil.which(bin_name) is None:
                raise RuntimeError(f"Missing dependency: {bin_name} not found in PATH")

        console.print(f"\n[cyan]📁 Target: {target_dir}[/cyan]")
        console.print(f"[cyan]📄 JSON Output: {json_path}[/cyan]")
        console.print(f"[cyan]📄 HTML Output: {html_path}[/cyan]\n")

        # Clone rules with spinner
        rc, so, se = run_command_with_spinner(
            ["git", "clone", "--depth", "1", RULES_REPO, repo_dir],
            "🔄 Cloning Android security rules...",
            verbose
        )
        if rc != 0:
            raise RuntimeError(f"git clone failed:\n{se or so}")
        console.print("[green]✅ Rules cloned successfully[/green]")

        rules_path = os.path.join(repo_dir, "rules")
        if not os.path.isdir(rules_path):
            raise RuntimeError(f"Rules directory not found: {rules_path}")

        # Run semgrep with progress indicator
        cmd = [
            "semgrep", "scan",
            "--config", rules_path,
            "--no-git-ignore",
            "--json",
            f"--json-output={json_path}",
            target_dir,
        ]
        
        console.print("\n[bold cyan]🔍 Running Semgrep security scan...[/bold cyan]")
        console.print("[dim]This may take several minutes depending on codebase size[/dim]\n")
        
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[cyan]{task.fields[status]}[/cyan]"),
                transient=False,
            ) as progress:
                task = progress.add_task(
                    "Scanning files...", 
                    total=None,
                    status="analyzing..."
                )
                
                # Run semgrep in a separate thread to allow progress updates
                result_queue = queue.Queue()
                def run_semgrep():
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    result_queue.put((result.returncode, result.stdout, result.stderr))
                
                scan_thread = threading.Thread(target=run_semgrep, daemon=True)
                scan_thread.start()
                
                # Animate while waiting
                status_messages = [
                    "analyzing...", "checking patterns...", "scanning imports...",
                    "reviewing code...", "detecting vulnerabilities...", "processing..."
                ]
                idx = 0
                while scan_thread.is_alive():
                    progress.update(task, status=status_messages[idx % len(status_messages)])
                    idx += 1
                    scan_thread.join(timeout=2.0)
                
                rc, so, se = result_queue.get()
                progress.update(task, description="Scan complete!", status="done ✓")
        else:
            print("[*] Running Semgrep scan...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            rc, so, se = result.returncode, result.stdout, result.stderr
        
        if rc not in (0, 1):
            raise RuntimeError(f"semgrep scan failed (exit={rc}):\n{se or so}")

        # Parse and display results
        try:
            data = json.loads(Path(json_path).read_text(encoding="utf-8"))
            results = data.get("results", [])
            errors = data.get("errors", [])
            
            # Summary panel
            if HAS_RICH:
                severities = defaultdict(int)
                for r in results:
                    metadata = r.get("extra", {}).get("metadata", {})
                    impact = metadata.get("impact", "").upper()
                    if impact in ["HIGH", "MEDIUM", "LOW"]:
                        severities[impact] += 1
                    else:
                        raw_sev = r.get("extra", {}).get("severity", "INFO").upper()
                        severities[{"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(raw_sev, "MEDIUM")] += 1
                
                summary = f"""[bold green]✅ Scan Complete![/bold green]

[bold]Total Findings:[/bold] {len(results)}
[bold]Errors:[/bold] {len(errors)}

[bold]Severity Breakdown:[/bold]
  [red]• HIGH:[/red] {severities.get('HIGH', 0)}
  [yellow]• MEDIUM:[/yellow] {severities.get('MEDIUM', 0)}
  [blue]• LOW:[/blue] {severities.get('LOW', 0)}"""
                
                console.print(Panel(summary, title="Scan Results", border_style="green"))
            else:
                console.print(f"\n{'='*60}")
                console.print(f"Scan Complete!")
                console.print(f"  Findings: {len(results)}")
                console.print(f"  Errors: {len(errors)}")
                console.print(f"{'='*60}\n")
            
            # Generate HTML report with spinner
            if HAS_RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    transient=True,
                ) as progress:
                    task = progress.add_task("📊 Generating HTML report...", total=None)
                    success = generate_html_report(json_path, html_path, target_dir)
                    progress.update(task, completed=True)
            else:
                console.print("Generating HTML report...")
                success = generate_html_report(json_path, html_path, target_dir)
            
            if success:
                console.print(f"[green]✅ HTML report saved[/green]")
            else:
                console.print("[yellow]⚠️ Failed to generate HTML report[/yellow]")
                
        except Exception as e:
            console.print(f"[yellow]Could not parse JSON report: {e}[/yellow]")

        return 0

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        return 1
    finally:
        console.print(f"[dim]🧹 Cleaning up temp files...[/dim]")
        shutil.rmtree(tmp_dir, ignore_errors=True)


# =============================================================================
# CLI Commands
# =============================================================================

def get_reports_dir() -> Path:
    """Get the reports directory in Mobile-RE-Toolkit."""
    toolkit_root = get_toolkit_root()
    reports_dir = toolkit_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def cmd_scan(args):
    """Handle 'scan' subcommand - select APK, decompile, scan."""
    apk_path = select_apk_interactive()
    if not apk_path:
        return 1
    
    jadx_path = find_jadx_cli()
    if not jadx_path:
        console.print("[red]jadx not found. Cannot decompile APK.[/red]")
        return 1
    
    apk_basename = apk_path.stem
    
    # Save reports to reports/<APK_NAME>/
    reports_dir = get_reports_dir() / apk_basename
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Decompile to a sources subdirectory within reports
    output_base = reports_dir
    console.print(f"\n[cyan]📁 Output directory: {reports_dir}[/cyan]")
    
    decompiled_dir = decompile_apk(apk_path, output_base, jadx_path)
    if not decompiled_dir:
        console.print("[red]Decompilation failed. Cannot proceed with scan.[/red]")
        return 1
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = str(reports_dir / f"semgrep_findings_{timestamp}.json")
    html_path = str(reports_dir / f"semgrep_findings_{timestamp}.html")
    
    result = run_semgrep_scan(str(decompiled_dir), json_path, html_path, args.verbose)
    
    if result == 0:
        console.print(f"\n[bold green]✅ Scan complete![/bold green]")
        console.print(f"\n[cyan]📊 Reports saved to:[/cyan]")
        console.print(f"   [green]JSON:[/green] {json_path}")
        console.print(f"   [green]HTML:[/green] {html_path}")
        console.print(f"\n[dim]Decompiled sources: {decompiled_dir}[/dim]")
    
    return result


def cmd_code(args):
    """Handle 'code' subcommand - select codebase via dialog."""
    console.print("[bold magenta]Semgrep Android Security Scanner - Codebase Mode[/bold magenta]\n")
    
    target = pick_directory("Select the codebase directory to scan")
    if not target:
        console.print("[yellow]No directory selected. Exiting.[/yellow]")
        return 1
    
    target = os.path.abspath(target)
    dir_name = Path(target).name
    
    # Save reports to reports/<CODEBASE_NAME>/
    reports_dir = get_reports_dir() / dir_name
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    console.print(f"\n[cyan]📁 Output directory: {reports_dir}[/cyan]")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = str(reports_dir / f"semgrep_findings_{timestamp}.json")
    html_path = str(reports_dir / f"semgrep_findings_{timestamp}.html")
    
    result = run_semgrep_scan(target, json_path, html_path, args.verbose)
    
    if result == 0:
        console.print(f"\n[bold green]✅ Scan complete![/bold green]")
        console.print(f"\n[cyan]📊 Reports saved to:[/cyan]")
        console.print(f"   [green]JSON:[/green] {json_path}")
        console.print(f"   [green]HTML:[/green] {html_path}")
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Semgrep Android Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  scan    Select an APK, decompile with jadx, then scan
          Output saved to: reports/<APK_PACKAGE_NAME>/
    
  code    Select an existing source code directory to scan
          Output saved to: reports/<CODEBASE_NAME>/

Requirements:
  - git (for cloning Semgrep rules)
  - semgrep (CLI)
  - jadx (CLI) - only for APK mode
  - rich, prompt_toolkit - for APK selection UI

Examples:
  %(prog)s scan              # Interactive APK selection
  %(prog)s code              # GUI directory picker
  %(prog)s scan --verbose    # Verbose output
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Mode of operation")
    
    scan_parser = subparsers.add_parser("scan", help="Select APK, decompile, and scan")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    code_parser = subparsers.add_parser("code", help="Select codebase directory via GUI")
    code_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "code":
        return cmd_code(args)
    else:
        parser.print_help()
        console.print("\n[yellow]Please specify a mode: 'scan' or 'code'[/yellow]")
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Scan cancelled[/yellow]")
        raise SystemExit(1)
