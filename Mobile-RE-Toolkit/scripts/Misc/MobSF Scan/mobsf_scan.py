#!/usr/bin/env python3
# MRET: no_args
# MRET: platforms: All
# ---------------------------------------------------------------------------
# MobSF Scanner - Start MobSF, select APKs/IPAs, scan, and generate reports
# ---------------------------------------------------------------------------

"""
MobSF Integration Script

✅ Starts MobSF Docker container (or connects to existing instance)
✅ Interactive file selection with fuzzy search (APKs and IPAs)
✅ Uploads and scans selected mobile apps
✅ Generates JSON and HTML reports
✅ Saves reports to Mobile-RE-Toolkit/reports/mobsf_reports/
"""

import os
import sys
import json
import time
import shutil
import subprocess
import threading
import queue
import socket
import random
import string
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

console = Console()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def get_toolkit_root() -> Path:
    """Get the absolute path to the Mobile-RE-Toolkit root."""
    script_dir = Path(__file__).resolve().parent
    toolkit_root = script_dir
    for _ in range(10):
        if (toolkit_root / "main.py").exists():
            return toolkit_root
        toolkit_root = toolkit_root.parent
    return script_dir.parent.parent.parent


TOOLKIT_ROOT = get_toolkit_root()
REPORTS_DIR = TOOLKIT_ROOT / "reports" / "mobsf_reports"
CONFIG_FILE = TOOLKIT_ROOT / ".mobsf_config"
FILE_DIRECTORIES = [
    str(TOOLKIT_ROOT),
    str(TOOLKIT_ROOT / "src"),
    str(TOOLKIT_ROOT / "src" / "output" / "pulled_apks"),
]


def load_saved_api_key() -> Optional[str]:
    """Load API key from environment variable or config file."""
    # Check environment variable first
    env_key = os.environ.get("MOBSF_API_KEY")
    if env_key and len(env_key) == 64:
        console.print("[dim]Using API key from MOBSF_API_KEY environment variable[/dim]")
        return env_key
    
    # Check config file
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                for line in f:
                    if line.startswith("MOBSF_API_KEY="):
                        key = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if len(key) == 64:
                            console.print("[dim]Using saved API key from config file[/dim]")
                            return key
        except Exception:
            pass
    
    return None


def save_api_key(api_key: str) -> bool:
    """Save API key to config file for future use."""
    try:
        # Read existing config
        existing_lines = []
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r") as f:
                existing_lines = [l for l in f.readlines() if not l.startswith("MOBSF_API_KEY=")]
        
        # Write updated config
        with open(CONFIG_FILE, "w") as f:
            f.writelines(existing_lines)
            f.write(f'MOBSF_API_KEY="{api_key}"\n')
        
        console.print(f"[green]✓ API key saved to {CONFIG_FILE.name}[/green]")
        console.print(f"[dim]  You can also set MOBSF_API_KEY environment variable[/dim]")
        return True
    except Exception as e:
        console.print(f"[yellow]⚠ Could not save API key: {e}[/yellow]")
        return False

MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_CONTAINER_NAME = "mobsf"
DEFAULT_PORT = 8000
MAX_PORT_TRIES = 50

# ---------------------------------------------------------------------------
# Docker Helpers
# ---------------------------------------------------------------------------

def is_docker_available() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is free."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def find_free_port(start: int = DEFAULT_PORT, max_tries: int = MAX_PORT_TRIES) -> int:
    """Find a free port starting from the given port."""
    for i in range(max_tries):
        port = start + i
        if port_free(port):
            return port
    raise RuntimeError(f"No free port found in range {start}-{start + max_tries - 1}")


def get_existing_container() -> Optional[str]:
    """Get existing MobSF container ID if it exists."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "-q", "--filter", f"name=^/{MOBSF_CONTAINER_NAME}$"],
            capture_output=True,
            text=True,
            timeout=10
        )
        container_id = result.stdout.strip()
        return container_id if container_id else None
    except Exception:
        return None


def is_container_running(container_id: str) -> bool:
    """Check if a container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip().lower() == "true"
    except Exception:
        return False


def get_container_port(container_id: str) -> Optional[int]:
    """Get the host port mapped to container port 8000."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", container_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        ports = json.loads(result.stdout.strip())
        port_mapping = ports.get("8000/tcp")
        if port_mapping and len(port_mapping) > 0:
            return int(port_mapping[0].get("HostPort", DEFAULT_PORT))
    except Exception:
        pass
    return None


def start_mobsf_container() -> tuple[str, int]:
    """Start MobSF Docker container and return (container_id, port)."""
    console.print("[cyan]🐳 Checking Docker...[/cyan]")
    
    if not is_docker_available():
        console.print("[red]❌ Docker is not available. Please install and start Docker.[/red]")
        sys.exit(1)
    
    # Check for existing container
    existing_id = get_existing_container()
    
    if existing_id:
        if is_container_running(existing_id):
            port = get_container_port(existing_id) or DEFAULT_PORT
            console.print(f"[green]✓ MobSF already running on port {port}[/green]")
            return existing_id, port
        else:
            # Start existing stopped container
            console.print("[cyan]🔄 Starting existing MobSF container...[/cyan]")
            subprocess.run(["docker", "start", existing_id], capture_output=True)
            time.sleep(3)
            port = get_container_port(existing_id) or DEFAULT_PORT
            console.print(f"[green]✓ MobSF started on port {port}[/green]")
            return existing_id, port
    
    # Pull latest image
    console.print("[cyan]📥 Pulling MobSF Docker image...[/cyan]")
    with console.status("[cyan]Downloading MobSF image (this may take a while)...[/cyan]"):
        subprocess.run(["docker", "pull", MOBSF_IMAGE], capture_output=True)
    
    # Find free port
    port = find_free_port()
    console.print(f"[cyan]🔌 Using port {port}[/cyan]")
    
    # Start new container
    console.print("[cyan]🚀 Starting MobSF container...[/cyan]")
    result = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", MOBSF_CONTAINER_NAME,
            "-p", f"{port}:8000",
            "--restart", "unless-stopped",
            MOBSF_IMAGE
        ],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        console.print(f"[red]❌ Failed to start MobSF: {result.stderr}[/red]")
        sys.exit(1)
    
    container_id = result.stdout.strip()
    console.print(f"[green]✓ MobSF container started (ID: {container_id[:12]})[/green]")
    
    return container_id, port


def wait_for_mobsf(base_url: str, timeout: int = 120) -> bool:
    """Wait for MobSF to be ready."""
    console.print("[cyan]⏳ Waiting for MobSF to initialize...[/cyan]")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{base_url}/api/v1/", timeout=5)
            if response.status_code in [200, 401, 403]:
                console.print("[green]✓ MobSF is ready![/green]")
                return True
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass
        time.sleep(2)
    
    console.print("[red]❌ MobSF failed to start within timeout[/red]")
    return False


# ---------------------------------------------------------------------------
# MobSF API
# ---------------------------------------------------------------------------

def get_api_key(base_url: str) -> str:
    """Get the MobSF API key from saved config, environment, or container."""
    # First, check for saved API key (env var or config file)
    saved_key = load_saved_api_key()
    if saved_key:
        return saved_key
    
    # Try multiple possible locations for the API key in container
    key_locations = [
        "/home/mobsf/.MobSF/secret",
        "/root/.MobSF/secret", 
        "/home/mobsf/Mobile-Security-Framework-MobSF/.env",
    ]
    
    for location in key_locations:
        try:
            result = subprocess.run(
                ["docker", "exec", MOBSF_CONTAINER_NAME, "cat", location],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                key = result.stdout.strip()
                # Handle .env file format (MOBSF_API_KEY=xxx)
                if "=" in key:
                    for line in key.split("\n"):
                        if "MOBSF_API_KEY" in line or "SECRET" in line.upper():
                            key = line.split("=", 1)[-1].strip().strip('"').strip("'")
                            break
                if key and len(key) > 10:  # Valid key should be reasonably long
                    return key
        except Exception:
            continue
    
    # Try to get from environment variable in container
    try:
        result = subprocess.run(
            ["docker", "exec", MOBSF_CONTAINER_NAME, "printenv", "MOBSF_API_KEY"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    
    # Try to find it in the logs
    try:
        result = subprocess.run(
            ["docker", "logs", MOBSF_CONTAINER_NAME, "--tail", "100"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            import re
            logs = result.stdout + result.stderr
            
            # Strip ALL ANSI escape codes and control characters
            # Handle both real ANSI codes (\x1B[1m) and remnants ([1m, [0m)
            logs_clean = re.sub(r'\x1B\[[0-9;]*[a-zA-Z]', '', logs)  # Real ANSI
            logs_clean = re.sub(r'\[\d+m', '', logs_clean)  # Remnant codes like [1m
            logs_clean = re.sub(r'\[0m', '', logs_clean)  # [0m specifically
            
            # Look for any 64-character hex string after "REST API Key"
            # More permissive pattern that handles any formatting
            match = re.search(r"REST\s*API\s*Key[:\s]+([a-f0-9]{64})", logs_clean, re.IGNORECASE)
            if match:
                api_key = match.group(1)
                console.print(f"[dim]Found API key in container logs[/dim]")
                return api_key
            
            # Fallback: just find any 64-char hex string (likely the API key)
            all_hex = re.findall(r'\b([a-f0-9]{64})\b', logs_clean, re.IGNORECASE)
            if all_hex:
                # Return the first unique 64-char hex (most likely the API key)
                console.print(f"[dim]Found API key via hex pattern[/dim]")
                return all_hex[0]
                
    except Exception as e:
        console.print(f"[dim]Log parsing error: {e}[/dim]")
    
    # Fallback: prompt user
    console.print("[yellow]⚠ Could not retrieve API key automatically.[/yellow]")
    console.print(f"[cyan]  Open {base_url} in your browser[/cyan]")
    console.print("[cyan]  The API key is shown on the home page or in REST API section[/cyan]")
    
    from rich.prompt import Prompt
    api_key = Prompt.ask("[cyan]Enter MobSF API Key[/cyan]")
    return api_key.strip()


def upload_file(base_url: str, api_key: str, file_path: Path) -> Optional[Dict[str, Any]]:
    """Upload a file to MobSF and return the response."""
    console.print(f"[cyan]📤 Uploading {file_path.name}...[/cyan]")
    console.print(f"[dim]File size: {file_path.stat().st_size / 1024 / 1024:.1f} MB[/dim]")
    
    # MobSF expects the API key directly in the Authorization header
    headers = {"Authorization": api_key}
    
    try:
        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f, "application/octet-stream")}
            response = requests.post(
                f"{base_url}/api/v1/upload",
                headers=headers,
                files=files,
                timeout=600  # 10 min timeout for large files
            )
        
        if response.status_code == 200:
            data = response.json()
            console.print(f"[green]✓ Upload successful! Hash: {data.get('hash', 'N/A')[:16]}...[/green]")
            return data
        elif response.status_code == 401:
            console.print(f"[red]❌ Upload failed: 401 Unauthorized[/red]")
            console.print(f"[yellow]The API key may be incorrect. Please verify:[/yellow]")
            console.print(f"[yellow]  1. Open {base_url} in your browser[/yellow]")
            console.print(f"[yellow]  2. Check the REST API Key shown on the page[/yellow]")
            console.print(f"[dim]Current key being used: {api_key[:16]}...[/dim]")
            return None
        else:
            console.print(f"[red]❌ Upload failed: {response.status_code} - {response.text}[/red]")
            return None
    except Exception as e:
        console.print(f"[red]❌ Upload error: {e}[/red]")
        return None


def scan_file(base_url: str, api_key: str, file_hash: str, file_name: str, scan_type: str) -> bool:
    """Trigger a scan for an uploaded file."""
    console.print(f"[cyan]🔍 Scanning {file_name}...[/cyan]")
    
    headers = {"Authorization": api_key}
    data = {
        "hash": file_hash,
        "file_name": file_name,
        "scan_type": scan_type,
        "re_scan": "0"
    }
    
    try:
        with console.status("[cyan]Scanning in progress (this may take several minutes)...[/cyan]"):
            response = requests.post(
                f"{base_url}/api/v1/scan",
                headers=headers,
                data=data,
                timeout=1800  # 30 min timeout for scanning
            )
        
        if response.status_code == 200:
            console.print("[green]✓ Scan completed![/green]")
            return True
        else:
            console.print(f"[red]❌ Scan failed: {response.status_code} - {response.text}[/red]")
            return False
    except Exception as e:
        console.print(f"[red]❌ Scan error: {e}[/red]")
        return False


def get_json_report(base_url: str, api_key: str, file_hash: str) -> Optional[Dict]:
    """Get JSON report for a scanned file."""
    headers = {"Authorization": api_key}
    
    try:
        response = requests.post(
            f"{base_url}/api/v1/report_json",
            headers=headers,
            data={"hash": file_hash},
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            console.print(f"[yellow]⚠ Could not get JSON report: {response.status_code}[/yellow]")
            return None
    except Exception as e:
        console.print(f"[yellow]⚠ JSON report error: {e}[/yellow]")
        return None


def download_pdf_report(base_url: str, api_key: str, file_hash: str, output_path: Path) -> bool:
    """Download PDF report for a scanned file."""
    headers = {"Authorization": api_key}
    
    try:
        response = requests.post(
            f"{base_url}/api/v1/download_pdf",
            headers=headers,
            data={"hash": file_hash},
            timeout=120,
            stream=True
        )
        
        if response.status_code == 200:
            with open(output_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        else:
            console.print(f"[yellow]⚠ Could not download PDF: {response.status_code}[/yellow]")
            return False
    except Exception as e:
        console.print(f"[yellow]⚠ PDF download error: {e}[/yellow]")
        return False


def generate_html_report(report_data: Dict, output_path: Path, file_name: str) -> bool:
    """Generate an HTML report from JSON data."""
    try:
        # Extract key information
        app_name = report_data.get("app_name", file_name)
        package_name = report_data.get("package_name", "N/A")
        version = report_data.get("version_name", "N/A")
        security_score = report_data.get("security_score", "N/A")
        
        # Get findings
        permissions = report_data.get("permissions", {})
        android_api = report_data.get("android_api", {})
        security_analysis = report_data.get("code_analysis", {}) or report_data.get("binary_analysis", {})
        manifest_analysis = report_data.get("manifest_analysis", [])
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MobSF Report - {app_name}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --success: #00d26a;
            --warning: #ffc107;
            --danger: #dc3545;
            --info: #0dcaf0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: var(--bg-secondary);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid var(--accent);
        }}
        h1 {{ color: var(--accent); margin-bottom: 10px; }}
        h2 {{ color: var(--accent); margin: 20px 0 10px; border-bottom: 1px solid var(--accent); padding-bottom: 5px; }}
        h3 {{ color: var(--text-primary); margin: 15px 0 10px; }}
        .meta {{ color: var(--text-secondary); font-size: 0.9em; }}
        .meta span {{ margin-right: 20px; }}
        .score {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 1.2em;
            font-weight: bold;
            margin-top: 10px;
        }}
        .score-high {{ background: var(--success); color: #000; }}
        .score-medium {{ background: var(--warning); color: #000; }}
        .score-low {{ background: var(--danger); color: #fff; }}
        section {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: rgba(233, 69, 96, 0.2); color: var(--accent); }}
        tr:hover {{ background: rgba(255, 255, 255, 0.05); }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge-danger {{ background: var(--danger); }}
        .badge-warning {{ background: var(--warning); color: #000; }}
        .badge-info {{ background: var(--info); color: #000; }}
        .badge-success {{ background: var(--success); color: #000; }}
        .findings-list {{ list-style: none; }}
        .findings-list li {{ padding: 10px; margin: 5px 0; background: rgba(0,0,0,0.2); border-radius: 5px; }}
        .timestamp {{ color: var(--text-secondary); font-size: 0.8em; margin-top: 20px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 MobSF Security Report</h1>
            <div class="meta">
                <span><strong>App:</strong> {app_name}</span>
                <span><strong>Package:</strong> {package_name}</span>
                <span><strong>Version:</strong> {version}</span>
            </div>
            <div class="score score-{'high' if isinstance(security_score, (int, float)) and security_score >= 70 else 'medium' if isinstance(security_score, (int, float)) and security_score >= 40 else 'low'}">
                Security Score: {security_score}/100
            </div>
        </header>

        <section>
            <h2>📋 Permissions</h2>
            <table>
                <tr><th>Permission</th><th>Status</th><th>Description</th></tr>
"""
        
        # Add permissions
        if isinstance(permissions, dict):
            for perm, details in list(permissions.items())[:20]:
                status = details.get("status", "unknown") if isinstance(details, dict) else "granted"
                desc = details.get("description", "") if isinstance(details, dict) else str(details)
                badge_class = "badge-danger" if "dangerous" in status.lower() else "badge-info"
                html_content += f"""                <tr>
                    <td><code>{perm}</code></td>
                    <td><span class="badge {badge_class}">{status}</span></td>
                    <td>{desc[:100]}</td>
                </tr>
"""
        
        html_content += """            </table>
        </section>

        <section>
            <h2>⚠️ Security Findings</h2>
"""
        
        # Add security findings
        if isinstance(security_analysis, dict):
            for category, findings in list(security_analysis.items())[:10]:
                if findings:
                    html_content += f"            <h3>{category}</h3>\n            <ul class='findings-list'>\n"
                    finding_list = findings if isinstance(findings, list) else [findings]
                    for finding in finding_list[:5]:
                        if isinstance(finding, dict):
                            title = finding.get("title", finding.get("name", "Finding"))
                            desc = finding.get("description", str(finding))[:200]
                            html_content += f"                <li><strong>{title}</strong>: {desc}</li>\n"
                        else:
                            html_content += f"                <li>{str(finding)[:200]}</li>\n"
                    html_content += "            </ul>\n"
        
        html_content += f"""        </section>

        <p class="timestamp">Report generated by MobSF Scanner on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>
"""
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return True
    except Exception as e:
        console.print(f"[yellow]⚠ HTML report generation error: {e}[/yellow]")
        return False


# ---------------------------------------------------------------------------
# File Selection (same as Open in JADX)
# ---------------------------------------------------------------------------

def scan_files_worker(dirs: List[str], out_q: queue.Queue):
    """Scan for APK and IPA files."""
    files = []
    for d in dirs:
        if not os.path.exists(d):
            continue
        for root, _, filenames in os.walk(d):
            for f in filenames:
                if f.lower().endswith(('.apk', '.ipa')):
                    files.append(os.path.join(root, f))
    files.sort(key=lambda p: os.path.basename(p).lower())
    out_q.put(files)


class FileCompleter(Completer):
    def __init__(self, file_paths: List[str]):
        self.file_paths = file_paths
        self.filenames = [os.path.basename(p) for p in file_paths]

    def get_completions(self, document, complete_event):
        text = document.text.strip()
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.file_paths):
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


def select_file(files: List[str]) -> str:
    """Interactive file selection with fuzzy search."""
    console.print(f'[green]📦 Found {len(files)} mobile app files[/green]\n')

    # Show table
    table = Table(title='Available Files (APK/IPA)', show_header=True, header_style='bold magenta')
    table.add_column('Index', justify='center', style='cyan', no_wrap=True, width=8)
    table.add_column('File Name', style='green', min_width=20)
    table.add_column('Type', justify='center', style='yellow', width=6)
    table.add_column('Full Path', style='dim', overflow='ellipsis')

    for i, fp in enumerate(files, 1):
        name = os.path.basename(fp)
        file_type = "APK" if name.lower().endswith('.apk') else "IPA"
        table.add_row(str(i), name, file_type, fp)
    console.print(table)

    names = [os.path.basename(p) for p in files]
    completer = FuzzyCompleter(FileCompleter(files))
    validator = NumberOrNameValidator(len(files), names)

    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print("  • Start typing a file name for fuzzy search")
    console.print("  • Use Tab for autocompletion\n")

    try:
        answer = pt_prompt(
            HTML('<cyan>Enter # or start typing name:</cyan> '),
            completer=completer,
            complete_while_typing=True,
            validator=validator,
            validate_while_typing=True
        ).strip()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Selection cancelled[/yellow]")
        sys.exit(0)

    # Resolve selection
    if answer.isdigit():
        return files[int(answer) - 1]
    
    # Fuzzy match
    lower = answer.lower()
    best = None
    best_key = (True, 10**9, '')
    for p in files:
        name = os.path.basename(p)
        name_l = name.lower()
        if FileCompleter._fuzzy_match(lower, name_l):
            key = (not name_l.startswith(lower), len(name), name_l)
            if key < best_key:
                best_key = key
                best = p
    return best if best else files[0]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    console.print(Panel.fit(
        "[bold magenta]🔍 MobSF Scanner[/bold magenta]\n"
        "[dim]Mobile Security Framework - Automated Security Analysis[/dim]",
        border_style="magenta"
    ))
    console.print()

    # Check dependencies
    if not REQUESTS_AVAILABLE:
        console.print("[red]❌ 'requests' library not installed.[/red]")
        console.print("[yellow]   Run: pip install requests[/yellow]")
        sys.exit(1)

    # Start/connect to MobSF
    _, port = start_mobsf_container()
    base_url = f"http://127.0.0.1:{port}"
    
    # Wait for MobSF to be ready
    if not wait_for_mobsf(base_url):
        sys.exit(1)
    
    console.print(f"\n[green]🌐 MobSF is running at: [bold]{base_url}[/bold][/green]")
    
    # Get API key
    api_key = get_api_key(base_url)
    if not api_key:
        console.print("[red]❌ Could not get API key[/red]")
        sys.exit(1)
    console.print(f"[green]✓ API key obtained[/green] [dim](length: {len(api_key)}, starts: {api_key[:16]}...)[/dim]")
    
    # Verify API key works
    try:
        test_response = requests.get(
            f"{base_url}/api/v1/scans",
            headers={"Authorization": api_key},
            timeout=10
        )
        if test_response.status_code == 200:
            console.print("[green]✓ API key verified[/green]")
            # Save the working key for future use
            save_api_key(api_key)
        elif test_response.status_code == 401:
            console.print("[yellow]⚠ API key verification failed (401)[/yellow]")
            console.print(f"[cyan]Please check the API key at: {base_url}/api_docs[/cyan]")
            from rich.prompt import Prompt
            manual_key = Prompt.ask("[cyan]Enter the correct API key (or press Enter to continue)[/cyan]")
            if manual_key.strip():
                api_key = manual_key.strip()
                console.print(f"[green]✓ Using manually entered API key[/green]")
                # Save the manually entered key for future use
                save_api_key(api_key)
    except Exception as e:
        console.print(f"[dim]API verification skipped: {e}[/dim]")

    # Scan for files
    console.print("\n[cyan]🔍 Scanning for APK/IPA files...[/cyan]")
    console.print(f"[dim]Searching in: {TOOLKIT_ROOT}[/dim]\n")
    
    q = queue.Queue()
    t = threading.Thread(target=scan_files_worker, args=(FILE_DIRECTORIES, q), daemon=True)
    t.start()
    files: List[str] = q.get()

    if not files:
        console.print('[red]❌ No APK or IPA files found![/red]')
        console.print('[yellow]💡 Place APK/IPA files in src/ or src/output/pulled_apks/[/yellow]')
        console.print(f"\n[cyan]You can still access MobSF at: {base_url}[/cyan]")
        sys.exit(0)

    # Select file
    selected_file = select_file(files)
    file_path = Path(selected_file)
    
    console.print(f"\n[green]🎯 Selected:[/green] {file_path.name}")
    console.print(f"[dim]Path: {file_path}[/dim]")

    # Determine scan type
    scan_type = "apk" if file_path.suffix.lower() == ".apk" else "ipa"
    
    # Upload file
    upload_result = upload_file(base_url, api_key, file_path)
    if not upload_result:
        sys.exit(1)
    
    file_hash = upload_result.get("hash")
    if not file_hash:
        console.print("[red]❌ No hash returned from upload[/red]")
        sys.exit(1)

    # Scan file
    if not scan_file(base_url, api_key, file_hash, file_path.name, scan_type):
        sys.exit(1)

    # Create reports directory
    app_name = file_path.stem.replace(" ", "_")
    report_dir = REPORTS_DIR / app_name
    report_dir.mkdir(parents=True, exist_ok=True)

    # Get and save reports
    console.print("\n[cyan]📊 Generating reports...[/cyan]")

    # JSON report
    json_report = get_json_report(base_url, api_key, file_hash)
    if json_report:
        json_path = report_dir / f"{app_name}_mobsf_report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✓ JSON report saved: {json_path}[/green]")
        
        # Generate HTML from JSON
        html_path = report_dir / f"{app_name}_mobsf_report.html"
        if generate_html_report(json_report, html_path, file_path.name):
            console.print(f"[green]✓ HTML report saved: {html_path}[/green]")

    # PDF report
    pdf_path = report_dir / f"{app_name}_mobsf_report.pdf"
    if download_pdf_report(base_url, api_key, file_hash, pdf_path):
        console.print(f"[green]✓ PDF report saved: {pdf_path}[/green]")

    # Summary
    console.print(Panel.fit(
        f"[bold green]✅ Scan Complete![/bold green]\n\n"
        f"[cyan]App:[/cyan] {file_path.name}\n"
        f"[cyan]Reports:[/cyan] {report_dir}\n"
        f"[cyan]MobSF Web:[/cyan] {base_url}",
        title="Summary",
        border_style="green"
    ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
