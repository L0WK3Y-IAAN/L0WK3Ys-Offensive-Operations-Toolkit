#!/usr/bin/env python3
# MRET: no_args
# ---------------------------------------------------------------------------
# Script by L0WK3Y (extended to support DEX single-file selection and CSV only)
# https://github.com/L0WK3Y-IAAN
# ---------------------------------------------------------------------------

"""
Extract printable strings from:
- Java sources decompiled from an APK using JADX (java mode),
- Smali sources decompiled using apktool (smali mode),
- A single selected DEX file, parsing string_ids/string_data to CSV only (dex mode).

DEX mode behavior:
- When user selects "dex", the script lists ONLY .dex files found under known roots.
- User picks ONE .dex by number.
- Script parses strings and writes CSV next to that .dex (or under output dir if desired).
"""

import os, re, argparse, csv, subprocess, shutil, sys, threading
from pathlib import Path
from zipfile import ZipFile
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

from rich.console import Console
from rich.progress import Progress

# prompt_toolkit for autocomplete dropdown
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()

# Locate external tools
JADX_PATH = shutil.which("jadx")
APKTOOL_PATH = shutil.which("apktool")

def get_toolkit_root() -> Path:
    """Get the absolute path to the Mobile-RE-Toolkit root."""
    script_dir = Path(__file__).resolve().parent
    toolkit_root = script_dir
    for _ in range(10):  # Safety limit
        if (toolkit_root / "main.py").exists():
            return toolkit_root
        toolkit_root = toolkit_root.parent
    return script_dir  # Fallback

TOOLKIT_ROOT = get_toolkit_root()
OUTPUT_BASE_DIR = str(TOOLKIT_ROOT / "src" / "output")

results_lock = threading.Lock()
unique_results = set()

# ---------- Autocomplete helpers ----------

def calculate_match_score(query: str, text: str) -> Tuple[int, int, int, str]:
    """
    Calculate match score for ranking completions.
    Returns (priority, -match_position, length, text_lower) for sorting.
    Lower values = better match.
    
    Priority levels:
    0 = Exact match (case-insensitive)
    1 = Starts with query
    2 = Contains query as substring
    3 = Fuzzy match (chars in order)
    4 = No match
    """
    query_lower = query.lower()
    text_lower = text.lower()
    
    # Exact match
    if query_lower == text_lower:
        return (0, 0, len(text), text_lower)
    
    # Starts with
    if text_lower.startswith(query_lower):
        return (1, 0, len(text), text_lower)
    
    # Contains as substring
    pos = text_lower.find(query_lower)
    if pos != -1:
        return (2, -pos, len(text), text_lower)
    
    # Fuzzy match (characters in order)
    idx = 0
    first_match_pos = -1
    for i, ch in enumerate(text_lower):
        if idx < len(query_lower) and ch == query_lower[idx]:
            if first_match_pos == -1:
                first_match_pos = i
            idx += 1
    
    if idx == len(query_lower):  # All chars found
        return (3, -first_match_pos, len(text), text_lower)
    
    # No match
    return (4, 0, len(text), text_lower)


class FormatCompleter(Completer):
    """Custom completer for format selection."""
    
    def __init__(self, options: List[Tuple[str, str]]):
        self.options = options
    
    def get_completions(self, document, complete_event):
        text = document.text.strip()
        
        # If user typed a number, show that specific option
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.options):
                fmt, desc = self.options[idx - 1]
                yield Completion(
                    text,
                    start_position=-len(document.text),
                    display=f"#{idx} → {desc}"
                )
            return
        
        # Match by format name or description
        matches = []
        for i, (fmt, desc) in enumerate(self.options, 1):
            score_fmt = calculate_match_score(text, fmt)
            score_desc = calculate_match_score(text, desc)
            # Use the better score
            score = min(score_fmt, score_desc)
            if score[0] < 4:  # Only include actual matches
                matches.append((score, i, fmt, desc))
        
        # Sort by score (best matches first)
        matches.sort(key=lambda x: x[0])
        
        # Yield completions (limit to top 10)
        for score, i, fmt, desc in matches[:10]:
            yield Completion(
                fmt if text.lower() == fmt.lower() else str(i),
                start_position=-len(document.text),
                display=f"#{i} → {desc}"
            )


class FormatValidator(Validator):
    """Validator for format selection."""
    
    def __init__(self, options: List[Tuple[str, str]]):
        self.options = options
    
    def validate(self, document):
        text = document.text.strip()
        if not text:
            raise ValidationError(message="Please enter a format selection")
        
        # Allow numbers
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.options):
                return
        
        # Allow format names
        fmt_names = [opt[0] for opt in self.options]
        if text.lower() in [f.lower() for f in fmt_names]:
            return
        
        raise ValidationError(message=f"Invalid selection. Enter a number (1-{len(self.options)}) or format name")


class FileCompleter(Completer):
    """Custom completer for file selection (APK or DEX)."""
    
    def __init__(self, files: List[str], file_type: str = "file"):
        self.files = files
        self.file_type = file_type
    
    def get_completions(self, document, complete_event):
        text = document.text.strip()
        
        # If user typed a number, show that specific file
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.files):
                file_path = self.files[idx - 1]
                display_name = os.path.basename(file_path)
                yield Completion(
                    text,
                    start_position=-len(document.text),
                    display=f"#{idx} → {display_name}"
                )
            return
        
        # Match by filename
        matches = []
        for i, file_path in enumerate(self.files, 1):
            basename = os.path.basename(file_path)
            full_path = file_path
            
            # Score against both basename and full path
            score_basename = calculate_match_score(text, basename)
            score_path = calculate_match_score(text, full_path)
            score = min(score_basename, score_path)
            
            if score[0] < 4:  # Only include actual matches
                matches.append((score, i, file_path, basename))
        
        # Sort by score (best matches first)
        matches.sort(key=lambda x: x[0])
        
        # Yield completions (limit to top 10)
        for score, i, file_path, basename in matches[:10]:
            yield Completion(
                str(i) if text.isdigit() or len(text) == 0 else basename,
                start_position=-len(document.text),
                display=f"#{i} → {basename}"
            )


class FileValidator(Validator):
    """Validator for file selection."""
    
    def __init__(self, files: List[str]):
        self.files = files
    
    def validate(self, document):
        text = document.text.strip()
        if not text:
            raise ValidationError(message="Please enter a file selection")
        
        # Allow numbers
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.files):
                return
        
        # Allow filename matches
        for file_path in self.files:
            basename = os.path.basename(file_path)
            if text.lower() in basename.lower() or text.lower() in file_path.lower():
                return
        
        raise ValidationError(message=f"Invalid selection. Enter a number (1-{len(self.files)}) or filename")


def resolve_file_selection(text: str, files: List[str]) -> int:
    """Resolve user input to a file index."""
    text = text.strip()
    
    # Try exact number match first
    if text.isdigit():
        idx = int(text)
        if 1 <= idx <= len(files):
            return idx - 1
    
    # Try exact filename match
    for i, file_path in enumerate(files):
        basename = os.path.basename(file_path)
        if text.lower() == basename.lower() or text.lower() == file_path.lower():
            return i
    
    # Try partial match
    for i, file_path in enumerate(files):
        basename = os.path.basename(file_path)
        if text.lower() in basename.lower() or text.lower() in file_path.lower():
            return i
    
    return -1


def resolve_format_selection(text: str, options: List[Tuple[str, str]]) -> str:
    """Resolve user input to a format name."""
    text = text.strip()
    
    # Try exact number match first
    if text.isdigit():
        idx = int(text)
        if 1 <= idx <= len(options):
            return options[idx - 1][0]
    
    # Try exact format name match
    for fmt, desc in options:
        if text.lower() == fmt.lower():
            return fmt
    
    # Try partial match in description
    for fmt, desc in options:
        if text.lower() in desc.lower():
            return fmt
    
    return None

# ---------- Tool checks and selection ----------

def check_tools():
    tools_status = {}
    if JADX_PATH:
        tools_status['jadx'] = JADX_PATH
        console.print(f"[green]✅ Found jadx at:[/] {JADX_PATH}")
    else:
        console.print("[yellow]⚠ jadx not found. Java format will be unavailable.[/]")
    if APKTOOL_PATH:
        tools_status['apktool'] = APKTOOL_PATH
        console.print(f"[green]✅ Found apktool at:[/] {APKTOOL_PATH}")
    else:
        console.print("[yellow]⚠ apktool not found. Smali format will be unavailable.[/]")
    return tools_status

def select_format():
    tools_status = check_tools()
    options = []
    if 'jadx' in tools_status:
        options.append(('java', 'Java (.java files) - using JADX'))
    if 'apktool' in tools_status:
        options.append(('smali', 'Smali (.smali files) - using apktool'))
    # dex needs no external tools
    options.append(('dex', 'DEX (.dex) - parse single file to CSV'))

    console.print("\n[cyan]🔧 Available output formats:[/]")
    for i, (_, desc) in enumerate(options, 1):
        console.print(f" [bold cyan][{i}][/bold cyan] {desc}")

    completer = FormatCompleter(options)
    validator = FormatValidator(options)

    while True:
        choice = pt_prompt(
            "\n🔹 Select output format: ",
            completer=completer,
            validator=validator,
            complete_while_typing=True,
            complete_in_thread=True
        ).strip()
        
        # Resolve selection
        resolved = resolve_format_selection(choice, options)
        if resolved:
            return resolved
        
        # Fallback to number parsing
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1][0]
        
        console.print("[yellow]⚠ Invalid selection. Please try again.[/]")


# ---------- Discovery helpers ----------

def find_apks():
    """
    Find .apk files recursively under common search paths.
    Searches through subdirectories (e.g., package folders in pulled_apks).
    Uses absolute paths based on toolkit root for Docker compatibility.
    """
    # Build absolute search paths from toolkit root
    search_paths = [
        TOOLKIT_ROOT,
        TOOLKIT_ROOT / "src",
        TOOLKIT_ROOT / "src" / "output" / "pulled_apks",
        TOOLKIT_ROOT / "src" / "pulled_apks",  # Docker symlink location
    ]
    
    # Also check Docker data directory if it exists
    docker_data = TOOLKIT_ROOT.parent / "data" / "apks"
    if docker_data.exists():
        search_paths.append(docker_data)
    
    apks = []
    for root in search_paths:
        if not root.exists() or not root.is_dir():
            continue
        # Use os.walk to recursively search through subdirectories
        for r, _, files in os.walk(str(root)):
            for file in files:
                if file.lower().endswith(".apk"):
                    apks.append(os.path.join(r, file))
    # De-dup and stable sort
    dedup = sorted(set(os.path.normpath(p) for p in apks))
    return dedup

def find_dex_files():
    """
    Find .dex files under common roots; this lists ONLY .dex files
    so the DEX chooser shows .dex entries, not APKs.
    Uses absolute paths based on toolkit root for Docker compatibility.
    """
    search_roots = [
        TOOLKIT_ROOT,
        TOOLKIT_ROOT / "src",
        TOOLKIT_ROOT / "src" / "output",
        TOOLKIT_ROOT / "src" / "output" / "pulled_apks",
        TOOLKIT_ROOT / "src" / "pulled_apks",
    ]
    
    # Also check Docker data directory if it exists
    docker_data = TOOLKIT_ROOT.parent / "data" / "apks"
    if docker_data.exists():
        search_roots.append(docker_data)
    
    dex_list = []
    for root in search_roots:
        if not root.exists() or not root.is_dir():
            continue
        for r, _, files in os.walk(str(root)):
            for f in files:
                if f.lower().endswith(".dex"):
                    dex_list.append(os.path.join(r, f))
    # De-dup and stable sort
    dedup = sorted(set(os.path.normpath(p) for p in dex_list))
    return dedup

def select_apk():
    apks = find_apks()
    if not apks:
        console.print("[red]✖ No APKs found![/]")
        console.print(f"[dim]Searched in: {TOOLKIT_ROOT}[/dim]")
        console.print("[yellow]Tip: Place APK files in src/output/pulled_apks/ or use APK Puller first.[/yellow]")
        sys.exit(1)
    
    console.print(f"[green]📦 Found {len(apks)} APK files[/green]\n")
    
    # Show table (same style as Open in JADX)
    from rich.table import Table
    table = Table(title='Available APK Files', show_header=True, header_style='bold magenta')
    table.add_column('Index', justify='center', style='cyan', no_wrap=True, width=8)
    table.add_column('APK Name', style='green', min_width=20)
    table.add_column('Full Path', style='dim', overflow='ellipsis')
    
    for i, apk in enumerate(apks, 1):
        name = os.path.basename(apk)
        table.add_row(str(i), name, apk)
    console.print(table)
    
    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print("  • Start typing an APK name for fuzzy search")
    console.print("  • Use Tab for autocompletion\n")
    
    from prompt_toolkit.completion import FuzzyCompleter
    completer = FuzzyCompleter(FileCompleter(apks, "APK"))
    validator = FileValidator(apks)
    
    try:
        choice = pt_prompt(
            HTML('<cyan>Enter # or start typing name:</cyan> '),
            completer=completer,
            validator=validator,
            complete_while_typing=True,
            validate_while_typing=True
        ).strip()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Selection cancelled[/yellow]")
        sys.exit(0)
    
    # Resolve selection
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(apks):
            selected = apks[idx]
            console.print(f"\n[green]🎯 Selected:[/green] {os.path.basename(selected)}")
            console.print(f"[dim]Path: {selected}[/dim]")
            return selected
    
    # Try to match by name (fuzzy)
    idx = resolve_file_selection(choice, apks)
    if idx >= 0:
        selected = apks[idx]
        console.print(f"\n[green]🎯 Selected:[/green] {os.path.basename(selected)}")
        console.print(f"[dim]Path: {selected}[/dim]")
        return selected
    
    # Fallback to first match
    console.print("[yellow]⚠ Could not resolve selection, using first APK.[/]")
    return apks[0]


def select_one_dex_from_list(dex_list):
    console.print(f"[green]🧩 Found {len(dex_list)} DEX files[/green]\n")
    
    # Show table (same style as APK selection)
    from rich.table import Table
    table = Table(title='Available DEX Files', show_header=True, header_style='bold magenta')
    table.add_column('Index', justify='center', style='cyan', no_wrap=True, width=8)
    table.add_column('DEX Name', style='green', min_width=20)
    table.add_column('Full Path', style='dim', overflow='ellipsis')
    
    for i, dex in enumerate(dex_list, 1):
        name = os.path.basename(dex)
        table.add_row(str(i), name, dex)
    console.print(table)
    
    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print("  • Start typing a DEX name for fuzzy search")
    console.print("  • Use Tab for autocompletion\n")
    
    from prompt_toolkit.completion import FuzzyCompleter
    completer = FuzzyCompleter(FileCompleter(dex_list, "DEX"))
    validator = FileValidator(dex_list)
    
    try:
        choice = pt_prompt(
            HTML('<cyan>Enter # or start typing name:</cyan> '),
            completer=completer,
            validator=validator,
            complete_while_typing=True,
            validate_while_typing=True
        ).strip()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Selection cancelled[/yellow]")
        sys.exit(0)
    
    # Resolve selection
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(dex_list):
            selected = dex_list[idx]
            console.print(f"\n[green]🎯 Selected:[/green] {os.path.basename(selected)}")
            console.print(f"[dim]Path: {selected}[/dim]")
            return selected
    
    # Try to match by name (fuzzy)
    idx = resolve_file_selection(choice, dex_list)
    if idx >= 0:
        selected = dex_list[idx]
        console.print(f"\n[green]🎯 Selected:[/green] {os.path.basename(selected)}")
        console.print(f"[dim]Path: {selected}[/dim]")
        return selected
    
    # Fallback to first match
    console.print("[yellow]⚠ Could not resolve selection, using first DEX.[/]")
    return dex_list[0]


# ---------- Java/Smali text extraction ----------

def extract_strings_from_file(file_path, min_length=4):
    results = []
    pattern = re.compile(r'[\x20-\x7E]{' + str(min_length) + r',}')
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for match in pattern.findall(content):
            results.append((file_path, match))
    except Exception as e:
        console.print(f"[yellow]⚠ Error processing file {file_path}: {e}[/]")
    return results

def decompile_apk_to_java(apk_path):
    apk_name = os.path.basename(apk_path).replace(".apk", "")
    base_dir = os.path.join(OUTPUT_BASE_DIR, f"{apk_name}_EXTRACTION")
    if os.path.exists(base_dir):
        console.print(f"[blue]📂 Removing existing directory:[/] {base_dir}")
        shutil.rmtree(base_dir, ignore_errors=True)
    os.makedirs(base_dir, exist_ok=True)
    sources_dir = os.path.join(base_dir, "sources")
    os.makedirs(sources_dir, exist_ok=True)

    console.print(f"[cyan]🛠 Decompiling APK to Java sources with JADX:[/]\n {apk_path}\n -> {sources_dir}")
    console.print("[yellow]⚠ Note: JADX may report errors for complex apps, but will still extract what it can.[/]")
    
    # JADX flags to handle errors more gracefully:
    # --log-level ERROR: Only show errors, suppress warnings (reduces noise)
    # -j: Number of threads (use fewer to reduce memory issues with large APKs)
    # Note: JADX will continue even with errors, extracting what it can
    # The key is to check if files were actually created, not just the exit code
    
    jadx_flags = [
        JADX_PATH,
        "-d", sources_dir,
        "--log-level", "ERROR",  # Suppress warnings, only show errors
        "-j", str(min(4, max(1, (os.cpu_count() or 2) - 1))),  # Limit threads to reduce memory issues
        apk_path
    ]
    
    try:
        # Run JADX and capture output
        result = subprocess.run(
            jadx_flags,
            check=False,  # Don't fail on non-zero exit
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        # Check if sources directory was created and has content
        java_files = []
        if os.path.exists(sources_dir):
            for root, _, files in os.walk(sources_dir):
                java_files.extend([f for f in files if f.endswith(('.java', '.kt'))])
        
        if java_files:
            console.print(f"[green]✅ JADX extracted {len(java_files)} source files (despite possible errors)[/]")
            if result.returncode != 0:
                # Count errors from stderr
                error_lines = [line for line in result.stderr.split('\n') if 'ERROR' in line.upper()]
                if error_lines:
                    console.print(f"[yellow]⚠ JADX reported {len(error_lines)} errors, but extraction continued.[/]")
                    console.print("[yellow]   Some methods may be missing or incomplete, but available code will be extracted.[/]")
        else:
            # No files extracted, this is a real failure
            console.print(f"[red]✖ JADX decompilation failed: No source files were extracted.[/]")
            if result.stderr:
                # Show last few error lines
                error_lines = result.stderr.strip().split('\n')
                console.print("[red]Last errors:[/]")
                for line in error_lines[-5:]:
                    if line.strip():
                        console.print(f"[red]  {line}[/]")
            return None, None
            
    except subprocess.TimeoutExpired:
        console.print(f"[red]✖ JADX decompilation timed out after 10 minutes.[/]")
        # Check if we got partial results
        java_files = []
        if os.path.exists(sources_dir):
            for root, _, files in os.walk(sources_dir):
                java_files.extend([f for f in files if f.endswith(('.java', '.kt'))])
        if java_files:
            console.print(f"[yellow]⚠ Partial extraction: {len(java_files)} files were extracted before timeout.[/]")
            console.print("[yellow]   Continuing with available sources...[/]")
        else:
            return None, None
    except Exception as e:
        console.print(f"[red]✖ JADX decompilation failed with exception: {e}[/]")
        # Check if we got partial results
        java_files = []
        if os.path.exists(sources_dir):
            for root, _, files in os.walk(sources_dir):
                java_files.extend([f for f in files if f.endswith(('.java', '.kt'))])
        if java_files:
            console.print(f"[yellow]⚠ Partial extraction: {len(java_files)} files were extracted despite error.[/]")
            console.print("[yellow]   Continuing with available sources...[/]")
        else:
            return None, None
    
    return sources_dir, apk_name

def decompile_apk_to_smali(apk_path):
    apk_name = os.path.basename(apk_path).replace(".apk", "")
    base_dir = os.path.join(OUTPUT_BASE_DIR, f"{apk_name}_EXTRACTION")
    if os.path.exists(base_dir):
        console.print(f"[blue]📂 Removing existing directory:[/] {base_dir}")
        shutil.rmtree(base_dir, ignore_errors=True)
    os.makedirs(base_dir, exist_ok=True)
    sources_dir = os.path.join(base_dir, "sources")

    console.print(f"[cyan]🛠 Decompiling APK to smali sources with apktool:[/]\n {apk_path}\n -> {sources_dir}")
    try:
        subprocess.run(
            [APKTOOL_PATH, "d", apk_path, "-o", sources_dir, "-f"],
            check=True
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✖ apktool decompilation failed: {e}[/]")
        return None, None
    return sources_dir, apk_name

def process_file(file_path, min_length, task, progress):
    extracted = extract_strings_from_file(file_path, min_length=min_length)
    with results_lock:
        unique_results.update(extracted)
    progress.update(task, advance=1)

def process_directory(directory, min_length, format_type):
    if format_type == "java":
        include_exts = {
            ".java", ".kt", ".xml", ".txt", ".properties", ".gradle", ".pro", ".json", ".yml", ".yaml",
            ".aidl", ".mf", ".md"
        }
    elif format_type == "smali":
        include_exts = {
            ".smali", ".xml", ".txt", ".properties", ".pro", ".json", ".yml", ".yaml", ".md"
        }
    else:
        include_exts = {
            ".java", ".kt", ".smali", ".xml", ".txt", ".properties", ".gradle", ".pro", ".json", ".yml", ".yaml",
            ".aidl", ".mf", ".md"
        }

    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            fp = os.path.join(root, file)
            if os.path.splitext(file)[1].lower() in include_exts:
                all_files.append(fp)

    console.print(f"[magenta]📑 Extracting strings from:[/] {directory} ({len(all_files)} files)")
    if not all_files:
        return []

    with Progress() as progress:
        task = progress.add_task("[cyan]Extracting Strings...", total=len(all_files))
        with ThreadPoolExecutor(max_workers=10) as executor:
            for file_path in all_files:
                executor.submit(process_file, file_path, min_length, task, progress)
    return sorted(unique_results, key=lambda x: (x[0], x[1]))


# ---------- DEX parsing (single .dex selection, CSV only) ----------

def _read_uleb128(data: bytes, off: int):
    result, shift, pos = 0, 0, off
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, pos

def _read_mutf8_cstring(data: bytes, off: int):
    """
    Read a MUTF-8 NUL-terminated string starting at off.
    Convert common overlong 0xC0 0x80 to 0x00, decode via UTF-8 surrogatepass.
    """
    buf = bytearray()
    pos = off
    while True:
        b = data[pos]
        pos += 1
        if b == 0:
            break
        buf.append(b)
    out = bytearray()
    i = 0
    while i < len(buf):
        if i + 1 < len(buf) and buf[i] == 0xC0 and buf[i+1] == 0x80:
            out.append(0x00)
            i += 2
        else:
            out.append(buf[i])
            i += 1
    s = out.decode("utf-8", errors="surrogatepass")
    return s, pos

def _iter_dex_files(dex_dir: str | None, glob_pat: str):
    import glob
    candidates = []
    if dex_dir and os.path.isdir(dex_dir):
        candidates.extend(glob.glob(os.path.join(dex_dir, glob_pat)))
        # fallback to all dex if glob misses
        if not candidates:
            for r, _, fs in os.walk(dex_dir):
                for f in fs:
                    if f.lower().endswith(".dex"):
                        candidates.append(os.path.join(r, f))
    else:
        candidates = find_dex_files()
        # refine with glob if provided
        if glob_pat:
            base_dirs = sorted(set(os.path.dirname(p) for p in candidates))
            refined = []
            for d in base_dirs:
                refined.extend(glob.glob(os.path.join(d, glob_pat)))
            if refined:
                candidates = refined
    # de-dup and sort
    return sorted(set(os.path.normpath(p) for p in candidates if os.path.isfile(p)))

def _scan_one_dex(path: str, substr_filter: str | None, min_len: int):
    try:
        data = Path(path).read_bytes()
        entries = parse_dex_strings(data)  # returns tuples: (index, offset, string)
        hits = []
        for idx, off, s in entries:
            if not s:
                continue
            if len(s) < min_len:
                continue
            if substr_filter is not None and substr_filter not in s:
                continue
            hits.append((path, idx, off, s))
        return hits
    except Exception as e:
        return [(path, -1, 0, f"[ERROR] {e}")]


def dex_multi_mode_scan(dex_dir: str | None, glob_pat: str,
                        substr_filter: str, jobs: int,
                        out_csv: str, min_len: int):
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    dex_files = _iter_dex_files(dex_dir, glob_pat)
    if not dex_files:
        console.print("[red]✖ No .dex files found for dex-multi scan.[/]")
        return
    console.print(f"[magenta]📦 Scanning {len(dex_files)} dex files (pattern='{glob_pat}')...[/]")

    results = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Parsing DEX strings...", total=len(dex_files))
        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            futures = []
            for p in dex_files:
                futures.append(pool.submit(_scan_one_dex, p, substr_filter, min_len))
            for fut in futures:
                results.extend(fut.result())
                progress.update(task, advance=1)

    # write CSV
    with open(out_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["dex_file", "index", "offset_hex", "string"])
        writer.writeheader()
        for path, idx, off, s in results:
            writer.writerow({
                "dex_file": path,
                "index": idx,
                "offset_hex": f"0x{off:08X}" if isinstance(off, int) and off >= 0 else "",
                "string": s
            })
    console.print(f"[green]✅ Multi-dex strings saved to:[/] {out_csv}")
    console.print(f"[cyan]📊 Total matches:[/] {len(results)}")


def parse_dex_strings(dex_bytes: bytes):
    """
    Return list of (string_index, string_data_offset, string) per AOSP dex spec:
    string_ids_size @ 0x38, string_ids_off @ 0x3C; each id -> string_data_item (uleb128 len + MUTF-8 + NUL).
    """
    if len(dex_bytes) < 0x40:
        raise ValueError("Not a valid DEX (too small)")
    string_ids_size = int.from_bytes(dex_bytes[0x38:0x3C], "little")
    string_ids_off  = int.from_bytes(dex_bytes[0x3C:0x40], "little")
    end = string_ids_off + string_ids_size * 4
    if end > len(dex_bytes):
        raise ValueError("Corrupt DEX string_ids")

    results = []
    for i in range(string_ids_size):
        sdata_off = int.from_bytes(
            dex_bytes[string_ids_off + i*4:string_ids_off + (i+1)*4],
            "little"
        )
        if sdata_off <= 0 or sdata_off >= len(dex_bytes):
            continue
        try:
            _utf16_len, p = _read_uleb128(dex_bytes, sdata_off)
            s, _np = _read_mutf8_cstring(dex_bytes, p)
        except Exception:
            try:
                _utf16_len, p = _read_uleb128(dex_bytes, sdata_off)
                # fallback raw until NUL
                q = p
                raw = bytearray()
                while q < len(dex_bytes) and dex_bytes[q] != 0:
                    raw.append(dex_bytes[q]); q += 1
                s = raw.decode("latin1", errors="replace")
            except Exception:
                s = "<decode_error>"
        results.append((i, sdata_off, s))
    return results

def dex_mode_select_and_write_csv():
    """
    List ONLY .dex files, let user select one, parse strings, and write CSV next to the file.
    """
    dex_list = find_dex_files()
    if not dex_list:
        console.print("[red]✖ No .dex files found under the known roots.[/]")
        return

    dex_path = select_one_dex_from_list(dex_list)
    if not dex_path:
        return

    console.print(f"\n[cyan]🔎 Parsing DEX strings from:[/] {dex_path}")
    try:
        data = Path(dex_path).read_bytes()
        entries = parse_dex_strings(data)
    except Exception as e:
        console.print(f"[red]✖ Failed to parse DEX: {e}[/]")
        return

    # Save CSV under the central output directory instead of next to the .dex file
    out_dir = os.path.join(OUTPUT_BASE_DIR, "dex_strings")
    os.makedirs(out_dir, exist_ok=True)
    out_csv = os.path.join(out_dir, f"{Path(dex_path).stem}_strings.csv")

    try:
        with open(out_csv, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["index", "offset_hex", "string"])
            writer.writeheader()
            for idx, off, s in entries:
                writer.writerow({
                    "index": idx,
                    "offset_hex": f"0x{off:08X}",
                    "string": s
                })
        console.print(f"[green]✅ DEX strings saved to:[/] {out_csv}")
        console.print(f"[cyan]📊 Total strings extracted:[/] {len(entries)}")
    except Exception as e:
        console.print(f"[red]✖ Error writing CSV: {e}[/]")


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(
        description="Extract strings from APK sources (java/smali) or DEX (single/multi)."
    )
    parser.add_argument("input", nargs="?", help="APK file or directory (optional for java/smali; ignored for dex modes)")
    parser.add_argument("-m", "--min-length", type=int, default=4, help="Minimum string length to extract (default: 4)")
    parser.add_argument(
        "-f", "--format",
        choices=["java", "smali", "dex", "dex-multi"],
        help="Output format: java, smali, dex (single), dex-multi (many)"
    )
    # dex-multi specific
    parser.add_argument("--dex-dir", help="Directory to search for .dex files (dex-multi)")
    parser.add_argument("--glob", default="classes*.dex", help="Glob for dex files within dex-dir (dex-multi)")
    parser.add_argument("--filter", help="Substring filter (omit to include ALL strings in dex-multi)")
    parser.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1),
                        help="Parallel workers for dex-multi")
    parser.add_argument("-o", "--output",
                        default=os.path.join(OUTPUT_BASE_DIR, "dex_strings", "multi_dex_strings.csv"),
                        help="Output CSV path for dex-multi")
    args = parser.parse_args()

    format_type = args.format or select_format()

    # DEX single-file mode: ignore APK chooser; list ONLY .dex files for selection and write CSV
    if format_type == "dex":
        dex_mode_select_and_write_csv()
        return

    # DEX multi-file mode: scan many .dex files concurrently, filter, and write combined CSV
    if format_type == "dex-multi":
        # Ensure min-length flows into multi-dex
        min_len = getattr(args, "min_length", 4)
        try:
            dex_multi_mode_scan(
                dex_dir=args.dex_dir,
                glob_pat=args.glob,
                substr_filter=args.filter,
                jobs=max(1, args.jobs),
                out_csv=args.output,
                min_len=min_len
            )
        except NameError:
            console.print("[red]✖ dex-multi not integrated: missing dex_multi_mode_scan(). Add the multi-dex functions.[/]")
        return

    # Otherwise, java/smali flows
    input_path = args.input or select_apk()
    if not os.path.exists(input_path):
        console.print(f"[red]✖ Error: {input_path} does not exist.[/]")
        return

    # Reset unique results for this run
    global unique_results
    unique_results = set()

    # If an APK is provided, decompile accordingly
    if input_path.lower().endswith(".apk"):
        if format_type == "java":
            target_dir, apk_name = decompile_apk_to_java(input_path)
            if not target_dir:
                console.print("\n[yellow]⚠ JADX (Java) decompilation failed completely.[/]")
                console.print("[cyan]💡 Suggestion: Try using 'smali' format instead, which is more reliable for complex apps.[/]")
                console.print("[cyan]   Or use 'dex' format to extract strings directly from DEX files without decompilation.[/]")
                console.print("[red]✖ Exiting...[/]")
                return
        elif format_type == "smali":
            target_dir, apk_name = decompile_apk_to_smali(input_path)
        else:
            console.print("[red]✖ Invalid format specified.[/]")
            return
        if not target_dir:
            console.print("[red]✖ Decompilation failed. Exiting...[/]")
            return
    else:
        # If a directory is provided directly, operate on it
        target_dir = input_path
        apk_name = os.path.basename(os.path.normpath(target_dir))

    extracted_strings = process_directory(target_dir, args.min_length, format_type)

    # Compute output location for java/smali results
    if input_path.lower().endswith(".apk"):
        base_name = os.path.basename(input_path).replace(".apk", "")
        csv_filename = f"{base_name}_EXTRACTION_strings.csv"
        base_dir = os.path.join(OUTPUT_BASE_DIR, f"{base_name}_EXTRACTION")
    else:
        base_name = os.path.basename(os.path.normpath(target_dir))
        csv_filename = f"{base_name}_strings.csv"
        base_dir = os.path.dirname(os.path.normpath(target_dir))

    os.makedirs(base_dir, exist_ok=True)
    output_file = os.path.join(base_dir, csv_filename)

    try:
        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["file", "string"])
            writer.writeheader()
            for file_path, string in extracted_strings:
                writer.writerow({"file": file_path, "string": string})
        console.print(f"\n[green]✅ Extracted strings saved to:[/] {output_file}")
        console.print(f"[cyan]📊 Total unique strings extracted:[/] {len(extracted_strings)}")
    except Exception as e:
        console.print(f"[red]✖ Error writing to output file: {e}[/]")


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
