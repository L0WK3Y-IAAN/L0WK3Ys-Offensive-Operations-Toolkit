"""APK selection utilities with autocompletion"""

import os
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()


def get_workspace_root() -> Path:
    """Dynamically find the workspace root directory."""
    current_file = Path(__file__).resolve()
    # Traverse up until we find the actual workspace root
    # Look for .git first (most reliable), then main.py + src/ combination
    for parent in current_file.parents:
        # Check for .git (definitive workspace root)
        if (parent / ".git").exists():
            return parent
        # Check for main.py AND src/ directory (workspace markers)
        if (parent / "main.py").exists() and (parent / "src").exists():
            return parent
    # Fallback: try to find src/ + scripts/ combination
    for parent in current_file.parents:
        if (parent / "src").exists() and (parent / "scripts").exists():
            return parent
    # Last resort: current directory
    return Path.cwd()


# Default APK directories to scan
def get_default_apk_dirs() -> List[Path]:
    """Get list of default directories to scan for APKs."""
    workspace_root = get_workspace_root()
    return [
        workspace_root / "src",
        workspace_root / "src" / "output" / "pulled_apks"
    ]


class APKCompleter(Completer):
    """Completer that accepts numbers or fuzzy filename matching."""
    
    def __init__(self, apk_paths: List[Path]):
        self.apk_paths = apk_paths
        self.filenames = [p.name for p in apk_paths]

    def get_completions(self, document, complete_event):
        text = document.text.strip()
        # If the user typed a number, offer that as a completion too
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.apk_paths):
                yield Completion(text, start_position=-len(text), display=f"#{idx} -> {self.filenames[idx-1]}")
            return
        # Otherwise, fuzzy filter by filename
        lower = text.lower()
        matches = []
        for name in self.filenames:
            if not text:
                matches.append(name)
            else:
                if self._fuzzy_match(lower, name.lower()):
                    matches.append(name)
        matches.sort(key=lambda n: (not n.lower().startswith(lower), len(n), n.lower()))
        for name in matches:
            yield Completion(name, start_position=-len(text), display=name)

    @staticmethod
    def _fuzzy_match(pattern: str, text: str) -> bool:
        """Check if pattern matches text using fuzzy matching."""
        i = 0
        for ch in text:
            if i < len(pattern) and ch == pattern[i]:
                i += 1
        return i == len(pattern)


class NumberOrNameValidator(Validator):
    """Validator that accepts either a number or a filename."""
    
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
        # Allow any text; selection can still be an exact filename
        return


def scan_apks(directory: Path, recursive: bool = True) -> List[Path]:
    """
    Scan directory for APK files, optionally recursively.
    
    Args:
        directory: Directory to scan
        recursive: If True, scan subdirectories recursively
        
    Returns:
        List of APK file paths, sorted by name
    """
    apks = []
    if directory.exists() and directory.is_dir():
        if recursive:
            # Use recursive glob pattern to scan all subdirectories
            pattern = "**/*.apk"
        else:
            # Only scan the immediate directory
            pattern = "*.apk"
        
        for apk_file in directory.glob(pattern):
            if apk_file.is_file():
                apks.append(apk_file)
    apks.sort(key=lambda p: p.name.lower())
    return apks


def scan_multiple_directories(directories: List[Path]) -> List[Path]:
    """
    Scan multiple directories for APK files and combine results.
    
    Args:
        directories: List of directories to scan
        
    Returns:
        List of unique APK file paths, sorted by name
    """
    all_apks = []
    seen_names = set()
    
    for directory in directories:
        apks = scan_apks(directory)
        for apk in apks:
            # Use name as key to avoid duplicates
            if apk.name not in seen_names:
                seen_names.add(apk.name)
                all_apks.append(apk)
    
    all_apks.sort(key=lambda p: p.name.lower())
    return all_apks


def select_apk(apk_directory: Optional[Path] = None) -> Optional[Path]:
    """
    Interactive APK selection with autocompletion.
    
    Args:
        apk_directory: Directory to scan for APKs (if None, scans default directories)
        
    Returns:
        Selected APK path or None if cancelled
    """
    console.print("[bold cyan]Geiger - APK Selector[/bold cyan]")
    console.print("[dim]Enhanced APK selector with fuzzy search[/dim]\n")
    
    # Scan for APKs
    if apk_directory is None:
        # Scan multiple default directories
        default_dirs = get_default_apk_dirs()
        console.print("[cyan]🔍 Scanning for APKs in:[/cyan]")
        for directory in default_dirs:
            console.print(f"  • {directory}")
        console.print()
        
        apks = scan_multiple_directories(default_dirs)
    else:
        # Scan single specified directory
        console.print(f"[cyan]🔍 Scanning for APKs in: {apk_directory}[/cyan]")
        apks = scan_apks(apk_directory)
    
    if not apks:
        if apk_directory is None:
            console.print(f"[red]❌ No APK files found in default directories[/red]")
        else:
            console.print(f"[red]❌ No APK files found in {apk_directory}[/red]")
        return None
    
    console.print(f"[green]📦 Found {len(apks)} APK file(s)[/green]\n")
    
    # Show table
    table = Table(title='Available APK Files', show_header=True, header_style='bold magenta')
    table.add_column('Index', justify='center', style='cyan', no_wrap=True, width=8)
    table.add_column('APK Name', style='green', min_width=20)
    table.add_column('Full Path', style='dim', overflow='ellipsis')
    
    for i, apk_path in enumerate(apks, 1):
        table.add_row(str(i), apk_path.name, str(apk_path))
    console.print(table)
    
    names = [p.name for p in apks]
    completer = FuzzyCompleter(APKCompleter(apks))
    validator = NumberOrNameValidator(len(apks), names)
    
    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print("  • Start typing an APK name for fuzzy search")
    console.print("  • Use Tab for autocompletion\n")
    
    # Single prompt that accepts either a number or a name
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
        return None
    
    # Resolve selection
    if answer.isdigit():
        choice = int(answer)
        apk_path = apks[choice - 1]
    else:
        # If the user typed a name directly, try exact filename first
        # Otherwise, pick best fuzzy suggestion by simple ranking
        lower = answer.lower()
        best = None
        best_key = (True, 10**9, '')
        for p in apks:
            name = p.name
            name_l = name.lower()
            
            def fuzzy_ok(pat, txt):
                i = 0
                for ch in txt:
                    if i < len(pat) and ch == pat[i]:
                        i += 1
                return i == len(pat)
            
            if fuzzy_ok(lower, name_l):
                key = (not name_l.startswith(lower), len(name), name_l)
                if key < best_key:
                    best_key = key
                    best = p
        apk_path = best if best else apks[0]
    
    console.print(f"\n[green]🎯 Selected:[/green] {apk_path.name}")
    console.print(f"[dim]Path: {apk_path}[/dim]\n")
    
    # Verify file exists
    if not apk_path.exists():
        console.print(f"[red]❌ APK file not found: {apk_path}[/red]")
        return None
    
    return apk_path
