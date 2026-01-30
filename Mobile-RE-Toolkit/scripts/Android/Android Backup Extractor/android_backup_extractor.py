#!/usr/bin/env python3
# MRET: no_args
# ---------------------------------------------------------------------------
# Script by L0WK3Y
# https://github.com/L0WK3Y-IAAN
# Android Backup Extractor - Extracts and decompresses Android .ab backups
# ---------------------------------------------------------------------------

import os
import sys
import struct
import tarfile
import zlib
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()


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
OUTPUT_BASE = TOOLKIT_ROOT / "src" / "output"


# =============================================================================
# Selection Menu (same style as Open In Jadx)
# =============================================================================

class FileCompleter(Completer):
    """Completer for file selection with fuzzy matching."""
    
    def __init__(self, file_paths: List[str]):
        self.file_paths = file_paths
        self.filenames = [os.path.basename(p) for p in file_paths]

    def get_completions(self, document, complete_event):
        text = document.text.strip()
        
        # If the user typed a number, offer that as a completion
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.file_paths):
                yield Completion(
                    text, 
                    start_position=-len(text), 
                    display=f"#{idx} → {self.filenames[idx-1]}"
                )
            return
        
        # Fuzzy filter by filename
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
    """Validator that accepts numbers or file names."""
    
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


# =============================================================================
# Core Functions
# =============================================================================

def find_ab_files() -> List[str]:
    """Searches for .ab files in the toolkit directories."""
    search_paths = [
        TOOLKIT_ROOT,
        TOOLKIT_ROOT / "src",
        TOOLKIT_ROOT / "src" / "backups",
        TOOLKIT_ROOT / "src" / "output",
    ]
    
    # Also check Docker data directory if it exists
    docker_data = TOOLKIT_ROOT.parent / "data" / "backups"
    if docker_data.exists():
        search_paths.append(docker_data)
    
    ab_files = []

    for search_path in search_paths:
        if not search_path.exists():
            continue
        # Search recursively
        for root, _, files in os.walk(str(search_path)):
            for file in files:
                if file.lower().endswith(".ab"):
                    ab_files.append(os.path.join(root, file))

    # De-duplicate and sort
    return sorted(set(ab_files))


def select_ab_file(ab_files: List[str]) -> str:
    """Interactive selection menu for .ab files."""
    
    console.print(f'[green]📦 Found {len(ab_files)} Android backup files[/green]\n')

    # Show table
    table = Table(
        title='Available Android Backups (.ab)', 
        show_header=True, 
        header_style='bold magenta'
    )
    table.add_column('Index', justify='center', style='cyan', no_wrap=True, width=8)
    table.add_column('Backup Name', style='green', min_width=20)
    table.add_column('Full Path', style='dim', overflow='ellipsis')

    for i, ab_path in enumerate(ab_files, 1):
        name = os.path.basename(ab_path)
        table.add_row(str(i), name, ab_path)
    console.print(table)

    names = [os.path.basename(p) for p in ab_files]
    completer = FuzzyCompleter(FileCompleter(ab_files))
    validator = NumberOrNameValidator(len(ab_files), names)

    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print("  • Start typing a backup name for fuzzy search")
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
        choice = int(answer)
        return ab_files[choice - 1]
    else:
        # Find best fuzzy match
        lower = answer.lower()
        best = None
        best_key = (True, 10**9, '')
        
        for p in ab_files:
            name = os.path.basename(p)
            name_l = name.lower()
            
            # Check fuzzy match
            i = 0
            for ch in name_l:
                if i < len(lower) and ch == lower[i]:
                    i += 1
            
            if i == len(lower):  # Fuzzy match found
                key = (not name_l.startswith(lower), len(name), name_l)
                if key < best_key:
                    best_key = key
                    best = p
        
        return best if best else ab_files[0]


def is_android_backup(file_path: str) -> bool:
    """Checks if a file is a valid Android backup."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(15)
            return header.startswith(b"ANDROID BACKUP")
    except Exception:
        return False


def convert_ab_to_tar(input_ab: str, output_tar: str) -> None:
    """Extracts the tar file from a .ab backup, decompressing if needed."""
    console.print(f"[cyan]📦 Converting {os.path.basename(input_ab)} to tar...[/cyan]")

    with open(input_ab, "rb") as ab_file:
        header = ab_file.read(24)  # Read first 24 bytes
        magic, version, compressed = struct.unpack(">14sH?", header[:17])

        if magic != b"ANDROID BACKUP":
            console.print("[red]❌ Error: Not a valid Android backup file![/red]")
            sys.exit(1)

        console.print(f"[dim]Backup version: {version}, Compressed: {'Yes' if compressed else 'No'}[/dim]")

        with open(output_tar, "wb") as tar_file:
            if compressed:
                console.print("[cyan]🔓 Decompressing backup...[/cyan]")
                decompressor = zlib.decompressobj()
                while True:
                    chunk = ab_file.read(4096)
                    if not chunk:
                        break
                    tar_file.write(decompressor.decompress(chunk))
                tar_file.write(decompressor.flush())
            else:
                console.print("[cyan]📄 Extracting raw tar data...[/cyan]")
                tar_file.write(ab_file.read())

    console.print(f"[green]✅ Converted to: {output_tar}[/green]")


def extract_tar(tar_file: str, output_dir: str) -> None:
    """Extracts a tar archive."""
    console.print(f"[cyan]📂 Extracting to {output_dir}...[/cyan]")

    os.makedirs(output_dir, exist_ok=True)

    with tarfile.open(tar_file, "r") as tar:
        tar.extractall(path=output_dir)

    console.print(f"[green]✅ Extracted to: {output_dir}[/green]")


def delete_file(file_path: str) -> None:
    """Safely deletes a file."""
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            console.print(f"[dim]🗑️ Cleaned up: {os.path.basename(file_path)}[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Failed to delete {file_path}: {e}[/yellow]")


def main():
    console.print("[bold magenta]╔═══════════════════════════════════════╗[/bold magenta]")
    console.print("[bold magenta]║   Android Backup Extractor (.ab)      ║[/bold magenta]")
    console.print("[bold magenta]╚═══════════════════════════════════════╝[/bold magenta]")
    console.print()

    # Find .ab files
    console.print("[cyan]🔍 Scanning for Android backup files...[/cyan]")
    ab_files = find_ab_files()

    if not ab_files:
        console.print("[red]❌ No Android backup (.ab) files found![/red]")
        console.print(f"[dim]Searched in: {TOOLKIT_ROOT}[/dim]")
        console.print("\n[yellow]💡 Tips:[/yellow]")
        console.print("  • Place .ab files in [cyan]src/backups/[/cyan]")
        console.print("  • Use MRET import: press [cyan]i[/cyan] and drag your .ab file")
        console.print("  • Create backup with: [cyan]adb backup -apk -shared -all[/cyan]")
        sys.exit(1)

    # Select backup file
    backup_ab = select_ab_file(ab_files)
    backup_filename = os.path.basename(backup_ab).replace(".ab", "")

    console.print(f"\n[green]🎯 Selected:[/green] {os.path.basename(backup_ab)}")
    console.print(f"[dim]Path: {backup_ab}[/dim]")

    # Verify it's a valid backup
    if not is_android_backup(backup_ab):
        console.print("[red]❌ Error: Not a valid Android backup file![/red]")
        sys.exit(1)

    # Define output locations
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
    tar_file = str(OUTPUT_BASE / f"{backup_filename}.tar")
    output_dir = str(OUTPUT_BASE / backup_filename)

    console.print()

    # Convert and extract
    convert_ab_to_tar(backup_ab, tar_file)
    extract_tar(tar_file, output_dir)

    # Clean up temporary tar file
    delete_file(tar_file)

    console.print()
    console.print("[bold green]╔═══════════════════════════════════════╗[/bold green]")
    console.print("[bold green]║   ✅ Extraction Complete!              ║[/bold green]")
    console.print("[bold green]╚═══════════════════════════════════════╝[/bold green]")
    console.print(f"\n[cyan]📁 Output:[/cyan] {output_dir}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
