#!/usr/bin/env python3
"""
Hermes Bytecode Decompiler
Recursively scans for React Native Hermes bundle files and decompiles them using hermes-dec.
"""

import os
import sys
import shutil
import subprocess
import threading
import queue
from pathlib import Path
from typing import List, Tuple, Optional
from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()


MAIN_PY = "main.py"
HBC_DECOMPILER = "hbc_decompiler.py"


def get_toolkit_root() -> Path:
    """Resolve Mobile-RE-Toolkit root (contains main.py and src/)."""
    env_root = os.environ.get("MOBILE_RE_TOOLKIT_ROOT")
    if env_root:
        root = Path(env_root).resolve()
        if root.exists() and (root / MAIN_PY).exists() and (root / "src").exists():
            return root
    script_dir = Path(__file__).resolve().parent
    current = script_dir
    for _ in range(10):
        if (current / MAIN_PY).exists() and (current / "src").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    cwd = Path.cwd()
    if (cwd / MAIN_PY).exists() and (cwd / "src").exists():
        return cwd
    return script_dir  # fallback


def get_tools_dir() -> Path:
    """Get the Tools directory path, creating it if needed."""
    toolkit_root = get_toolkit_root()
    tools_dir = toolkit_root / "Tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    return tools_dir


def ensure_hermes_dec() -> Optional[Path]:
    """Ensure hermes-dec is cloned in Tools directory. Returns path to hermes-dec root."""
    tools_dir = get_tools_dir()
    hermes_dir = tools_dir / "hermes-dec"
    
    # Check if already exists
    if hermes_dir.exists() and (hermes_dir / HBC_DECOMPILER).exists():
        console.print(f"[green]✅ hermes-dec found at: {hermes_dir}[/green]")
        return hermes_dir
    
    # Clone if not exists
    console.print(f"[cyan]📥 Cloning hermes-dec to: {hermes_dir}[/cyan]")
    try:
        result = subprocess.run(
            ["git", "clone", "https://github.com/P1sec/hermes-dec.git", str(hermes_dir)],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            console.print(f"[red]❌ Failed to clone hermes-dec: {result.stderr}[/red]")
            return None
        
        if (hermes_dir / HBC_DECOMPILER).exists():
            console.print("[green]✅ hermes-dec cloned successfully[/green]")
            return hermes_dir
        else:
            console.print(f"[red]❌ hermes-dec cloned but {HBC_DECOMPILER} not found[/red]")
            return None
    except subprocess.TimeoutExpired:
        console.print("[red]❌ Git clone timed out[/red]")
        return None
    except FileNotFoundError:
        console.print("[red]❌ Git not found. Please install Git to clone hermes-dec[/red]")
        return None
    except Exception as e:
        console.print(f"[red]❌ Error cloning hermes-dec: {e}[/red]")
        return None


def scan_for_bundle_files() -> List[Tuple[str, Path]]:
    """
    Recursively scan src/output/ for index.android.bundle files.
    Returns list of (package_name, bundle_path) tuples.
    Handles both 'source' and 'sources' directory names.
    """
    toolkit_root = get_toolkit_root()
    output_dir = toolkit_root / "src" / "output"
    
    if not output_dir.exists():
        return []
    
    bundles = []
    
    # Search for index.android.bundle files recursively
    for bundle_path in output_dir.rglob("index.android.bundle"):
        # Extract package name from path
        # Path format: <PACKAGE_NAME>_EXTRACTION/source(s)/resources/assets/index.android.bundle
        try:
            # Find the _EXTRACTION folder in the path
            for part in bundle_path.parts:
                if part.endswith("_EXTRACTION"):
                    package_name = part.replace("_EXTRACTION", "")
                    bundles.append((package_name, bundle_path))
                    break
        except Exception:
            # Fallback: use directory name
            package_name = bundle_path.parent.name or "unknown"
            bundles.append((package_name, bundle_path))
    
    # Sort by package name
    bundles.sort(key=lambda x: x[0].lower())
    return bundles


def scan_bundles_worker(out_q: queue.Queue):
    """Background worker to scan for bundle files."""
    bundles = scan_for_bundle_files()
    out_q.put(bundles)


class BundleCompleter(Completer):
    """Completer for bundle file selection."""
    
    def __init__(self, bundles: List[Tuple[str, Path]]):
        self.bundles = bundles
        self.package_names = [pkg for pkg, _ in bundles]
    
    def get_completions(self, document, complete_event):
        text = document.text.strip()
        # If the user typed a number, offer that as a completion
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.bundles):
                pkg_name, _ = self.bundles[idx - 1]
                yield Completion(text, start_position=-len(text), display=f"#{idx} -> {pkg_name}")
            return
        
        # Otherwise, fuzzy filter by package name
        lower = text.lower()
        matches = []
        for name in self.package_names:
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
        """Check if pattern matches text in fuzzy way."""
        i = 0
        for ch in text:
            if i < len(pattern) and ch == pattern[i]:
                i += 1
        return i == len(pattern)


class NumberOrNameValidator(Validator):
    """Validator that accepts either a number or a package name."""
    
    def __init__(self, count: int, names: List[str]):
        self.count = count
        self.names = set(names)
    
    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message='Type a number or start typing a package name')
        if t.isdigit():
            idx = int(t)
            if 1 <= idx <= self.count:
                return
            raise ValidationError(message=f'Number must be 1..{self.count}')
        return


def is_hermes_bytecode(file_path: Path) -> Tuple[bool, str]:
    """
    Check if a file is a Hermes bytecode file by reading the magic header.
    Returns (is_hermes, file_type_description).
    """
    try:
        with open(file_path, "rb") as f:
            # Read first few bytes to check magic header
            header = f.read(16)
            
            # Hermes bytecode magic: "Hermes" followed by version info
            # Common patterns: starts with specific bytes
            if len(header) < 4:
                return False, "File too small"
            
            # Check for Hermes magic bytes (varies by version, but often starts with specific pattern)
            # Try to detect by checking if it looks like binary vs text
            # Hermes files are binary, plain JS would be text
            try:
                # Try to decode as UTF-8 - if it works, it's likely plain JavaScript
                header.decode('utf-8', errors='strict')
                # If we can decode it, check if it looks like JavaScript
                if header.startswith(b'__d(') or header.startswith(b'(function') or b'require' in header[:100]:
                    return False, "Plain JavaScript (not Hermes bytecode)"
                # Could be other text format
                return False, "Text file (not Hermes bytecode)"
            except UnicodeDecodeError:
                # Binary file - could be Hermes, but we need to verify
                # Hermes bytecode has specific structure, but magic varies
                # The hermes-dec tool will do the actual validation
                # For now, if it's binary and named index.android.bundle, assume it might be Hermes
                return True, "Binary file (possibly Hermes bytecode)"
    except Exception as e:
        return False, f"Error reading file: {e}"


def decompile_bundle(bundle_path: Path, output_dir: Path, hermes_dir: Path) -> bool:
    """
    Decompile a Hermes bundle file using hermes-dec tools.
    Outputs disassembly and decompilation to the extraction directory.
    """
    console.print(f"\n[cyan]🔧 Decompiling: {bundle_path.name}[/cyan]")
    console.print(f"[dim]Bundle: {bundle_path}[/dim]")
    console.print(f"[dim]Output: {output_dir}[/dim]\n")
    
    # Validate file type first
    console.print("[cyan]🔍 Validating file type...[/cyan]")
    is_hermes, file_type = is_hermes_bytecode(bundle_path)
    
    if not is_hermes:
        console.print(f"[yellow]⚠ Warning: {file_type}[/yellow]")
        console.print("[yellow]💡 This file may not be a Hermes bytecode file.[/yellow]")
        console.print("[yellow]💡 It might be plain JavaScript instead.[/yellow]")
        console.print("[yellow]💡 Attempting decompilation anyway...[/yellow]\n")
    else:
        console.print(f"[green]✅ File appears to be binary (possibly Hermes bytecode)[/green]\n")
    
    # Create output subdirectory for hermes results
    hermes_output = output_dir / "hermes_decompiled"
    hermes_output.mkdir(parents=True, exist_ok=True)
    
    # Run hbc-file-parser
    console.print("[cyan]📋 Parsing bundle file headers...[/cyan]")
    parser_script = hermes_dir / "hbc_file_parser.py"
    if parser_script.exists():
        try:
            result = subprocess.run(
                [sys.executable, str(parser_script), str(bundle_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                # Save parser output
                parser_output = hermes_output / "file_headers.txt"
                with open(parser_output, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                console.print(f"[green]✅ File headers saved to: {parser_output}[/green]")
            else:
                console.print(f"[yellow]⚠ Parser returned non-zero exit code[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠ Error running file parser: {e}[/yellow]")
    
    # Run hbc-disassembler
    console.print("[cyan]🔨 Disassembling bytecode...[/cyan]")
    disasm_script = hermes_dir / "hbc_disassembler.py"
    disasm_output = hermes_output / "disassembly.hasm"
    
    if disasm_script.exists():
        try:
            result = subprocess.run(
                [sys.executable, str(disasm_script), str(bundle_path), str(disasm_output)],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                console.print(f"[green]✅ Disassembly saved to: {disasm_output}[/green]")
            else:
                console.print("[yellow]⚠ Disassembler returned non-zero exit code[/yellow]")
                if result.stderr:
                    error_msg = result.stderr
                    if "magic header" in error_msg.lower() or "does not have the magic" in error_msg.lower():
                        console.print("[red]❌ This file is not a Hermes bytecode file![/red]")
                        console.print("[yellow]💡 The file is likely plain JavaScript, not compiled Hermes bytecode.[/yellow]")
                        console.print("[yellow]💡 You can view it directly as a text file - no decompilation needed.[/yellow]")
                        # Save the error for reference
                        error_file = hermes_output / "error.txt"
                        with open(error_file, "w", encoding="utf-8") as f:
                            f.write("Hermes decompilation failed:\n")
                            f.write(error_msg)
                    else:
                        console.print(f"[dim]{error_msg}[/dim]")
        except Exception as e:
            console.print(f"[red]❌ Error running disassembler: {e}[/red]")
            return False
    else:
        console.print(f"[red]❌ Disassembler script not found: {disasm_script}[/red]")
        return False
    
    # Run hbc-decompiler
    console.print("[cyan]📝 Decompiling to pseudo-code...[/cyan]")
    decomp_script = hermes_dir / HBC_DECOMPILER
    decomp_output = hermes_output / "decompiled.js"
    
    if decomp_script.exists():
        try:
            result = subprocess.run(
                [sys.executable, str(decomp_script), str(bundle_path), str(decomp_output)],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                console.print(f"[green]✅ Decompiled code saved to: {decomp_output}[/green]")
                console.print("[dim]Note: This is pseudo-code and may not be valid JavaScript yet.[/dim]")
            else:
                console.print("[yellow]⚠ Decompiler returned non-zero exit code[/yellow]")
                if result.stderr:
                    error_msg = result.stderr
                    if "magic header" in error_msg.lower() or "does not have the magic" in error_msg.lower():
                        console.print("[red]❌ This file is not a Hermes bytecode file![/red]")
                        console.print("[yellow]💡 The file is likely plain JavaScript, not compiled Hermes bytecode.[/yellow]")
                        console.print("[yellow]💡 You can view it directly as a text file - no decompilation needed.[/yellow]")
                        # Save the error for reference
                        error_file = hermes_output / "error.txt"
                        with open(error_file, "w", encoding="utf-8") as f:
                            f.write("Hermes decompilation failed:\n")
                            f.write(error_msg)
                    else:
                        console.print(f"[dim]{error_msg}[/dim]")
        except Exception as e:
            console.print(f"[red]❌ Error running decompiler: {e}[/red]")
            return False
    else:
        console.print(f"[red]❌ Decompiler script not found: {decomp_script}[/red]")
        return False
    
    # Check if we actually got any successful output
    has_output = False
    if (hermes_output / "disassembly.hasm").exists() and (hermes_output / "disassembly.hasm").stat().st_size > 0:
        has_output = True
    if (hermes_output / "decompiled.js").exists() and (hermes_output / "decompiled.js").stat().st_size > 0:
        has_output = True
    
    if has_output:
        console.print("\n[green]✨ Hermes decompilation complete![/green]")
        console.print(f"[dim]Results saved to: {hermes_output}[/dim]")
        return True
    else:
        console.print("\n[yellow]⚠ Decompilation attempted but no output files were created.[/yellow]")
        console.print("[yellow]💡 This usually means the file is not a Hermes bytecode file.[/yellow]")
        console.print("[yellow]💡 If it's plain JavaScript, you can view it directly as a text file.[/yellow]")
        console.print(f"[dim]Error details saved to: {hermes_output}/error.txt (if available)[/dim]")
        return False


def main():
    console.print("[bold cyan]Hermes Bytecode Decompiler[/bold cyan]")
    console.print("[dim]React Native Hermes bundle decompiler[/dim]\n")
    
    # Ensure hermes-dec is available
    hermes_dir = ensure_hermes_dec()
    if not hermes_dir:
        console.print("[red]❌ Failed to set up hermes-dec. Exiting...[/red]")
        sys.exit(1)
    
    # Scan for bundle files
    toolkit_root = get_toolkit_root()
    output_dir = toolkit_root / "src" / "output"
    
    console.print(f"[cyan]🔍 Scanning for bundle files in: {output_dir}[/cyan]")
    
    if not output_dir.exists():
        console.print(f"[red]❌ Output directory does not exist: {output_dir}[/red]")
        sys.exit(1)
    
    # Scan in background
    q = queue.Queue()
    t = threading.Thread(target=scan_bundles_worker, args=(q,), daemon=True)
    t.start()
    bundles: List[Tuple[str, Path]] = q.get()  # wait for scan to finish
    
    if not bundles:
        console.print("[red]❌ No Hermes bundle files found[/red]")
        console.print(f"[yellow]💡 Expected locations:[/yellow]")
        console.print(f"[dim]  {output_dir}/<PACKAGE_NAME>_EXTRACTION/source/resources/assets/index.android.bundle[/dim]")
        console.print(f"[dim]  {output_dir}/<PACKAGE_NAME>_EXTRACTION/sources/resources/assets/index.android.bundle[/dim]")
        console.print(f"[yellow]💡 The script searches recursively in: {output_dir}[/yellow]")
        sys.exit(1)
    
    console.print(f"[green]📦 Found {len(bundles)} bundle file(s)[/green]\n")
    
    # Show table
    table = Table(title="Available Hermes Bundle Files", show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True, width=8)
    table.add_column("Package Name", style="green", min_width=25)
    table.add_column("Bundle Path", style="dim", overflow="ellipsis")
    
    for i, (pkg_name, bundle_path) in enumerate(bundles, 1):
        # Show relative path from toolkit root
        try:
            rel_path = bundle_path.relative_to(toolkit_root)
        except ValueError:
            rel_path = bundle_path
        table.add_row(str(i), pkg_name, str(rel_path))
    
    console.print(table)
    
    # Get package names for completer
    package_names = [pkg for pkg, _ in bundles]
    completer = FuzzyCompleter(BundleCompleter(bundles))
    validator = NumberOrNameValidator(len(bundles), package_names)
    
    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print("  • Start typing a package name for fuzzy search")
    console.print("  • Use Tab for autocompletion\n")
    
    # Prompt for selection
    try:
        answer = pt_prompt(
            HTML("<cyan>Enter # or start typing package name:</cyan> "),
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
        selected_pkg, selected_bundle = bundles[choice - 1]
    else:
        # Fuzzy match by package name
        lower = answer.lower()
        best = None
        best_key = (True, 10**9, '')
        for pkg, bundle in bundles:
            pkg_l = pkg.lower()
            def fuzzy_ok(pat, txt):
                i = 0
                for ch in txt:
                    if i < len(pat) and ch == pat[i]:
                        i += 1
                return i == len(pat)
            if fuzzy_ok(lower, pkg_l):
                key = (not pkg_l.startswith(lower), len(pkg), pkg_l)
                if key < best_key:
                    best_key = key
                    best = (pkg, bundle)
        if best:
            selected_pkg, selected_bundle = best
        else:
            selected_pkg, selected_bundle = bundles[0]
    
    console.print(f"\n[green]🎯 Selected:[/green] {selected_pkg}")
    console.print(f"[dim]Bundle: {selected_bundle}[/dim]")
    
    # Verify bundle file exists
    if not selected_bundle.exists():
        console.print(f"[red]❌ Bundle file not found: {selected_bundle}[/red]")
        sys.exit(1)
    
    # Get the extraction directory
    # Path structure: <PACKAGE_NAME>_EXTRACTION/source(s)/resources/assets/index.android.bundle
    # Go up from: assets -> resources -> source(s) -> _EXTRACTION
    extraction_dir = selected_bundle.parent.parent.parent.parent
    
    # Verify we're in an _EXTRACTION directory, search up if needed
    if not extraction_dir.name.endswith("_EXTRACTION"):
        current = extraction_dir
        for _ in range(5):
            if current.name.endswith("_EXTRACTION"):
                extraction_dir = current
                break
            current = current.parent
    
    # Decompile
    success = decompile_bundle(selected_bundle, extraction_dir, hermes_dir)
    
    if success:
        console.print("\n[green]✨ All done![/green]")
    else:
        console.print("\n[yellow]⚠ Decompilation completed with warnings[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
