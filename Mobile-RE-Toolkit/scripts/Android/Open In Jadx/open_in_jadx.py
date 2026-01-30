#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import threading
import queue
import platform
import time
from typing import List
from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()
APK_DIRECTORIES = ["root", "src", "src/output/pulled_apks"]

# --- Background workers -----------------------------------------------------

def scan_apks_worker(dirs: List[str], out_q: queue.Queue):
    apks = []
    for d in dirs:
        if not os.path.exists(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if f.endswith('.apk'):
                    apks.append(os.path.join(root, f))
    apks.sort(key=lambda p: os.path.basename(p).lower())
    out_q.put(apks)

def launch_jadx_worker(apk_path: str):
    """Launch JADX-GUI with proper detachment"""
    console.print(f"[cyan]🚀 Starting JADX-GUI for: {os.path.basename(apk_path)}[/cyan]")

    # Set up environment with UI scaling
    env = os.environ.copy()
    env['JAVA_TOOL_OPTIONS'] = '-Dsun.java2d.uiScale=2.0'

    try:
        if platform.system() == 'Windows':
            # Windows: Use proper detachment flags
            process = subprocess.Popen(
                ['jadx-gui', apk_path],
                env=env,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )
        else:
            # Linux/macOS: Use os.setsid for proper detachment
            process = subprocess.Popen(
                ['jadx-gui', apk_path],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

        # Give JADX a moment to start
        time.sleep(2)

        # Check if process is still running (not immediately crashed)
        if process.poll() is None:
            console.print(f"[green]✅ JADX-GUI launched successfully (PID: {process.pid})[/green]")
        else:
            console.print(f"[red]❌ JADX-GUI process exited immediately (exit code: {process.returncode})[/red]")

    except FileNotFoundError:
        console.print("[red]❌ jadx-gui not found in PATH[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error launching JADX-GUI: {e}[/red]")

# --- Completer that also accepts numbers -----------------------------------
class APKCompleter(Completer):
    def __init__(self, apk_paths: List[str]):
        self.apk_paths = apk_paths
        self.filenames = [os.path.basename(p) for p in apk_paths]

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
        i = 0
        for ch in text:
            if i < len(pattern) and ch == pattern[i]:
                i += 1
        return i == len(pattern)

# Validator: accept either a valid number or an existing filename suggestion
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
        # allow any text; selection can still be an exact filename
        # We don't force exact match during typing; user can press TAB to pick.
        return

# --- Utility ----------------------------------------------------------------

def is_jadx_gui_available() -> bool:
    """Check if jadx-gui is available and executable"""
    jadx_path = shutil.which('jadx-gui')
    if not jadx_path:
        return False

    # Try to run jadx-gui --help to verify it's executable
    try:
        result = subprocess.run(['jadx-gui', '--help'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return True  # If it runs without crashing, it's available
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        return False

# --- Main flow --------------------------------------------------------------

def main():
    console.print("[bold cyan]JADX-GUI APK Launcher[/bold cyan]")
    console.print("[dim]Enhanced APK selector with fuzzy search[/dim]\n")

    # Check JADX availability
    if not is_jadx_gui_available():
        console.print('[red]❌ jadx-gui not found in PATH or not executable[/red]')
        console.print('[yellow]💡 Please install JADX-GUI and ensure it\'s in your PATH[/yellow]')
        sys.exit(1)

    console.print('[green]✅ jadx-gui found and available[/green]')
    console.print('[cyan]🔍 Scanning for APKs...[/cyan]')

    # Scan for APKs in background
    q = queue.Queue()
    t = threading.Thread(target=scan_apks_worker, args=(APK_DIRECTORIES, q), daemon=True)
    t.start()
    apks: List[str] = q.get()  # wait for scan to finish

    if not apks:
        console.print('[red]❌ No APKs found in the following directories:[/red]')
        for directory in APK_DIRECTORIES:
            exists = "✅" if os.path.exists(directory) else "❌"
            console.print(f'  {exists} {directory}')
        sys.exit(1)

    console.print(f'[green]📦 Found {len(apks)} APK files[/green]\n')

    # Show table
    table = Table(title='Available APK Files', show_header=True, header_style='bold magenta')
    table.add_column('Index', justify='center', style='cyan', no_wrap=True, width=8)
    table.add_column('APK Name', style='green', min_width=20)
    table.add_column('Full Path', style='dim', overflow='ellipsis')

    for i, ap in enumerate(apks, 1):
        name = os.path.basename(ap)
        table.add_row(str(i), name, ap)
    console.print(table)

    names = [os.path.basename(p) for p in apks]
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
        sys.exit(0)

    # Resolve selection
    if answer.isdigit():
        choice = int(answer)
        apk_path = apks[choice-1]
    else:
        # If the user typed a name directly, try exact filename first
        # Otherwise, pick best fuzzy suggestion by simple ranking
        lower = answer.lower()
        best = None
        best_key = (True, 10**9, '')
        for p in apks:
            name = os.path.basename(p)
            name_l = name.lower()
            def fuzzy_ok(pat, txt):
                i=0
                for ch in txt:
                    if i < len(pat) and ch == pat[i]:
                        i+=1
                return i==len(pat)
            if fuzzy_ok(lower, name_l):
                key = (not name_l.startswith(lower), len(name), name_l)
                if key < best_key:
                    best_key = key
                    best = p
        apk_path = best if best else apks[0]

    console.print(f"\n[green]🎯 Selected:[/green] {os.path.basename(apk_path)}")
    console.print(f"[dim]Path: {apk_path}[/dim]")

    # Verify file exists
    if not os.path.exists(apk_path):
        console.print(f"[red]❌ APK file not found: {apk_path}[/red]")
        sys.exit(1)

    # Launch JADX in a non-daemon thread and wait for it to start
    launch_thread = threading.Thread(target=launch_jadx_worker, args=(apk_path,))
    launch_thread.start()

    # Wait for the launch thread to complete (this ensures JADX starts properly)
    launch_thread.join()

    # Keep the main thread alive briefly to ensure JADX fully initializes
    console.print("[dim]⏳ Waiting for JADX-GUI to initialize...[/dim]")
    time.sleep(3)

    console.print("[green]✨ JADX-GUI should now be open with your selected APK![/green]")
    console.print("[dim]You can now close this terminal if desired.[/dim]")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
