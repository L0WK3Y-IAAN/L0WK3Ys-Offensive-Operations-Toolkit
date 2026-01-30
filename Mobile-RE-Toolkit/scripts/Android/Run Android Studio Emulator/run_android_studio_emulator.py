#!/usr/bin/env python3
import subprocess
import sys
import shutil
import platform
import os
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box

console = Console()

def find_emulator_bin() -> Optional[str]:
    # First try to find emulator in PATH
    emulator_name = "emulator.exe" if platform.system() == "Windows" else "emulator"
    path = shutil.which(emulator_name)
    if path:
        return path
    
    candidates = []
    system = platform.system()
    
    # Check environment variables
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        root = os.environ.get(var)
        if root:
            if system == "Windows":
                candidates.append(os.path.join(root, "emulator", "emulator.exe"))
            else:
                candidates.append(os.path.join(root, "emulator", "emulator"))
    
    # Add platform-specific default paths
    if system == "Darwin":  # macOS
        candidates.append(os.path.expanduser("~/Library/Android/sdk/emulator/emulator"))
    elif system == "Windows":
        # Windows default paths
        localappdata = os.getenv('LOCALAPPDATA')
        if localappdata:
            candidates.append(os.path.join(localappdata, "Android", "Sdk", "emulator", "emulator.exe"))
        # Also try USERPROFILE for older installations
        userprofile = os.getenv('USERPROFILE')
        if userprofile:
            candidates.append(os.path.join(userprofile, "AppData", "Local", "Android", "Sdk", "emulator", "emulator.exe"))
    else:  # Linux
        candidates.append(os.path.expanduser("~/Android/Sdk/emulator/emulator"))
    
    # Test all candidates
    for cand in candidates:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    
    return None


def list_avds(emulator_bin: str) -> List[str]:
    try:
        out = subprocess.check_output(
            [emulator_bin, "-list-avds"],
            text=True,
            stderr=subprocess.STDOUT
        )
        return [line.strip() for line in out.splitlines() if line.strip()]
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to list AVDs. Output:[/red]\n{e.output}")
        input("Press Enter to continue...")
        return []

def make_table(avds: List[str]) -> Table:
    # Color scheme styled like the screenshot
    table = Table(
        title="[bold white]Available Android Virtual Devices[/bold white]",
        show_lines=True,
        header_style="bold medium_purple3",
        box=box.SQUARE,
        border_style="grey39",
        title_style="bold white"
    )
    table.add_column("Index", style="bright_magenta", justify="right", no_wrap=True)
    table.add_column("Device ID", style="green3", overflow="fold")
    for idx, name in enumerate(avds, start=1):
        table.add_row(str(idx), f"[green3]{name}[/green3]")
    # Add the extra launcher row
    extra_index = len(avds) + 1
    table.add_row(str(extra_index), "[cyan]Open Android Studio[/cyan]")
    return table

def open_android_studio() -> bool:
    # Cross-platform launch
    system = platform.system()
    try:
        if system == "Darwin":
            # macOS: prefer bundle name
            subprocess.Popen(["open", "-a", "Android Studio"])
            return True
        elif system == "Windows":
            # Try default installation path or PATH (studio64.exe on newer builds)
            possible = [
                shutil.which("studio64.exe"),
                shutil.which("studio.exe"),
                os.path.expandvars(r"%ProgramFiles%\Android\Android Studio\bin\studio64.exe"),
                os.path.expandvars(r"%ProgramFiles%\Android\Android Studio\bin\studio.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Android\Android Studio\bin\studio64.exe"),
            ]
            for path in possible:
                if path and os.path.exists(path):
                    subprocess.Popen([path], shell=True)
                    return True
            # Fallback to start if in PATH
            subprocess.Popen(["start", "", "studio64.exe"], shell=True)
            return True
        else:
            # Linux/Unix
            for cmd in ("android-studio", "studio", "studio.sh", "flatpak", "snap"):
                p = shutil.which(cmd)
                if p:
                    if cmd == "flatpak":
                        # common Flatpak ID
                        subprocess.Popen(["flatpak", "run", "com.google.AndroidStudio"])
                    elif cmd == "snap":
                        subprocess.Popen(["snap", "run", "android-studio"])
                    else:
                        subprocess.Popen([p])
                    return True
            # Try desktop entry
            subprocess.Popen(["xdg-open", "android-studio"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            return True
    except Exception as e:
        console.print(f"[red]Failed to open Android Studio: {e}[/red]")
        return False

def pick_avd(avds: List[str]) -> Optional[str]:
    if not avds:
        return None
    table = make_table(avds)
    console.print(table)

    max_choice = len(avds) + 1
    while True:
        choice = Prompt.ask(f"Select a device by number 1-{max_choice} (or 'q' to quit)")
        if choice.lower() in ("q", "quit", "exit"):
            return None
        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(avds):
                return avds[i - 1]
            if i == max_choice:
                opened = open_android_studio()
                if opened:
                    console.print("[green]Opening Android Studio...[/green]")
                else:
                    console.print("[red]Could not launch Android Studio automatically.[/red]")
                    input("Press Enter to continue...")
                # After opening Studio, keep prompting without exiting
                table = make_table(avds)
                console.print(table)
                continue
        console.print("[yellow]Invalid selection. Try again.[/yellow]")

def launch_avd_detached(emulator_bin: str, avd_name: str, extra_args: Optional[List[str]] = None) -> subprocess.Popen:
    args = [emulator_bin, "-avd", avd_name]
    if extra_args:
        args.extend(extra_args)
    return subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        start_new_session=True
    )

def main():
    emulator_bin = find_emulator_bin()
    if not emulator_bin:
        console.print("[red]Could not find the Android emulator binary.[/red]")
        console.print("Ensure the SDK is installed and emulator is on PATH, or set ANDROID_SDK_ROOT. Example:")
        console.print("  export ANDROID_SDK_ROOT=\"$HOME/Library/Android/sdk\"")
        console.print("  export PATH=\"$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/platform-tools:$PATH\"")
        console.print(f"  [green]{os.getenv('LOCALAPPDATA')}\\Android\\Sdk\\emulator[/green]")
        input("Press Enter to continue...")
        sys.exit(1)

    avds = list_avds(emulator_bin)
    if not avds:
        console.print("[red]No AVDs found.[/red]")
        console.print("Create one with avdmanager or Android Studio, then re-run.")
        input("Press Enter to continue...")
        sys.exit(1)

    chosen = pick_avd(avds)
    if not chosen:
        console.print("[blue]No selection made. Exiting.[/blue]")
        sys.exit(0)

    extra = []
    proc = launch_avd_detached(emulator_bin, chosen, extra_args=extra)
    console.print(f"[green]Launching AVD[/green] [bold]{chosen}[/bold] [green]in the background (PID {proc.pid}).[/green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        sys.exit(0)
