#!/usr/bin/env python3
# MRET: no_args
# ---------------------------------------------------------------------------
# Android APK Builder - Recompiles decompiled APK source code into APK & Signs It,
# with an option to clean up leftover artifacts at the end.
# ---------------------------------------------------------------------------

import os
import sys
import subprocess
import shutil
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
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
    return script_dir.parent.parent.parent  # Fallback


TOOLKIT_ROOT = get_toolkit_root()
OUTPUT_DIR = str(TOOLKIT_ROOT / "src" / "output")
APKTOOL_PATH = shutil.which("apktool")
APKSIGNER_PATH = shutil.which("apksigner")
ADB_PATH = shutil.which("adb")   # Check for adb

if not APKTOOL_PATH:
    console.print("[red]❌ Error: apktool is not found in the system environment variables![/]")
    console.print("[yellow]🔍 Ensure apktool is installed and added to PATH.[/]")
    sys.exit(1)

if not APKSIGNER_PATH:
    console.print("[red]❌ Error: apksigner is not found in the system environment variables![/]")
    console.print("[yellow]🔍 Ensure apksigner from Android SDK is installed and added to PATH.[/]")
    sys.exit(1)

if not ADB_PATH:
    console.print("[red]❌ Error: adb is not found in the system environment variables![/]")
    console.print("[yellow]🔍 Ensure adb is installed and added to PATH.[/]")
    sys.exit(1)

KEYSTORE_PATH = "debug.keystore"  # Default keystore
STORE_PASS = "android"
KEY_PASS = "android"
KEY_ALIAS = "androiddebugkey"

# Provide a full DName so keytool doesn't become interactive
DNAME = "CN=Android Debug,O=Android,C=US"

# ---------------------------------------------------------------------------
# Ensures we have a debug.keystore
# ---------------------------------------------------------------------------
def ensure_keystore():
    if os.path.exists(KEYSTORE_PATH):
        return  # Already exists

    console.print("[yellow]⚠ Keystore not found! Generating a new one...[/]")
    try:
        # Provide all necessary fields so keytool won't prompt
        key_cmd = [
            "keytool", "-genkey", "-v",
            "-keystore", KEYSTORE_PATH,
            "-storepass", STORE_PASS,
            "-alias", KEY_ALIAS,
            "-keypass", KEY_PASS,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-dname", DNAME
        ]
        subprocess.run(key_cmd, check=True)
        console.print("[green]✅ Keystore created successfully![/]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Failed to create keystore! Error code {e.returncode}[/]")
        sys.exit(e.returncode)

# ---------------------------------------------------------------------------
# Finds valid Android "projects" in src/output (apktool-decompiled)
# ---------------------------------------------------------------------------
def find_android_projects():
    valid_projects = []
    jadx_projects = []

    if not os.path.exists(OUTPUT_DIR):
        console.print(f"[red]❌ Output directory '{OUTPUT_DIR}' does not exist.[/]")
        return []

    for folder in os.listdir(OUTPUT_DIR):
        folder_path = os.path.join(OUTPUT_DIR, folder)

        if not os.path.isdir(folder_path):
            continue

        # Check for apktool-style decompilation (can be rebuilt)
        manifest_path = os.path.join(folder_path, "AndroidManifest.xml")
        smali_folder = os.path.join(folder_path, "smali")
        dex_file = os.path.join(folder_path, "classes.dex")

        if os.path.exists(manifest_path) and (os.path.exists(smali_folder) or os.path.exists(dex_file)):
            valid_projects.append(folder_path)
            continue

        # Check for JADX-style decompilation (Java source - cannot be rebuilt)
        sources_folder = os.path.join(folder_path, "sources")
        resources_folder = os.path.join(folder_path, "resources")
        # Also check nested structure: folder/sources/sources and folder/sources/resources
        nested_sources = os.path.join(folder_path, "sources", "sources")
        nested_resources = os.path.join(folder_path, "sources", "resources")
        
        if (os.path.exists(sources_folder) and os.path.exists(resources_folder)) or \
           (os.path.exists(nested_sources) and os.path.exists(nested_resources)):
            jadx_projects.append(folder_path)

    # Warn about JADX projects
    if jadx_projects and not valid_projects:
        console.print("[yellow]⚠ Found JADX decompilations (cannot be rebuilt):[/yellow]")
        for proj in jadx_projects:
            console.print(f"  [dim]• {os.path.basename(proj)}[/dim]")
        console.print()
        console.print("[cyan]ℹ JADX produces Java source code for reading/analysis.[/cyan]")
        console.print("[cyan]  To rebuild an APK, use [bold]APK Extraction[/bold] with apktool.[/cyan]")
        console.print()

    return valid_projects

# ---------------------------------------------------------------------------
# Find APK files in the build output directory
# ---------------------------------------------------------------------------
def find_apk_files():
    apk_files = []
    search_dirs = [
        os.path.join(OUTPUT_DIR, "build_output"),
        str(TOOLKIT_ROOT),
        str(TOOLKIT_ROOT / "src"),
        str(TOOLKIT_ROOT / "src" / "output" / "pulled_apks"),
    ]
 
    for directory in search_dirs:
        if not os.path.exists(directory):
            continue
 
        for file in os.listdir(directory):
            if file.endswith(".apk"):
                apk_files.append(os.path.join(directory, file))
 
    return apk_files

# ---------------------------------------------------------------------------
# Let user pick one of the valid projects or APKs
# ---------------------------------------------------------------------------
class ProjectAPKCompleter(Completer):
    def __init__(self, choices):
        self.choices = choices
        self.names = [os.path.basename(path) for typ, path in choices]
    def get_completions(self, document, complete_event):
        text = document.text.strip()
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.choices):
                name = os.path.basename(self.choices[idx-1][1])
                yield Completion(text, start_position=-len(text), display=f"#{idx} -> {name}")
            return
        lower = text.lower()
        matches = []
        for name in self.names:
            if not text or fuzzy_match(lower, name.lower()):
                matches.append(name)
        matches.sort(key=lambda n: (not n.lower().startswith(lower), len(n), n.lower()))
        for name in matches:
            yield Completion(name, start_position=-len(text), display=name)

def fuzzy_match(pattern, text):
    i = 0
    for ch in text:
        if i<len(pattern) and ch == pattern[i]:
            i+=1
    return i==len(pattern)

class NumberOrNameValidator(Validator):
    def __init__(self, count, names):
        self.count = count
        self.names = set(names)
    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message='Type a number or start typing a name')
        if t.isdigit():
            idx = int(t)
            if 1<=idx<=self.count:
                return
            raise ValidationError(message=f'Number must be 1..{self.count}')
        return

def select_project_or_apk(projects, apks):
    console.print("\n[bold magenta]📦 Available Projects & APKs[/]\n")
    table = Table(title="Projects & APKs", show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True)
    table.add_column("Type", style="yellow")
    table.add_column("Name", style="green")
    choices = []
    for i, project in enumerate(projects, 1):
        table.add_row(str(i), "Project", os.path.basename(project))
        choices.append(("project", project))
    offset = len(projects)+1
    for i, apk in enumerate(apks, offset):
        table.add_row(str(i), "APK", os.path.basename(apk))
        choices.append(("apk", apk))
    console.print(table)
    names = [os.path.basename(path) for typ, path in choices]
    completer = FuzzyCompleter(ProjectAPKCompleter(choices))
    validator = NumberOrNameValidator(len(choices), names)
    answer = pt_prompt(
        HTML("Enter # or start typing name: "),
        completer=completer,
        complete_while_typing=True,
        validator=validator,
        validate_while_typing=True
    ).strip()
    if answer.isdigit():
        idx = int(answer)
        return choices[idx-1]
    lower = answer.lower()
    best = None
    best_key = (True, 10**9, '')
    for typ, path in choices:
        name_l = os.path.basename(path).lower()
        if fuzzy_match(lower, name_l):
            key = (not name_l.startswith(lower), len(name_l), name_l)
            if key < best_key:
                best_key = key
                best = (typ, path)
    return best if best else choices[0]

# ---------------------------------------------------------------------------
# Build the APK with apktool
# ---------------------------------------------------------------------------
def build_apk(project_path):
    project_name = os.path.basename(project_path)
    console.print(f"\n[cyan]🚀 Building APK for {project_name}...[/]")

    build_output = os.path.join(OUTPUT_DIR, "build_output")
    os.makedirs(build_output, exist_ok=True)

    unsigned_apk = os.path.join(build_output, f"{project_name}_unsigned.apk")
    signed_apk = os.path.join(build_output, f"{project_name}_signed.apk")

    # Run apktool
    try:
        subprocess.run([
            APKTOOL_PATH, "b", project_path,
            "-o", unsigned_apk
        ], check=True)
        console.print(f"[green]✅ APK successfully built: {unsigned_apk}[/]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ APK build failed with code {e.returncode}![/]")
        sys.exit(e.returncode)

    # Sign the resulting APK
    sign_apk(unsigned_apk, signed_apk)

    # Prompt for cleanup
    prompt_cleanup(unsigned_apk, signed_apk)

    # Prompt for installation
    prompt_install(signed_apk)

# ---------------------------------------------------------------------------
# Sign the APK with apksigner
# ---------------------------------------------------------------------------
def sign_apk(unsigned_apk, signed_apk):
    console.print("[cyan]🔏 Signing APK...[/]")

    # Make sure keystore is available
    ensure_keystore()

    try:
        subprocess.run([
            APKSIGNER_PATH, "sign",
            "--ks", KEYSTORE_PATH,
            "--ks-pass", f"pass:{STORE_PASS}",
            "--key-pass", f"pass:{KEY_PASS}",
            "--ks-key-alias", KEY_ALIAS,
            "--out", signed_apk,
            unsigned_apk
        ], check=True)
        console.print(f"[green]✅ APK successfully signed: {signed_apk}[/]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ APK signing failed with code {e.returncode}![/]")
        sys.exit(e.returncode)

# ---------------------------------------------------------------------------
# Optionally remove leftover files: the unsigned APK and .idsig
# ---------------------------------------------------------------------------
def prompt_cleanup(unsigned_apk, signed_apk):
    # The .idsig file is automatically generated by apksigner
    idsig_file = signed_apk + ".idsig"

    ans = Prompt.ask(
        "[bold yellow]Would you like to remove leftover files (unsigned APK & .idsig)? (y/n)[/]",
        default="n"
    ).strip().lower()

    if ans.startswith("y"):
        # Remove the unsigned APK
        if os.path.exists(unsigned_apk):
            try:
                os.remove(unsigned_apk)
                console.print(f"[green]Removed leftover file:[/] {unsigned_apk}")
            except Exception as e:
                console.print(f"[red]Could not remove {unsigned_apk}: {e}[/]")

        # Remove the .idsig
        if os.path.exists(idsig_file):
            try:
                os.remove(idsig_file)
                console.print(f"[green]Removed leftover file:[/] {idsig_file}")
            except Exception as e:
                console.print(f"[red]Could not remove {idsig_file}: {e}[/]")
        console.print("[green]Cleanup complete![/]")
    else:
        console.print("[yellow]Skipping cleanup. All files remain in place.[/]")

# ---------------------------------------------------------------------------
# List connected devices using adb
# ---------------------------------------------------------------------------
def list_devices():
    try:
        result = subprocess.run([ADB_PATH, "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Failed to run adb devices: {e}[/]")
        return []

    lines = result.stdout.strip().splitlines()
    devices = []
    for line in lines[1:]:  # Skip the header line
        line = line.strip()
        if line:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
    return devices

# ---------------------------------------------------------------------------
# Prompt user to install the APK on a selected device
# ---------------------------------------------------------------------------
def prompt_install(signed_apk):
    ans = Prompt.ask(
        "[bold yellow]Would you like to install the signed APK on a connected device? (y/n)[/]",
        default="y"
    ).strip().lower()

    if not ans.startswith("y"):
        console.print("[yellow]Skipping APK installation.[/]")
        return

    devices = list_devices()
    if not devices:
        console.print("[red]❌ No connected devices found. Please connect a device and try again.[/]")
        input("Press Enter to continue...")
        return

    if len(devices) == 1:
        selected_device = devices[0]
        console.print(f"[cyan]Using the only connected device: {selected_device}[/]\n")
    else:
        console.print("\n[bold magenta]📱 Connected Devices[/]\n")
        table = Table(title="Available Devices", show_header=True, header_style="bold magenta")
        table.add_column("Index", justify="center", style="cyan", no_wrap=True)
        table.add_column("Device ID", style="green")

        for i, device in enumerate(devices, 1):
            table.add_row(str(i), device)

        console.print(table)

        while True:
            choice = Prompt.ask("[bold cyan]Enter the number of the device to install the APK[/]").strip()
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(devices):
                    selected_device = devices[idx - 1]
                    break
            console.print("[red]⚠ Invalid selection. Try again.[/]")

    console.print(f"[cyan]Installing APK on device {selected_device}...[/]")
    try:
        subprocess.run([ADB_PATH, "-s", selected_device, "install", "-r", signed_apk], check=True)
        console.print("[green]✅ APK installed successfully![/]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ APK installation failed with code {e.returncode}![/]")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    console.print("\n[bold magenta]🛠 Android APK Builder[/]\n")
    console.print(f"[dim]Toolkit root: {TOOLKIT_ROOT}[/dim]")
    console.print(f"[dim]Output directory: {OUTPUT_DIR}[/dim]\n")

    projects = find_android_projects()
    apks = find_apk_files()

    if not projects and not apks:
        console.print("[red]❌ No rebuildable Android projects or APKs found![/]")
        console.print(f"[dim]Searched in: {OUTPUT_DIR}[/dim]")
        console.print("\n[yellow]💡 Tips:[/yellow]")
        console.print("  • Use [cyan]APK Extraction[/cyan] with [bold]apktool[/bold] to create rebuildable projects")
        console.print("  • JADX decompilations (Java source) [red]cannot[/red] be rebuilt into APKs")
        console.print("  • Or place APK files in [cyan]src/output/pulled_apks/[/cyan] to install them")
        return

    selection_type, selection = select_project_or_apk(projects, apks)

    if selection_type == "project":
        build_apk(selection)
    elif selection_type == "apk":
        prompt_install(selection)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        sys.exit(0)
