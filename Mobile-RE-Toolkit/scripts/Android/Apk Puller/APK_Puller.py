#!/usr/bin/env python3
# MRET: no_args
import argparse
import subprocess
import os
import shutil
import zipfile
from pathlib import Path
from typing import List, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
import concurrent.futures

# prompt_toolkit for autocomplete dropdown
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()

# Resolve OUTPUT_DIR relative to the Mobile-RE-Toolkit root
def get_output_dir() -> str:
    """Get the absolute path to the output directory."""
    # Start from script location and find toolkit root
    script_dir = Path(__file__).resolve().parent
    
    # Navigate up to find Mobile-RE-Toolkit root (contains main.py)
    toolkit_root = script_dir
    for _ in range(10):  # Safety limit
        if (toolkit_root / "main.py").exists():
            break
        toolkit_root = toolkit_root.parent
    
    # Check for Docker environment (symlink or data dir)
    docker_path = toolkit_root / "src" / "pulled_apks"
    if docker_path.exists() or (toolkit_root.parent / "data" / "apks").exists():
        # In Docker, use the symlinked path or data dir
        if docker_path.is_symlink() or docker_path.exists():
            return str(docker_path)
        return str(toolkit_root.parent / "data" / "apks")
    
    # Default: src/output/pulled_apks
    output_dir = toolkit_root / "src" / "output" / "pulled_apks"
    output_dir.mkdir(parents=True, exist_ok=True)
    return str(output_dir)

OUTPUT_DIR = get_output_dir()

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


class PackageCompleter(Completer):
    """Custom completer for package names with fuzzy matching."""
    
    def __init__(self, packages: List[str]):
        self.packages = packages
    
    def get_completions(self, document, complete_event):
        text = document.text.strip()
        
        # If user typed a number, show that specific package
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.packages):
                package = self.packages[idx - 1]
                yield Completion(
                    text, 
                    start_position=-len(document.text),
                    display=f"#{idx} → {package}"
                )
            return
        
        # Match by package name with scoring
        matches = []
        
        for i, package in enumerate(self.packages, 1):
            score = calculate_match_score(text, package)
            if score[0] < 4:  # Only include actual matches
                matches.append((score, i, package))
        
        # Sort by score (best matches first)
        matches.sort(key=lambda x: x[0])
        
        # Yield completions
        for score, idx, package in matches:
            yield Completion(
                package,
                start_position=-len(document.text),
                display=f"[{idx}] {package}"
            )


def resolve_package_selection(user_input: str, packages: List[str]) -> Optional[int]:
    """
    Resolve user input to package index (0-based).
    Prioritizes exact matches over fuzzy matches.
    """
    user_lower = user_input.lower().strip()
    
    # Direct numeric selection
    if user_input.strip().isdigit():
        idx = int(user_input.strip()) - 1
        if 0 <= idx < len(packages):
            return idx
        return None
    
    # First, try exact match (case-insensitive) - this handles dropdown selections
    for i, package in enumerate(packages):
        if package.lower() == user_lower:
            return i
    
    # Then try starts-with match - prefer longer/more specific matches
    starts_with_matches = []
    for i, package in enumerate(packages):
        if package.lower().startswith(user_lower):
            starts_with_matches.append((len(package), i, package))
    
    if starts_with_matches:
        # Sort by length (longer = more specific), then by index (stable order)
        starts_with_matches.sort(key=lambda x: (-x[0], x[1]))
        return starts_with_matches[0][1]  # Return the longest match
    
    # Find best match using same scoring logic
    best_score = (4, 0, 0, '')  # Start with "no match"
    best_idx = None
    
    for i, package in enumerate(packages):
        score = calculate_match_score(user_input, package)
        if score < best_score:
            best_score = score
            best_idx = i
    
    # Only return if we found at least a fuzzy match
    if best_score[0] < 4:
        return best_idx
    
    return None


class PackageValidator(Validator):
    """Validates that input is either a valid index or matches a package name."""
    
    def __init__(self, count: int, packages: List[str]):
        self.count = count
        self.packages = packages
    
    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message='Type a number or package name')
        
        # Accept valid numbers
        if t.isdigit():
            idx = int(t)
            if 1 <= idx <= self.count:
                return
            raise ValidationError(message=f'Number must be 1..{self.count}')
        
        # Check if text matches any package
        resolved = resolve_package_selection(t, self.packages)
        if resolved is None:
            raise ValidationError(message='No matching package found')
        
        return


def get_device_id():
    """List connected devices and prompt the user to select one, or auto-select if only one."""
    try:
        output = subprocess.check_output(["adb", "devices"], text=True)
        
        # Parse device list more carefully - exclude header lines and invalid entries
        devices = []
        for line in output.splitlines():
            line = line.strip()
            # Skip empty lines, header lines, and lines that don't contain "device"
            if not line or "List of devices" in line or "devices attached" in line.lower():
                continue
            # Only process lines that end with "device" (connected devices)
            if line.endswith("device"):
                parts = line.split()
                if len(parts) >= 2:
                    device_id = parts[0]
                    status = parts[1]
                    # Only include devices that are actually connected (status is "device")
                    if status == "device" and device_id and device_id.lower() not in ("list", "of", "devices", "attached"):
                        devices.append(device_id)
        
        if not devices:
            console.print("[red]No devices connected.[/red]")
            return None
        
        # Auto-select if only one device
        if len(devices) == 1:
            device_id = devices[0]
            device_type = "Usb" if ":" in device_id else "Local" if device_id == "local" else "Remote"
            console.print(f"[green]✓ Auto-selected device: {device_id} ({device_type})[/green]")
            return device_id
        
        # Multiple devices - show selection table
        table = Table(title="Available Devices", show_header=True, header_style="bold magenta")
        table.add_column("Index", justify="center", style="cyan", no_wrap=True)
        table.add_column("Device ID", style="green", no_wrap=True)
        table.add_column("Type", style="yellow", no_wrap=True)

        for i, device in enumerate(devices, 1):
            device_type = "Usb" if ":" in device else "Local" if device == "local" else "Remote"
            table.add_row(str(i), device, device_type)

        console.print(table)

        choice = console.input("[bold cyan]Enter the number of the device you want to use:[/] ").strip()
        selected_index = int(choice) - 1
        
        if selected_index < 0 or selected_index >= len(devices):
            raise ValueError
        
        return devices[selected_index]
    except (subprocess.CalledProcessError, ValueError):
        console.print("[red]❌ Invalid selection or error retrieving devices. Exiting.[/]")
        return None

def list_packages(exclude_system: bool, filter_system: bool, device_id: str):
    """
    List packages installed on the device.
    Uses adb shell pm list packages.
    If exclude_system is True, only third-party packages are listed.
    If filter_system is True, filters out known system packages like 'com.google', 'com.android'.
    """
    try:
        cmd = ["adb", "-s", device_id, "shell", "pm", "list", "packages", "-3"] if exclude_system else ["adb", "-s", device_id, "shell", "pm", "list", "packages", "-a"]
        output = subprocess.check_output(cmd, text=True)

        packages = [line.replace("package:", "").strip() for line in output.splitlines()]

        # Define system prefixes to filter out
        system_prefixes = ("com.google", "com.android", "androidx", "com.qualcomm", "com.samsung", "android", "com.oplus", "net.oneplus", "com.oneplus", "oplus")

        if filter_system:
            packages = [pkg for pkg in packages if not pkg.startswith(system_prefixes)]

        return packages
    except subprocess.CalledProcessError as e:
        console.print("[red]Error listing packages:[/red]", e)
        return []

def get_apk_paths(package: str, device_id: str):
    try:
        cmd = ["adb", "-s", device_id, "shell", "pm", "path", package]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
        paths = []
        for line in output.splitlines():
            if line.startswith("package:"):
                paths.append(line.replace("package:", "").strip())
        if not paths:
            console.print(f"[yellow]⚠ No APK paths found for {package}[/]")
            return []
        return paths
    except subprocess.CalledProcessError:
        console.print(f"[red]⚠ Error retrieving APK paths for {package}[/]")
        return []

def find_bundletool():
    """Find bundletool.jar in common locations."""
    # Check PATH first
    bundletool = shutil.which("bundletool")
    if bundletool:
        return bundletool
    
    # Check common locations
    common_paths = [
        os.path.expanduser("~/bundletool.jar"),
        os.path.expanduser("~/.local/bin/bundletool.jar"),
        "/usr/local/bin/bundletool.jar",
        "./bundletool.jar",
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    return None


def merge_split_apks_manual(apk_files: List[str], output_path: str) -> bool:
    """
    Manually merge split APKs by combining their contents.
    This is a fallback method when apksigner is not available.
    """
    try:
        # Find base APK (usually the largest or named 'base.apk')
        base_apk = None
        base_size = 0
        split_apks = []
        
        for apk in apk_files:
            name = os.path.basename(apk).lower()
            size = os.path.getsize(apk)
            if 'base' in name or size > base_size:
                if base_apk:
                    split_apks.append(base_apk)
                base_apk = apk
                base_size = size
            else:
                split_apks.append(apk)
        
        if not base_apk:
            base_apk = apk_files[0]
            split_apks = apk_files[1:]
        
        # Copy base APK to output
        shutil.copy2(base_apk, output_path)
        
        # Open output APK as zip
        with zipfile.ZipFile(output_path, 'a', zipfile.ZIP_DEFLATED) as out_zip:
            # Get existing filenames from base APK
            existing_files = set(out_zip.namelist())
            
            # Merge contents from split APKs
            for split_apk in split_apks:
                with zipfile.ZipFile(split_apk, 'r') as split_zip:
                    for item in split_zip.infolist():
                        # Skip duplicate entries (base APK takes precedence)
                        if item.filename not in existing_files:
                            data = split_zip.read(item.filename)
                            out_zip.writestr(item, data)
                            existing_files.add(item.filename)  # Track added files
        
        return os.path.exists(output_path) and os.path.getsize(output_path) > 0
    except Exception as e:
        console.print(f"[red]Error merging APKs manually: {e}[/]")
        return False


def merge_split_apks(apk_files: List[str], output_path: str) -> bool:
    """Merge split APKs using the best available method."""
    console.print(f"\n[cyan]🔗 Merging {len(apk_files)} split APKs into single APK...[/]")
    
    # Use manual merge (most reliable for split APKs pulled from device)
    # Note: For AAB files, bundletool would be preferred, but for split APKs
    # pulled directly from a device, manual merge is the most practical approach
    if merge_split_apks_manual(apk_files, output_path):
        console.print(f"[green]✅ Successfully merged APKs: {output_path}[/]")
        console.print("[yellow]⚠ Note: Merged APK may need to be re-signed for installation.[/]")
        return True
    
    console.print("[red]❌ Failed to merge split APKs[/]")
    return False


def pull_apks(apk_paths, package_name, device_id):
    out_dir = os.path.join(OUTPUT_DIR, package_name)
    os.makedirs(out_dir, exist_ok=True)
    table = Table(title=f"Pulling {package_name}")
    table.add_column("Remote Path", style="green")
    table.add_column("Local File", style="cyan")
    table.add_column("Status", style="yellow")
    
    pulled_files = []
    for p in apk_paths:
        local_name = os.path.basename(p) if p.endswith(".apk") else f"{package_name}_{os.path.basename(p)}.apk"
        out_path = os.path.join(out_dir, local_name)
        res = subprocess.run(["adb", "-s", device_id, "pull", p, out_path], capture_output=True, text=True)
        if res.returncode == 0:
            # If the file is named "base.apk", rename it to use the package name
            if local_name.lower() == "base.apk":
                new_name = f"{package_name}.apk"
                new_path = os.path.join(out_dir, new_name)
                if os.path.exists(out_path):
                    os.rename(out_path, new_path)
                    out_path = new_path
                    local_name = new_name
                    console.print(f"[dim]Renamed base.apk to {new_name}[/]")
            status = "[green]OK[/]"
            pulled_files.append(out_path)
        else:
            status = f"[red]ERR: {res.stderr.strip()}[/]"
        table.add_row(p, local_name, status)
    console.print(table)

    # Check if we have split APKs (multiple APKs)
    if len(pulled_files) > 1:
        console.print(f"\n[cyan]📦 Detected {len(pulled_files)} split APKs[/]")
        console.print(Panel(
            "[yellow]Split APKs detected! You can merge them into a single APK for easier installation and analysis.[/]",
            title="[bold cyan]Split APKs[/]",
            border_style="cyan"
        ))
        
        merge_choice = console.input("\n[bold cyan]Would you like to merge them into a single APK? (Y/n): [/]").strip().lower()
        
        if merge_choice != 'n':
            merged_apk_path = os.path.join(out_dir, f"{package_name}_merged.apk")
            if merge_split_apks(pulled_files, merged_apk_path):
                console.print(f"\n[green]✅ Merged APK saved to:[/] {merged_apk_path}")
                console.print(f"[cyan]📊 Original files: {len(pulled_files)} | Merged size: {os.path.getsize(merged_apk_path) / (1024*1024):.2f} MB[/]")
            else:
                console.print("\n[yellow]⚠ Merge failed. Individual APK files are still available in the output directory.[/]")
    
    return pulled_files



def main():
    # Show output directory at startup
    console.print(f"\n[cyan]📁 APKs will be saved to:[/] [bold]{OUTPUT_DIR}[/]\n")
    
    device_id = get_device_id()
    if not device_id:
        return

    parser = argparse.ArgumentParser(description="List APKs from an Android device")
    parser.add_argument("--exclude-system", action="store_true", 
                        help="Exclude system/default packages (only list third-party apps)")
    
    filter_system_prompt = console.input("[bold cyan]Would you like to filter out system-related packages (com.google, com.android, etc.)? (Y/n): [/]")
    filter_system = filter_system_prompt.strip().lower() != 'n'
    
    args = parser.parse_args()
    
    packages = list_packages(args.exclude_system, filter_system, device_id)
    if not packages:
        console.print("[red]No packages found on the device.[/red]")
        return

    table = Table(
        title="Installed Applications",
        show_header=True,
        header_style="bold magenta",
        box=box.SIMPLE_HEAVY,
        border_style="grey39"
    )
    table.add_column("Index", justify="center", style="cyan", no_wrap=True)
    table.add_column("Package", style="green", no_wrap=True)

    for i, package in enumerate(packages, 1):
        table.add_row(str(i), package)

    console.print(table)
    console.print("\n[bold yellow]💡 Type number, package name, or use Tab/Arrow keys[/]\n")

    # Interactive selection with autocomplete
    completer = PackageCompleter(packages)
    validator = PackageValidator(len(packages), packages)
    
    try:
        choice = pt_prompt(
            HTML('<cyan>Select package (# or name):</cyan> '),
            completer=completer,
            complete_while_typing=True,
            validator=validator,
            validate_while_typing=False
        ).strip()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Cancelled by user.[/]")
        return

    # Resolve selection
    selected_index = resolve_package_selection(choice, packages)
    
    if selected_index is None:
        console.print("[red]❌ Invalid selection. Exiting.[/]")
        return
    
    selected_package = packages[selected_index]
    console.print(f"[green]✓ Selected:[/] {selected_package}")

    apk_paths = get_apk_paths(selected_package, device_id)
    if apk_paths:
        pull_apks(apk_paths, selected_package, device_id)
    else:
        console.print(f"[red]⚠ Could not retrieve APK path(s) for {selected_package}.[/]")

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