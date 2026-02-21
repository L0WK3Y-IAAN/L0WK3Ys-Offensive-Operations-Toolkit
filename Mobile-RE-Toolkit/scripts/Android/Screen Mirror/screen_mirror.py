import os
import sys
import platform
import subprocess
import tarfile
import shutil
import urllib.request
import time
from pathlib import Path

# --- Configuration ---
# Set the version you expect. If the installed version matches this, we skip download.
# If you just want ANY version, we can relax the check, but this ensures consistency.
SCRCPY_VERSION = "v3.3.4"


def _get_toolkit_tools_dir():
    """Return Mobile-RE-Toolkit/Tools directory (create if needed). Resolves from script location."""
    script_dir = Path(__file__).resolve().parent
    current = script_dir
    for _ in range(12):
        if (current / "main.py").exists() and (current / "src").exists():
            tools = current / "Tools"
            tools.mkdir(parents=True, exist_ok=True)
            return tools
        parent = current.parent
        if parent == current:
            break
        current = parent
    # Fallback: cwd/Tools
    tools = Path.cwd() / "Tools"
    tools.mkdir(parents=True, exist_ok=True)
    return tools


INSTALL_DIR = str(_get_toolkit_tools_dir() / "scrcpy-tool")
LOCAL_BINARY = os.path.join(INSTALL_DIR, "scrcpy")

URL_LINUX_X64 = f"https://github.com/Genymobile/scrcpy/releases/download/{SCRCPY_VERSION}/scrcpy-linux-x86_64-{SCRCPY_VERSION}.tar.gz"
URL_MAC_ARM64 = f"https://github.com/Genymobile/scrcpy/releases/download/{SCRCPY_VERSION}/scrcpy-macos-aarch64-{SCRCPY_VERSION}.tar.gz"
URL_MAC_X64 = f"https://github.com/Genymobile/scrcpy/releases/download/{SCRCPY_VERSION}/scrcpy-macos-x86_64-{SCRCPY_VERSION}.tar.gz"

class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    END = '\033[0m'

def print_info(msg):
    print(f"{Colors.BLUE}[i] {msg}{Colors.END}")

def print_success(msg):
    print(f"{Colors.GREEN}[+] {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}[!] {msg}{Colors.END}")

def get_scrcpy_command():
    """
    Returns the path to the scrcpy binary to use.
    Prioritizes local install, then checks global PATH.
    Returns None if not found.
    """
    # 1. Check local directory first (user might want the portable version)
    if os.path.exists(LOCAL_BINARY):
        return LOCAL_BINARY
    
    # 2. Check global PATH
    global_path = shutil.which("scrcpy")
    if global_path:
        return global_path
        
    return None

def check_scrcpy_installed():
    """
    Checks if scrcpy is installed and prints the version.
    Returns True if usable, False if missing.
    """
    cmd = get_scrcpy_command()
    
    if cmd:
        try:
            # Check version
            output = subprocess.check_output([cmd, "--version"], stderr=subprocess.STDOUT).decode()
            # Extract first line usually contains "scrcpy 2.x"
            version_line = output.split('\n')[0]
            print_success(f"Found existing scrcpy: {cmd} ({version_line})")
            return True, cmd
        except Exception as e:
            print_error(f"Found scrcpy at {cmd} but failed to run: {e}")
            return False, None
    
    return False, None

def get_download_url():
    system = platform.system()
    arch = platform.machine()
    
    print_info(f"Detecting environment: {system} ({arch})")

    if system == "Linux":
        if arch == "x86_64":
            return URL_LINUX_X64
        else:
            print_error(f"Unsupported Linux architecture: {arch}")
            sys.exit(1)
    elif system == "Darwin": # macOS
        if arch == "arm64":
            return URL_MAC_ARM64
        elif arch == "x86_64":
            return URL_MAC_X64
        else:
            print_error(f"Unsupported macOS architecture: {arch}")
            sys.exit(1)
    else:
        print_error(f"Unsupported OS: {system}")
        sys.exit(1)

def install_scrcpy(url):
    print_info(f"Downloading scrcpy {SCRCPY_VERSION}...")
    
    os.makedirs(INSTALL_DIR, exist_ok=True)
    tar_name = "scrcpy_temp.tar.gz"
    
    try:
        urllib.request.urlretrieve(url, tar_name)
        
        print_info("Extracting...")
        with tarfile.open(tar_name, "r:gz") as tar:
            top_level_dir = os.path.commonprefix(tar.getnames())
            tar.extractall()

        # Handle extraction folder structure
        # Find the extracted folder (it's usually scrcpy-macos-...)
        extracted_roots = [d for d in os.listdir('.') if d.startswith("scrcpy-") and os.path.isdir(d) and d != "scrcpy-tool"]
        
        if extracted_roots:
            source_dir = extracted_roots[0]
            for file_name in os.listdir(source_dir):
                shutil.move(os.path.join(source_dir, file_name), INSTALL_DIR)
            os.rmdir(source_dir)
        
        os.remove(tar_name)

        if platform.system() == "Darwin":
            print_info("Removing macOS quarantine attributes...")
            for binary in ["scrcpy", "adb", "scrcpy-server"]:
                path = os.path.join(INSTALL_DIR, binary)
                if os.path.exists(path):
                    subprocess.run(["xattr", "-d", "com.apple.quarantine", path], 
                                   stderr=subprocess.DEVNULL)

        print_success("Installation complete.")
        return LOCAL_BINARY

    except Exception as e:
        print_error(f"Installation failed: {e}")
        if os.path.exists(tar_name):
            os.remove(tar_name)
        sys.exit(1)

def get_adb_command():
    if shutil.which("adb"):
        return "adb"
    
    local_adb = os.path.join(INSTALL_DIR, "adb")
    if os.path.exists(local_adb):
        return local_adb
    
    print_error("ADB not found in PATH or scrcpy directory. Please install ADB.")
    sys.exit(1)

def list_devices(adb_cmd):
    print_info("Scanning for devices...")
    try:
        output = subprocess.check_output([adb_cmd, "devices"]).decode("utf-8")
        lines = output.strip().split('\n')[1:]
        devices = []
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serial = parts[0]
                try:
                    model = subprocess.check_output(
                        [adb_cmd, "-s", serial, "shell", "getprop", "ro.product.model"],
                        stderr=subprocess.DEVNULL
                    ).decode("utf-8").strip()
                except:
                    model = "Unknown"
                devices.append((serial, model))
        return devices
    except subprocess.CalledProcessError:
        print_error("Failed to run ADB.")
        sys.exit(1)

def main():
    print(f"{Colors.BLUE}[*] Nokron Security - Android Mirror Tool{Colors.END}")
    
    # 1. Check for existing scrcpy
    installed, scrcpy_bin = check_scrcpy_installed()
    
    if not installed:
        # If not found, download it
        url = get_download_url()
        scrcpy_bin = install_scrcpy(url)
    
    # 2. List Devices
    adb_cmd = get_adb_command()
    devices = list_devices(adb_cmd)
    
    if not devices:
        print_error("No devices connected.")
        sys.exit(1)
    
    # 3. Selection
    print(f"\n{Colors.GREEN}Available Devices:{Colors.END}")
    for idx, (serial, model) in enumerate(devices):
        print(f"  {idx + 1}) {serial} ({model})")
    
    try:
        selection = input(f"\nSelect device [1-{len(devices)}]: ")
        index = int(selection) - 1
        if index < 0 or index >= len(devices):
            raise ValueError
    except (ValueError, IndexError):
        print_error("Invalid selection.")
        sys.exit(1)
        
    target_serial = devices[index][0]
    
    # 4. Launch
    log_file_name = f"scrcpy_{target_serial}.log"
    print_info(f"Starting scrcpy for {target_serial}...")
    
    with open(log_file_name, "w") as log_file:
        process = subprocess.Popen(
            [scrcpy_bin, "-s", target_serial],
            stdout=log_file,
            stderr=log_file,
            start_new_session=True
        )
    
    print_success(f"Launched (PID: {process.pid})")
    print(f"    Logs: {log_file_name}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.END}")
        import traceback
        print(f"{Colors.BLUE}{traceback.format_exc()}{Colors.END}")
        sys.exit(1)
