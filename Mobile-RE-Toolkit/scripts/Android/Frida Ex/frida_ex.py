#!/usr/bin/env python3

# FridaEX Automation Tool (Multithreaded/Optimized)

import os
import sys
import re
import json
import shlex
import struct
import time
import lzma
import plistlib
import shutil
import signal
import subprocess
import zipfile as zipfile_mod
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
import tempfile
import threading

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.panel import Panel

# prompt_toolkit for autocomplete
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError
from typing import List, Tuple, Optional

console = Console()

# Config
REMOTE_SERVER_PATH = "/data/local/tmp/frida-server"
CACHE_DIR = Path.home() / ".fridaex-cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_LIST_ONLY_USER_APPS = True
DEFAULT_BIND = "0.0.0.0:27042"

# Stable gadget mode (iOS): frida's server-injected agent crashes apps on
# iOS 27's dyld4 as soon as they lazily load an image while attached
# (SIGABRT in the dyld add-image notification path). Loading frida-gadget
# into the process instead suppresses the crash completely, so the stable
# workflow patches the app to LC_LOAD_DYLIB the gadget, lets vphone's
# apps.install re-sign it, and attaches to the gadget over iproxy.
GADGET_GUEST_PATH = "/var/root/frida-gadget.dylib"
GADGET_CONFIG_GUEST_PATH = "/var/root/frida-gadget.config"
GADGET_PORT = 27045
GADGET_URL = "https://github.com/frida/frida/releases/download/17.26.1/frida-gadget-17.26.1-ios-universal.dylib.xz"

MAX_WORKERS = max(4, (os.cpu_count() or 4))
NET_TIMEOUT = 45
ADB_TIMEOUT = 10
SHORT_TIMEOUT = 4

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------

def project_scripts_folder():
    script_dir = Path(__file__).resolve().parent
    base_dir = script_dir.parent
    scripts_path = base_dir / "Frida Script Downloader" / "scripts"
    if not scripts_path.is_dir():
        return None
    return str(scripts_path)

def run(cmd, timeout=10, check=False, text=True):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=check, text=text)


def frida_safe_env():
    """Environment for frida subprocesses/exec. DYLD_LIBRARY_PATH (and
    friends) can pull Homebrew's libpng/libjpeg in front of Apple's codecs;
    frida's device-icon extraction then decodes a PNG through the broken
    combination and dies with SIGBUS inside ImageIO (known upstream bug:
    frida-go#63). The helpers only need system frameworks, so strip them."""
    env = dict(os.environ)
    for var in ("DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"):
        env.pop(var, None)
    return env

def adb(device_id, args, timeout=ADB_TIMEOUT, check=False):
    return run(["adb", "-s", device_id] + args, timeout=timeout, check=check)

def run_as_root(device_id, *args, timeout=SHORT_TIMEOUT):
    cmd_str = " ".join(shlex.quote(a) for a in args)
    variants = [
        ["shell", "su", "-c", cmd_str],
        ["shell", "su", "0", cmd_str],
        ["shell", "sh", "-c", f"su -c {shlex.quote(cmd_str)}"],
    ]
    last_err = None
    for v in variants:
        try:
            return adb(device_id, v, timeout=timeout)
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("su invocation failed")

def try_adb_root(device_id):
    res = adb(device_id, ["root"], timeout=8)
    out = (res.stdout + res.stderr).lower()
    time.sleep(1.0)
    return "cannot run as root" not in out

def is_device_rooted(device_id):
    try:
        res = run_as_root(device_id, "whoami", timeout=3)
        return "root" in res.stdout.strip().lower()
    except Exception:
        return False

class _DeviceInfo:
    """Lightweight stand-in for a frida.core.Device, carrying only what the
    rest of this script needs (id/type/name, plus the OS id we pre-fetched
    for it - see get_frida_devices)."""
    __slots__ = ("id", "type", "name", "os_id")

    def __init__(self, id_, type_, name_, os_id_):
        self.id = id_
        self.type = type_
        self.name = name_
        self.os_id = os_id_


_ENUMERATE_DEVICES_HELPER = (
    "import frida, json\n"
    "out = []\n"
    "for d in frida.enumerate_devices():\n"
    "    try:\n"
    "        params = d.query_system_parameters()\n"
    "        os_id = (params.get('os') or {}).get('id') or None\n"
    "    except Exception:\n"
    "        os_id = None\n"
    "    out.append({'id': d.id, 'type': d.type, 'name': d.name, 'os_id': os_id})\n"
    "print(json.dumps(out))\n"
)


def get_frida_devices():
    """Enumerate Frida devices out-of-process.

    frida.enumerate_devices() has been observed to crash the interpreter
    outright (SIGBUS, no traceback) on some host/version combinations -
    notably when the Python `frida` module's version doesn't match the
    frida-server/CLI version on the target device. Running it in a
    subprocess means a crash there is reported as a failed subprocess
    instead of taking the whole tool down with it.
    """
    try:
        res = subprocess.run(
            [sys.executable, "-c", _ENUMERATE_DEVICES_HELPER],
            capture_output=True, text=True, timeout=30, env=frida_safe_env(),
        )
    except subprocess.TimeoutExpired:
        console.print("[red]Error getting devices: enumeration timed out.[/]")
        return []
    except Exception as e:
        console.print(f"[red]Error getting devices: {e}[/]")
        return []

    if res.returncode != 0:
        if res.returncode < 0:
            console.print(f"[red]❌ Device enumeration crashed (signal {-res.returncode}) instead of raising an error.[/]")
        else:
            err = (res.stderr or "").strip().splitlines()
            console.print(f"[red]❌ Error getting devices: {err[-1] if err else 'unknown error'}[/]")
        console.print(
            "[yellow]This is commonly caused by a version mismatch between the Python "
            "`frida` module this tool uses and the frida-server/frida CLI on the "
            "target device (run `frida --version` and align the versions), or by "
            "DYLD_LIBRARY_PATH pulling Homebrew image dylibs into frida's icon "
            "decoder (frida-go#63) - this tool already strips DYLD_* for its frida "
            "subprocesses, so a crash here means the outer environment is doing it.[/]"
        )
        return []

    try:
        data = json.loads(res.stdout.strip() or "[]")
    except Exception as e:
        console.print(f"[red]Error parsing device list: {e}[/]")
        return []

    return [_DeviceInfo(d["id"], d["type"], d.get("name") or d["id"], d.get("os_id")) for d in data]


_ENUMERATE_APPS_HELPER = (
    "import frida, json, sys\n"
    "dev = frida.get_device(sys.argv[1], timeout=15)\n"
    "apps = dev.enumerate_applications()\n"
    "print(json.dumps([{'identifier': a.identifier, 'name': a.name, 'pid': a.pid} for a in apps]))\n"
)


def get_frida_applications(device_id):
    """List installed applications through Frida itself. iOS has no adb,
    so this is the only way to enumerate apps there. Runs out-of-process
    for the same crash-isolation reason as get_frida_devices."""
    try:
        res = subprocess.run(
            [sys.executable, "-c", _ENUMERATE_APPS_HELPER, device_id],
            capture_output=True, text=True, timeout=45, env=frida_safe_env(),
        )
    except subprocess.TimeoutExpired:
        console.print("[red]Error listing applications: timed out.[/]")
        return []
    except Exception as e:
        console.print(f"[red]Error listing applications: {e}[/]")
        return []

    if res.returncode != 0:
        err = (res.stderr or "").strip().splitlines()
        console.print(f"[red]❌ Error listing applications: {err[-1] if err else 'unknown error'}[/]")
        console.print(
            "[yellow]Frida couldn't talk to the device. On iOS this usually means "
            "frida-server isn't running inside the VM/device (it must be jailbroken "
            "with frida-server started as root).[/]"
        )
        return []

    try:
        return json.loads(res.stdout.strip() or "[]")
    except Exception as e:
        console.print(f"[red]Error parsing application list: {e}[/]")
        return []

# ------------------------------------------------------------------------------
# Type completion helpers
# ------------------------------------------------------------------------------

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


def resolve_selection(user_input: str, items: List[str], names: Optional[List[str]] = None) -> Optional[int]:
    """
    Resolve user input to item index (0-based).
    Prioritizes exact matches over fuzzy matches.
    """
    if names is None:
        names = items
    
    user_lower = user_input.lower().strip()
    
    # Direct numeric selection
    if user_input.strip().isdigit():
        idx = int(user_input.strip()) - 1
        if 0 <= idx < len(items):
            return idx
        return None
    
    # First, try exact match (case-insensitive)
    for i, name in enumerate(names):
        if name.lower() == user_lower:
            return i
    
    # Then try starts-with match - prefer longer/more specific matches
    starts_with_matches = []
    for i, name in enumerate(names):
        if name.lower().startswith(user_lower):
            starts_with_matches.append((len(name), i, name))
    
    if starts_with_matches:
        # Sort by length (longer = more specific), then by index (stable order)
        starts_with_matches.sort(key=lambda x: (-x[0], x[1]))
        return starts_with_matches[0][1]
    
    # Find best match using same scoring logic
    best_score = (4, 0, 0, '')
    best_idx = None
    
    for i, name in enumerate(names):
        score = calculate_match_score(user_input, name)
        if score < best_score:
            best_score = score
            best_idx = i
    
    # Only return if we found at least a fuzzy match
    if best_score[0] < 4:
        return best_idx
    
    return None


class DeviceCompleter(Completer):
    """Custom completer for device selection."""
    
    def __init__(self, devices: List):
        self.devices = devices
        self.device_ids = [dev.id for dev in devices]
    
    def get_completions(self, document, complete_event):
        text = document.text.strip()
        
        # If user typed a number, show that specific device
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.devices):
                dev = self.devices[idx - 1]
                yield Completion(
                    text,
                    start_position=-len(document.text),
                    display=f"#{idx} → {dev.id} ({dev.type})"
                )
            return
        
        # Match by device ID with scoring
        matches = []
        for i, dev_id in enumerate(self.device_ids, 1):
            dev = self.devices[i - 1]
            score = calculate_match_score(text, dev_id)
            if score[0] < 4:
                matches.append((score, i, dev_id, dev.type))
        
        matches.sort(key=lambda x: x[0])
        
        for score, idx, dev_id, dev_type in matches:
            yield Completion(
                str(idx) if text.isdigit() or len(text) == 0 else dev_id,
                start_position=-len(document.text),
                display=f"[{idx}] {dev_id} ({dev_type})"
            )


class DeviceValidator(Validator):
    """Validator for device selection."""
    
    def __init__(self, count: int, device_ids: List[str]):
        self.count = count
        self.device_ids = device_ids
    
    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message='Type a number or device ID')
        
        if t.isdigit():
            idx = int(t)
            if 1 <= idx <= self.count:
                return
            raise ValidationError(message=f'Number must be 1..{self.count}')
        
        resolved = resolve_selection(t, self.device_ids)
        if resolved is None:
            raise ValidationError(message='No matching device found')


class PackageCompleter(Completer):
    """Custom completer for package selection."""
    
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
            if score[0] < 4:
                matches.append((score, i, package))
        
        matches.sort(key=lambda x: x[0])
        
        for score, idx, package in matches[:20]:  # Limit to top 20
            yield Completion(
                package,
                start_position=-len(document.text),
                display=f"[{idx}] {package}"
            )


class PackageValidator(Validator):
    """Validator for package selection."""
    
    def __init__(self, count: int, packages: List[str]):
        self.count = count
        self.packages = packages
    
    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message='Type a number or package name')
        
        if t.isdigit():
            idx = int(t)
            if 1 <= idx <= self.count:
                return
            raise ValidationError(message=f'Number must be 1..{self.count}')
        
        resolved = resolve_selection(t, self.packages)
        if resolved is None:
            raise ValidationError(message='No matching package found')


class ScriptCompleter(Completer):
    """Custom completer for script selection."""
    
    def __init__(self, scripts: List[str]):
        self.scripts = scripts
        self.script_names = [os.path.basename(s) for s in scripts]
    
    def get_completions(self, document, complete_event):
        text = document.text.strip()
        
        # If user typed a number, show that specific script
        if text.isdigit():
            idx = int(text)
            if idx == 0:
                yield Completion(
                    text,
                    start_position=-len(document.text),
                    display="0 → Skip script injection"
                )
                return
            if 1 <= idx <= len(self.scripts):
                script_name = self.script_names[idx - 1]
                yield Completion(
                    text,
                    start_position=-len(document.text),
                    display=f"#{idx} → {script_name}"
                )
            return
        
        # Match by script name with scoring
        matches = []
        for i, script_name in enumerate(self.script_names, 1):
            score = calculate_match_score(text, script_name)
            if score[0] < 4:
                matches.append((score, i, script_name))
        
        matches.sort(key=lambda x: x[0])
        
        for score, idx, script_name in matches[:15]:  # Limit to top 15
            yield Completion(
                script_name,
                start_position=-len(document.text),
                display=f"[{idx}] {script_name}"
            )


class ScriptValidator(Validator):
    """Validator for script selection."""
    
    def __init__(self, count: int, script_names: List[str]):
        self.count = count
        self.script_names = script_names
    
    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message='Type a number or script name')
        
        if t.isdigit():
            idx = int(t)
            if 0 <= idx <= self.count:
                return
            raise ValidationError(message=f'Number must be 0..{self.count}')
        
        resolved = resolve_selection(t, self.script_names)
        if resolved is None:
            raise ValidationError(message='No matching script found')


def select_device(devices):
    if not devices:
        console.print("[red]No devices found! Ensure ADB detects a device/emulator.[/]")
        sys.exit(1)
    
    # Filter out remote ADB devices and local Frida instances, keep only USB devices
    real_devices = []
    for dev in devices:
        dev_id_lower = dev.id.lower()
        dev_type_lower = dev.type.lower()
        
        # Exclude local Frida instances and socket connections
        if dev_id_lower in ["local", "socket"]:
            continue
        # Exclude devices with "local" type (local Frida instances)
        if dev_type_lower == "local":
            continue
        # Exclude all remote ADB devices
        if dev_type_lower == "remote":
            continue
        # Include USB devices (always real)
        if dev_type_lower == "usb":
            real_devices.append(dev)
        # Include any other types that might be real devices (but not remote or local)
        elif dev_type_lower not in ["local", "remote"]:
            real_devices.append(dev)
    
    if not real_devices:
        console.print("[red]No actual ADB devices found! Ensure a device/emulator is connected via ADB.[/]")
        sys.exit(1)
    
    # Auto-select if only one real device
    if len(real_devices) == 1:
        selected = real_devices[0]
        console.print(f"\n[green]✅ Auto-selected device: {selected.id} ({selected.type.capitalize()})[/]\n")
        return selected
    
    # Show filtered device list
    console.print("\n[cyan]📱 Available Devices:[/]")
    table = Table(title="Connected Devices", show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True)
    table.add_column("Device ID", style="green")
    table.add_column("Type", style="yellow")
    for i, dev in enumerate(real_devices, 1):
        table.add_row(str(i), dev.id, dev.type.capitalize())
    console.print(table)
    
    device_ids = [dev.id for dev in real_devices]
    completer = DeviceCompleter(real_devices)
    validator = DeviceValidator(len(real_devices), device_ids)
    
    console.print("[cyan]💡 Type a number or device ID, use Tab/Arrow keys for suggestions[/]\n")
    
    while True:
        try:
            choice = pt_prompt(
                HTML('<cyan>Select device (# or ID):</cyan> '),
                completer=completer,
                complete_while_typing=True,
                validator=validator,
                validate_while_typing=False
            ).strip()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Exiting...[/]")
            sys.exit(130)
        
        # Check if it's a number
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(real_devices):
                return real_devices[idx - 1]
        
        # Try to resolve by device ID
        resolved = resolve_selection(choice, device_ids)
        if resolved is not None:
            return real_devices[resolved]
        
        console.print("[bold red]Invalid selection. Try again.[/]")

def detect_device_os(device):
    """Identify the connected device's OS from the os_id Frida reported
    for it during enumeration (works over USB regardless of whether adb
    can see the device, e.g. iOS). Returns a lowercase os id
    ('android', 'ios', ...) or 'unknown' if it wasn't available."""
    os_id = getattr(device, "os_id", None)
    return os_id.lower() if os_id else "unknown"

def detect_device_arch(device_id):
    res = adb(device_id, ["shell", "getprop", "ro.product.cpu.abi"], timeout=5)
    abi = res.stdout.strip().lower()
    if "arm64" in abi: return "arm64"
    if "arm" in abi: return "arm"
    if "x86_64" in abi: return "x86_64"
    if "x86" in abi: return "x86"
    console.print(f"[yellow]Unrecognized ABI '{abi}', defaulting to arm.[/]")
    return "arm"

def get_local_frida_version():
    res = run(["frida", "--version"], timeout=6, check=True)
    return res.stdout.strip()

def build_frida_asset_urls(version, arch):
    filename = f"frida-server-{version}-android-{arch}.xz"
    url = f"https://github.com/frida/frida/releases/download/{version}/{filename}"
    return filename, url

# ---- Multithreaded frida-server acquisition ----

def _stream_download(url, dst_path, timeout=NET_TIMEOUT):
    with requests.get(url, stream=True, timeout=timeout) as resp:
        resp.raise_for_status()
        with open(dst_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 256):
                if chunk:
                    f.write(chunk)

def _xz_decompress_stream(xz_path, out_path):
    # Stream decompress to avoid big temp files
    with lzma.open(xz_path, "rb") as xzf, open(out_path, "wb") as out:
        shutil.copyfileobj(xzf, out)
    os.chmod(out_path, 0o755)

def ensure_cached_download_fast(version, arch, executor: ThreadPoolExecutor):
    filename, url = build_frida_asset_urls(version, arch)
    xz_path = CACHE_DIR / filename
    bin_path = CACHE_DIR / filename.replace(".xz", "")
    if bin_path.exists():
        return str(bin_path)

    # If no xz file, download in background; as soon as file exists and is non-empty, start decompress in another thread
    dl_future: Future = None
    decomp_future: Future = None

    if not xz_path.exists():
        console.print(f"[cyan]🔽 Downloading: {url}[/]")
        # Download into a temp file then move atomically
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".xz", dir=str(CACHE_DIR))
        os.close(tmp_fd)
        def do_download():
            try:
                _stream_download(url, tmp_path)
                os.replace(tmp_path, xz_path)
                return True
            finally:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
        dl_future = executor.submit(do_download)
    else:
        # Already downloaded; create a resolved future
        dl_future = executor.submit(lambda: True)

    # Decompress once download completes
    def do_decompress_after_download():
        dl_future.result()  # propagate errors
        console.print("[cyan]🔍 Extracting frida-server from XZ...[/]")
        _xz_decompress_stream(xz_path, bin_path)
        console.print("[green]✅ Extraction complete.[/]")
        return str(bin_path)

    decomp_future = executor.submit(do_decompress_after_download)
    return decomp_future.result()

# ---- Faster ADB server prep ----

def push_server(device_id, local_server_path):
    console.print("[cyan]📂 Pushing frida-server to device...[/]")
    adb(device_id, ["shell", "rm", "-f", REMOTE_SERVER_PATH], timeout=6)
    adb(device_id, ["push", local_server_path, REMOTE_SERVER_PATH], timeout=30)
    try:
        run_as_root(device_id, "chmod", "755", REMOTE_SERVER_PATH, timeout=3)
    except Exception:
        adb(device_id, ["shell", "chmod", "755", REMOTE_SERVER_PATH], timeout=5)
    console.print("[green]✅ frida-server pushed and chmod 755.[/]")

def kill_existing_frida(device_id):
    # parallel attempts for faster cleanup
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [
            ex.submit(lambda: adb(device_id, ["shell", "pkill", "-f", "frida-server"], timeout=3)),
            ex.submit(lambda: adb(device_id, ["shell", "sh", "-c", "killall frida-server"], timeout=3)),
            ex.submit(lambda: adb(device_id, ["shell", "sh", "-c", "for p in $(ps -A | grep frida-server | awk '{print $2}'); do kill -9 $p; done"], timeout=3)),
        ]
        for f in futs:
            try:
                f.result(timeout=3)
            except Exception:
                pass
    time.sleep(0.4)

def is_frida_running(device_id):
    checks = [
        ["shell", "pidof", "frida-server"],
        ["shell", "pgrep", "frida-server"],
    ]
    with ThreadPoolExecutor(max_workers=len(checks)) as ex:
        futures = [ex.submit(lambda c=c: adb(device_id, c, timeout=3)) for c in checks]
        for f in as_completed(futures, timeout=3.5):
            try:
                r = f.result()
                if r.stdout.strip():
                    return True
            except Exception:
                continue
    # Fallback
    r = adb(device_id, ["shell", "sh", "-c", "ps -A | grep frida-server | grep -v grep"], timeout=3)
    return bool(r.stdout.strip())

def start_frida_server(device_id, use_root, bind_addr=DEFAULT_BIND, retries=3, wait_secs=1.2):
    kill_existing_frida(device_id)
    cmd = f"{REMOTE_SERVER_PATH} -l {bind_addr} >/dev/null 2>&1 < /dev/null &"

    def try_start():
        try:
            if use_root:
                run_as_root(device_id, "sh", "-c", cmd, timeout=3)
            else:
                adb(device_id, ["shell", "sh", "-c", cmd], timeout=3)
        except Exception:
            pass

    for attempt in range(1, retries + 1):
        console.print(f"[cyan]🚀 Starting frida-server (attempt {attempt}/{retries})...[/]")
        with ThreadPoolExecutor(max_workers=2) as ex:
            ex.submit(try_start)
            ex.submit(lambda: time.sleep(wait_secs))
        if is_frida_running(device_id):
            console.print("[green]✅ Frida server is running.[/]")
            return True
    console.print("[red]❌ Failed to start frida-server after retries.[/]")
    return False

def disable_usap_and_reboot(device_id):
    console.print("[cyan]🔧 Disabling USAP pool and rebooting...[/]")
    try:
        try:
            run_as_root(device_id, "setprop", "persist.device_config.runtime_native.usap_pool_enabled", "false", timeout=3)
        except Exception:
            pass
        try:
            run_as_root(device_id, "setprop", "persist.sys.usap_pool_enabled", "false", timeout=3)
        except Exception:
            pass
    except Exception:
        console.print("[yellow]⚠ Could not set USAP property; proceeding.[/]")
    adb(device_id, ["reboot"], timeout=5)
    console.print("[cyan]⏳ Waiting for device to reboot...[/]")
    time.sleep(5)
    while True:
        try:
            out = adb(device_id, ["shell", "getprop", "sys.boot_completed"], timeout=5)
            if out.stdout.strip() == "1":
                break
        except Exception:
            pass
        time.sleep(1.5)
    time.sleep(2.0)
    console.print("[green]✅ Device rebooted and boot completed.[/]")

# ---- Faster package listing ----

def list_installed_packages(device_id, only_user=DEFAULT_LIST_ONLY_USER_APPS):
    console.print("[cyan]🔍 Retrieving installed packages...[/]")
    cmd = ["shell", "pm", "list", "packages", "-3"] if only_user else ["shell", "pm", "list", "packages"]
    res = adb(device_id, cmd, timeout=20)
    lines = res.stdout.splitlines()

    # Clean lines concurrently
    def clean(line):
        if line.startswith("package:"):
            return line.replace("package:", "").strip()
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        cleaned = list(ex.map(clean, lines))

    packages = [p for p in cleaned if p]
    packages.sort()
    return packages

def select_package(packages):
    if not packages:
        console.print("[red]❌ No packages found on the device.[/]")
        sys.exit(1)

    # Build table incrementally (perceived performance)
    table = Table(title="Installed Packages", show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True)
    table.add_column("Package Name", style="green")

    with Live(Panel("Loading package list..."), refresh_per_second=8, transient=True):
        pass

    # Batch rows in chunks
    chunk = 200
    for i in range(0, len(packages), chunk):
        rows = packages[i:i+chunk]
        for j, pkg in enumerate(rows, start=i+1):
            table.add_row(str(j), pkg)
    console.print(table)
    
    completer = PackageCompleter(packages)
    validator = PackageValidator(len(packages), packages)
    
    console.print("[cyan]💡 Type a number or package name, use Tab/Arrow keys for suggestions[/]\n")
    
    while True:
        try:
            choice = pt_prompt(
                HTML('<cyan>Select package (# or name):</cyan> '),
                completer=completer,
                complete_while_typing=True,
                validator=validator,
                validate_while_typing=False
            ).strip()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Exiting...[/]")
            sys.exit(130)
        
        # Check if it's a number
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(packages):
                return packages[idx - 1]
        
        # Try to resolve by package name
        resolved = resolve_selection(choice, packages)
        if resolved is not None:
            return packages[resolved]
        
        console.print("[bold red]Invalid selection. Try again.[/]")

def select_frida_script(default_folder=None):
    folder = default_folder
    if not folder or not os.path.isdir(folder):
        folder = Prompt.ask("[bold cyan]Enter path to folder with .js scripts (or leave empty to skip)[/]", default="").strip()
    if not folder:
        return None
    if not os.path.isdir(folder):
        console.print(f"[yellow]Not a directory: {folder}. Skipping script injection.[/]")
        return None
    scripts = [f for f in os.listdir(folder) if f.endswith(".js")]
    if not scripts:
        console.print("[yellow]No .js scripts found. Skipping script injection.[/]")
        return None
    table = Table(title="Available Frida Scripts", show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True)
    table.add_column("Script Name", style="green")
    for i, script_name in enumerate(scripts, 1):
        table.add_row(str(i), script_name)
    table.add_row("0", "[italic]Skip script injection (launch Frida shell only)[/]")
    console.print(table)
    
    script_paths = [os.path.join(folder, s) for s in scripts]
    script_names = [os.path.basename(s) for s in script_paths]
    completer = ScriptCompleter(script_paths)
    validator = ScriptValidator(len(scripts), script_names)
    
    console.print("[cyan]💡 Type a number or script name, use Tab/Arrow keys for suggestions[/]\n")
    
    while True:
        try:
            choice = pt_prompt(
                HTML('<cyan>Select script (# or name, 0 to skip):</cyan> '),
                completer=completer,
                complete_while_typing=True,
                validator=validator,
                validate_while_typing=False
            ).strip()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Exiting...[/]")
            sys.exit(130)
        
        # Check if it's a number
        if choice.isdigit():
            idx = int(choice)
            if idx == 0:
                return None
            if 1 <= idx <= len(scripts):
                return script_paths[idx - 1]
        
        # Try to resolve by script name
        resolved = resolve_selection(choice, script_names)
        if resolved is not None:
            return script_paths[resolved]
        
        console.print("[bold red]Invalid selection. Try again.[/]")

def launch_frida_shell(device_id, package_name, script_path=None):
    console.print("[cyan]🚀 Launching Frida shell...[/]")
    cmd = ["frida", "-D", device_id, "-f", package_name]
    if script_path:
        cmd.extend(["-l", script_path])
    env = frida_safe_env()
    try:
        os.execvpe(cmd[0], cmd, env)
    except FileNotFoundError:
        console.print("[red]❌ 'frida' not found in PATH. Ensure frida-tools is installed and on PATH.[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[yellow]⚠ exec failed ({e}); falling back to subprocess.[/]")
        subprocess.call(cmd, env=env)


def wait_for_app_pid(device_id, bundle_id, timeout=90):
    console.print(f"[cyan]⏳ Waiting for {bundle_id} to start - open (tap) it on the device/VM now (Ctrl+C to abort)...[/]")
    deadline = time.time() + timeout
    while time.time() < deadline:
        for a in get_frida_applications(device_id):
            if a["identifier"] == bundle_id and a.get("pid"):
                return a["pid"]
        time.sleep(2)
    return None


def launch_ios_frida_shell(device_id, bundle_id, pid, script_path=None):
    env = frida_safe_env()
    args = ["frida", "-D", device_id]
    if pid:
        console.print(f"[cyan]🚀 App already running (pid {pid}) - attaching...[/]")
        args += ["-p", str(pid)]
    else:
        console.print("[cyan]🚀 Launching Frida shell (spawn)...[/]")
        args += ["-f", bundle_id]
    if script_path:
        args += ["-l", script_path]

    res = subprocess.run(args, env=env)
    if res.returncode == 0 or pid:
        return

    # Spawn refused (e.g. expired provisioning profile or debug-stub builds
    # like Injecta apps - frida reports NotSupportedError/ECANCELED). The app
    # usually still launches fine by hand, so ask the user to open it and
    # attach instead - same flow the README documents for running apps.
    console.print(f"[yellow]⚠ Spawn of {bundle_id} was refused (exit {res.returncode}). Falling back to attach.[/]")
    pid = wait_for_app_pid(device_id, bundle_id)
    if not pid:
        console.print("[red]❌ App never appeared - can't attach.[/]")
        sys.exit(1)
    args = ["frida", "-D", device_id, "-p", str(pid)]
    if script_path:
        args += ["-l", script_path]
    subprocess.run(args, env=env)


# --- Stable gadget mode (iOS) ----------------------------------------------

def get_toolkit_ipa_dirs():
    script_dir = Path(__file__).resolve().parent
    root = script_dir.parents[2]  # Mobile-RE-Toolkit
    return [root, root / "src", root / "src" / "ipa", root / "src" / "output" / "pulled_ipas"]


def find_ipa_for_bundle(bundle_id):
    """Find an IPA in the toolkit's IPA folders whose CFBundleIdentifier
    matches, so we can patch and re-install it through vphone."""
    seen = set()
    for d in get_toolkit_ipa_dirs():
        if not d.is_dir():
            continue
        for ipa in d.rglob("*.ipa"):
            key = os.path.realpath(ipa)
            if key in seen:
                continue
            seen.add(key)
            try:
                with zipfile_mod.ZipFile(ipa) as zf:
                    for name in zf.namelist():
                        if name.endswith(".app/Info.plist"):
                            info = plistlib.loads(zf.read(name))
                            if info.get("CFBundleIdentifier") == bundle_id:
                                return ipa
                            break
            except Exception:
                continue
    return None


def macho_add_load_dylib(binary: Path, dylib_path: str) -> None:
    """Add an LC_LOAD_DYLIB command to a thin arm64 Mach-O executable and
    drop LC_CODE_SIGNATURE (the bundle is re-signed by vphone's
    apps.install afterwards). Raises if the header has no room."""
    data = bytearray(binary.read_bytes())
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic != 0xfeedfacf:
        raise RuntimeError(f"{binary.name}: not a thin arm64 Mach-O (magic {magic:#x}) - patch this one manually")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)

    first_data = len(data)
    kept = bytearray()
    kept_size = 0
    kept_cmds = 0
    p = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmd == 0x19:  # LC_SEGMENT_64
            fileoff, filesize = struct.unpack_from("<QQ", data, p + 40)
            if 0 < fileoff < first_data and filesize > 0:
                first_data = fileoff
            nsects = struct.unpack_from("<I", data, p + 64)[0]
            sp = p + 72
            for _ in range(nsects):
                size = struct.unpack_from("<Q", data, sp + 40)[0]
                off = struct.unpack_from("<I", data, sp + 48)[0]
                if 0 < off < first_data and size > 0:
                    first_data = off
                sp += 80
        if cmd != 0x1d:  # drop LC_CODE_SIGNATURE
            kept += data[p:p + cmdsize]
            kept_size += cmdsize
            kept_cmds += 1
        p += cmdsize

    path_bytes = dylib_path.encode() + b"\x00"
    new_cmdsize = (24 + len(path_bytes) + 7) & ~7
    new_cmd = struct.pack("<IIIIII", 0x0C, new_cmdsize, 24, 0, 0x10000, 0x10000)
    new_cmd += path_bytes + b"\x00" * (new_cmdsize - 24 - len(path_bytes))

    if 32 + kept_size + new_cmdsize > first_data:
        raise RuntimeError(f"{binary.name}: no room in the Mach-O header for LC_LOAD_DYLIB")

    data[16:24] = struct.pack("<II", kept_cmds + 1, kept_size + new_cmdsize)
    data[32:32 + kept_size + new_cmdsize] = kept + new_cmd
    binary.write_bytes(data)


def repack_ipa(src_dir: Path, out_ipa: Path) -> None:
    out_resolved = out_ipa.resolve()
    with zipfile_mod.ZipFile(out_ipa, "w", zipfile_mod.ZIP_DEFLATED) as zf:
        for path in sorted(src_dir.rglob("*")):
            if path.is_file() and path.resolve() != out_resolved:
                zf.write(path, path.relative_to(src_dir))


# --- vphone CLI integration (stable mode's deploy channel) ------------------

def vph(*args, timeout=120):
    return subprocess.run(["vphone-launchpad-cli", *args], capture_output=True, text=True, timeout=timeout)


def vph_machine_for(device_id):
    """Match the frida device to a vphone machine by UDID; fall back to the
    only machine."""
    if not shutil.which("vphone-launchpad-cli"):
        return None
    try:
        res = vph("vm", "list", timeout=30)
        machines = json.loads(res.stdout)
    except Exception:
        return None
    if not machines:
        return None
    for m in machines:
        if m.get("udid") == device_id:
            return m.get("name")
    return machines[0].get("name") if len(machines) == 1 else None


def vph_push(machine, local, remote, mode="644", retries=3):
    payload = json.dumps({"t": "push", "local": str(local), "path": remote, "mode": mode, "screen": False})
    for attempt in range(retries):
        try:
            res = vph("guest", "send", machine, payload)
            if res.returncode == 0 and '"ok"' in res.stdout:
                return True
        except Exception:
            pass
        time.sleep(1.5)
    return False


def vph_rpc(machine, method, params, timeout=120):
    res = vph("guest", "rpc", machine, method, json.dumps(params), timeout=timeout)
    return res.returncode == 0


def ensure_gadget_cached():
    """Download + decompress frida-gadget for iOS into the cache; returns
    the local path."""
    bin_path = CACHE_DIR / "frida-gadget-ios.dylib"
    if bin_path.exists():
        return bin_path
    xz_path = CACHE_DIR / "frida-gadget-ios.dylib.xz"
    if not xz_path.exists():
        console.print(f"[cyan]🔽 Downloading frida-gadget: {GADGET_URL}[/]")
        _stream_download(GADGET_URL, xz_path)
    console.print("[cyan]🔍 Extracting frida-gadget...[/]")
    _xz_decompress_stream(xz_path, bin_path)
    return bin_path


def ensure_gadget_in_guest(machine):
    gadget = ensure_gadget_cached()
    config = json.dumps({
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": GADGET_PORT,
            "on_load": "resume",
        }
    })
    console.print("[cyan]📂 Deploying frida-gadget into the VM...[/]")
    if not vph_push(machine, gadget, GADGET_GUEST_PATH, mode="755"):
        console.print("[red]❌ Couldn't push frida-gadget into the guest.[/]")
        return False
    tmp_cfg = CACHE_DIR / "frida-gadget.config"
    tmp_cfg.write_text(config)
    if not vph_push(machine, tmp_cfg, GADGET_CONFIG_GUEST_PATH, mode="644"):
        console.print("[red]❌ Couldn't push the gadget config into the guest.[/]")
        return False
    return True


def start_gadget_tunnel():
    if not shutil.which("iproxy"):
        console.print("[red]❌ iproxy not found (brew install libimobiledevice).[/]")
        return False
    proc = subprocess.Popen(["iproxy", str(GADGET_PORT), str(GADGET_PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import atexit
    atexit.register(proc.kill)
    time.sleep(1)
    return True


def gadget_frida_pid():
    helper = (
        "import frida, json, sys\n"
        "d = frida.get_device_manager().add_remote_device(sys.argv[1])\n"
        "print(json.dumps([p.pid for p in d.enumerate_processes()]))\n"
    )
    try:
        res = subprocess.run([sys.executable, "-c", helper, f"127.0.0.1:{GADGET_PORT}"],
                             capture_output=True, text=True, timeout=30, env=frida_safe_env())
        pids = json.loads(res.stdout.strip() or "[]")
        return pids[0] if pids else None
    except Exception:
        return None


def run_gadget_flow(device_id, bundle_id, script_path=None):
    """Stable iOS instrumentation: patch the app to preload frida-gadget,
    (re)install it through vphone (which re-signs), and attach to the
    gadget over iproxy. Returns False when the prerequisites are missing."""
    machine = vph_machine_for(device_id)
    if not machine:
        console.print("[yellow]⚠ No vphone machine matched this device - gadget mode unavailable.[/]")
        return False

    ipa = find_ipa_for_bundle(bundle_id)
    if not ipa:
        console.print(f"[yellow]⚠ No IPA with CFBundleIdentifier {bundle_id} found in the toolkit's IPA folders - gadget mode needs it to patch the app.[/]")
        return False

    console.print(f"[cyan]🔧 Instrumenting {bundle_id} with frida-gadget (stable mode)...[/]")
    with tempfile.TemporaryDirectory(prefix="fridaex_gadget_") as tmp:
        tmp_path = Path(tmp)
        with zipfile_mod.ZipFile(ipa) as zf:
            zf.extractall(tmp_path)
        app_dirs = [p for p in (tmp_path / "Payload").iterdir() if p.is_dir() and p.suffix == ".app"]
        if not app_dirs:
            console.print("[red]❌ No .app bundle inside the IPA.[/]")
            return False
        app_dir = app_dirs[0]
        with open(app_dir / "Info.plist", "rb") as f:
            info = plistlib.load(f)
        exe = app_dir / info.get("CFBundleExecutable", app_dir.stem)
        try:
            macho_add_load_dylib(exe, GADGET_GUEST_PATH)
        except RuntimeError as e:
            console.print(f"[red]❌ {e}[/]")
            return False
        patched_ipa = CACHE_DIR / "fridaex-gadget.ipa"
        repack_ipa(tmp_path, patched_ipa)
        guest_ipa = "/var/root/fridaex-gadget.ipa"

        if not vph_push(machine, patched_ipa, guest_ipa):
            console.print("[red]❌ Couldn't push the patched IPA into the guest.[/]")
            return False
        vph_rpc(machine, "apps.terminate", {"bundle_id": bundle_id})
        if not vph_rpc(machine, "apps.install", {"path": guest_ipa}):
            console.print("[red]❌ apps.install failed in the guest.[/]")
            return False

    if not ensure_gadget_in_guest(machine):
        return False
    if not start_gadget_tunnel():
        return False

    console.print(f"[cyan]🚀 Launching {bundle_id} (gadget listens on 127.0.0.1:{GADGET_PORT})...[/]")
    vph_rpc(machine, "apps.launch", {"bundle_id": bundle_id})

    pid = None
    for _ in range(10):
        pid = gadget_frida_pid()
        if pid:
            break
        time.sleep(1)
    if not pid:
        console.print("[red]❌ Gadget never came online - is the app running?[/]")
        return False

    console.print(f"[green]✅ Gadget online (pid {pid}) - attaching in stable mode.[/]")
    env = frida_safe_env()
    args = ["frida", "-H", f"127.0.0.1:{GADGET_PORT}", "-p", str(pid)]
    if script_path:
        args += ["-l", script_path]
    subprocess.run(args, env=env)
    return True


def run_ios_flow(device_id):
    """iOS devices (including vphone virtual iPhones) have no adb and can't
    use the Android frida-server bootstrap - list apps through Frida itself
    and run the frida CLI against the selected one (spawn, or attach when
    the app is already running / spawn is refused)."""
    console.print("[green]🍏 iOS device - listing apps through Frida (requires frida-server running inside the device/VM).[/]")

    apps = get_frida_applications(device_id)
    if not apps:
        console.print("[red]❌ No applications visible via Frida - is frida-server running inside the iOS VM/device?[/]")
        sys.exit(1)

    only_user = Confirm.ask("[bold cyan]Hide system apps (com.apple.*)?[/]", default=DEFAULT_LIST_ONLY_USER_APPS)
    if only_user:
        apps = [a for a in apps if not a["identifier"].startswith("com.apple.")]
    app_pids = {a["identifier"]: a.get("pid") or 0 for a in apps}
    packages = sorted(app_pids)

    chosen_package = select_package(packages)

    default_scripts_dir = project_scripts_folder()
    if default_scripts_dir:
        console.print(f"[green]✅ Using existing Frida scripts folder: {default_scripts_dir}[/]")
    else:
        console.print("[yellow]ℹ Scripts folder not auto-detected; optional path prompt follows.[/]")

    script_path = select_frida_script(default_scripts_dir)
    if script_path:
        try:
            script_src = Path(script_path).read_text(errors="replace")
        except Exception:
            script_src = ""
        if "Java.perform" in script_src or "Java.use" in script_src:
            console.print("[yellow]⚠ This script uses the Java bridge (Android-only) - it will not do anything useful on iOS.[/]")

    if Confirm.ask("[bold cyan]Use stable gadget mode?[/] (recommended - direct attach crashes apps on iOS 17+)",
                   default=True):
        if run_gadget_flow(device_id, chosen_package, script_path):
            return
        console.print("[yellow]⚠ Gadget mode unavailable - falling back to direct attach.[/]")

    launch_ios_frida_shell(device_id, chosen_package, app_pids.get(chosen_package, 0), script_path)

# ------------------------------------------------------------------------------
# Main orchestration (with parallelism)
# ------------------------------------------------------------------------------

def main():
    console.print("\n[bold magenta]🔎 FridaEX Automation Tool 🔍[/]\n")

    # Prefetch local version (subprocess, thread-safe) while enumerating
    # devices. frida.enumerate_devices() drives a CF run loop for USB/IOKit
    # on macOS and must stay on the main thread - calling it from a worker
    # thread crashes the interpreter outright (SIGBUS).
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_ver = ex.submit(get_local_frida_version)

        try:
            local_version = fut_ver.result(timeout=6)
            console.print(f"[cyan]Local Frida version: {local_version}[/]")
        except Exception as e:
            console.print(f"[red]❌ Unable to read local Frida version: {e}[/]")
            sys.exit(1)

    devices = get_frida_devices()
    device = select_device(devices)
    device_id = device.id

    os_id = detect_device_os(device)
    if os_id == "ios":
        run_ios_flow(device_id)
        return
    if os_id not in ("unknown", "android"):
        console.print(f"[red]❌ Selected device is {os_id.capitalize()}, not Android or iOS — not supported.[/]")
        sys.exit(1)
    if os_id == "unknown":
        console.print("[yellow]⚠ Could not determine device OS from Frida; assuming Android and proceeding.[/]")

    # Start root checks and ABI detect in parallel
    with ThreadPoolExecutor(max_workers=3) as ex:
        fut_adb_root = ex.submit(try_adb_root, device_id)
        fut_su_root = ex.submit(is_device_rooted, device_id)
        fut_arch = ex.submit(detect_device_arch, device_id)

        adb_root_ok = False
        su_root_ok = False
        arch = "arm"
        try:
            adb_root_ok = fut_adb_root.result(timeout=5)
        except Exception:
            adb_root_ok = False
        try:
            su_root_ok = fut_su_root.result(timeout=5)
        except Exception:
            su_root_ok = False
        try:
            arch = fut_arch.result(timeout=6)
        except Exception:
            arch = "arm"

    use_root = adb_root_ok or su_root_ok
    if use_root:
        console.print("[green]✅ Root available (adb root or su).[/]")
    else:
        console.print("[yellow]⚠ Root not available; frida-server may fail to start on production builds.[/]")

    # Optional USAP disable + reboot
    if Confirm.ask("[bold cyan]Disable USAP pool and reboot to improve spawn reliability?[/] (recommended if timeouts occur)", default=False):
        disable_usap_and_reboot(device_id)

    # Download/extract frida-server while the user decides whether to hide system packages
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fut_server_path = ex.submit(ensure_cached_download_fast, local_version, arch, ex)

        # Prompt quickly
        only_user = Confirm.ask("[bold cyan]Hide system packages (only user-installed)?[/]", default=DEFAULT_LIST_ONLY_USER_APPS)

        # Wait server path, then push & start concurrently
        server_path = fut_server_path.result()

        # Push while we start listing packages to overlap I/O
        fut_push = ex.submit(push_server, device_id, server_path)
        fut_pkgs = ex.submit(list_installed_packages, device_id, only_user)

        # Ensure push completes, then start server
        try:
            fut_push.result()
        except Exception as e:
            console.print(f"[red]❌ Push failed: {e}[/]")
            sys.exit(1)

        if not start_frida_server(device_id, use_root=use_root, bind_addr=DEFAULT_BIND):
            console.print("[red]❌ Unable to start Frida server. Consider manual start: 'adb shell; su; /data/local/tmp/frida-server'[/]")
            sys.exit(1)

        # Packages (if not ready, wait now)
        try:
            packages = fut_pkgs.result()
        except Exception as e:
            console.print(f"[red]❌ Failed to list packages: {e}[/]")
            sys.exit(1)

    chosen_package = select_package(packages)

    default_scripts_dir = project_scripts_folder()
    if default_scripts_dir:
        console.print(f"[green]✅ Using existing Frida scripts folder: {default_scripts_dir}[/]")
    else:
        console.print("[yellow]ℹ Scripts folder not auto-detected; optional path prompt follows.[/]")

    script_path = select_frida_script(default_scripts_dir)

    launch_frida_shell(device_id, chosen_package, script_path)

if __name__ == "__main__":
    try:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Cancelled by user[/yellow]")
        sys.exit(0)
