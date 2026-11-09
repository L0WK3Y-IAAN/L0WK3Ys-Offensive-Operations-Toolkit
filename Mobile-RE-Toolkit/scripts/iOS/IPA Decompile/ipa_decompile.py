#!/usr/bin/env python3
"""IPA Decompile - lists IPAs under the toolkit's src tree (same convention
as Open In Jadx's APK picker), lets the user pick one, detects whether the
app binary is Swift, Objective-C, or a mix of both, and dumps its
declarations via ipsw into a per-app output folder."""

import os
import plistlib
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.validation import Validator, ValidationError

console = Console()


# --- Toolkit path resolution -------------------------------------------------

def get_toolkit_root() -> Path:
    """Resolve Mobile-RE-Toolkit root (contains main.py). src/ is created
    on demand, so it isn't required to exist yet."""
    env_root = os.environ.get("MOBILE_RE_TOOLKIT_ROOT")
    if env_root:
        root = Path(env_root).resolve()
        if root.exists() and (root / "main.py").exists():
            return root
    script_dir = Path(__file__).resolve().parent
    current = script_dir
    for _ in range(10):
        if (current / "main.py").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    cwd = Path.cwd()
    if (cwd / "main.py").exists():
        return cwd
    return script_dir


def get_ipa_directories() -> List[str]:
    root = get_toolkit_root()
    return [
        str(root),
        str(root / "src"),
        str(root / "src" / "ipa"),
        str(root / "src" / "output" / "pulled_ipas"),
    ]


def get_decompile_output_dir(app_name: str) -> Path:
    root = get_toolkit_root()
    out = root / "src" / "output" / "decompiled_ipas" / app_name
    out.mkdir(parents=True, exist_ok=True)
    return out


# --- Background scan ---------------------------------------------------------

def scan_ipas_worker(dirs: List[str], out_q: queue.Queue):
    seen = set()
    ipas = []
    for d in dirs:
        if not os.path.exists(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if f.endswith(".ipa"):
                    path = os.path.join(root, f)
                    canonical = os.path.realpath(path)
                    if canonical not in seen:
                        seen.add(canonical)
                        ipas.append(path)
    ipas.sort(key=lambda p: os.path.basename(p).lower())
    out_q.put(ipas)


# --- Completer / validator (same fuzzy-match UX as Open In Jadx) -----------

class FileCompleter(Completer):
    def __init__(self, paths: List[str]):
        self.paths = paths
        self.filenames = [os.path.basename(p) for p in paths]

    def get_completions(self, document, complete_event):
        text = document.text.strip()
        if text.isdigit():
            idx = int(text)
            if 1 <= idx <= len(self.paths):
                yield Completion(text, start_position=-len(text), display=f"#{idx} -> {self.filenames[idx-1]}")
            return
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
    def __init__(self, count: int):
        self.count = count

    def validate(self, document):
        t = document.text.strip()
        if not t:
            raise ValidationError(message="Type a number or start typing a name")
        if t.isdigit():
            idx = int(t)
            if 1 <= idx <= self.count:
                return
            raise ValidationError(message=f"Number must be 1..{self.count}")
        return


def select_from_list(paths: List[str], noun: str) -> str:
    completer = FileCompleter(paths)
    fuzzy = FuzzyCompleter(completer)
    validator = NumberOrNameValidator(len(paths))

    console.print("\n[cyan]💡 You can either:[/cyan]")
    console.print("  • Type a number (e.g., '1', '2', '3')")
    console.print(f"  • Start typing a {noun} name for fuzzy search")
    console.print("  • Use Tab for autocompletion\n")

    try:
        answer = pt_prompt(
            HTML("<cyan>Enter # or start typing name:</cyan> "),
            completer=fuzzy,
            complete_while_typing=True,
            validator=validator,
            validate_while_typing=True,
        ).strip()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Selection cancelled[/yellow]")
        sys.exit(0)

    if answer.isdigit():
        return paths[int(answer) - 1]

    lower = answer.lower()
    best = None
    best_key = (True, 10**9, "")
    for p in paths:
        name_l = os.path.basename(p).lower()
        if FileCompleter._fuzzy_match(lower, name_l):
            key = (not name_l.startswith(lower), len(name_l), name_l)
            if key < best_key:
                best_key = key
                best = p
    return best if best else paths[0]


# --- IPA extraction -----------------------------------------------------------

def extract_ipa(ipa_path: str, workdir: Path) -> Path:
    """Unzip the IPA and return the path to the .app bundle inside it."""
    with zipfile.ZipFile(ipa_path) as zf:
        zf.extractall(workdir)

    payload = workdir / "Payload"
    if not payload.is_dir():
        raise RuntimeError(f"No Payload/ folder found inside {os.path.basename(ipa_path)} - not a valid IPA?")

    app_dirs = [p for p in payload.iterdir() if p.is_dir() and p.suffix == ".app"]
    if not app_dirs:
        raise RuntimeError(f"No .app bundle found inside {os.path.basename(ipa_path)}'s Payload/")
    return app_dirs[0]


def read_info_plist(app_dir: Path) -> Dict:
    plist_path = app_dir / "Info.plist"
    if not plist_path.exists():
        return {}
    try:
        with open(plist_path, "rb") as f:
            return plistlib.load(f)
    except Exception as e:
        console.print(f"[yellow]⚠ Couldn't parse Info.plist: {e}[/yellow]")
        return {}


def find_main_binary(app_dir: Path, info: Dict) -> Optional[Path]:
    exe_name = info.get("CFBundleExecutable")
    if exe_name:
        candidate = app_dir / exe_name
        if candidate.exists():
            return candidate
    candidates = [p for p in app_dir.iterdir() if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def is_macho(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False
    return magic in (
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # 32-bit
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # 64-bit
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",  # fat/universal
    )


def find_embedded_machos(app_dir: Path, main_binary: Path) -> List[Path]:
    """Other Mach-O images shipped in the bundle: root-level dylibs and
    framework executables. Xcode debug builds put all the real code in
    <name>.debug.dylib and leave the main executable as a tiny stub with
    no Swift/ObjC metadata of its own."""
    found = []
    for p in app_dir.iterdir():
        if p.is_file() and p != main_binary and is_macho(p):
            found.append(p)
    frameworks = app_dir / "Frameworks"
    if frameworks.is_dir():
        for fw in frameworks.iterdir():
            if fw.suffix == ".framework":
                candidate = fw / fw.stem
                if candidate.is_file() and is_macho(candidate):
                    found.append(candidate)
    found.sort(key=lambda p: p.stat().st_size, reverse=True)
    return found


# --- Language detection --------------------------------------------------------

def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout or ""
    except Exception:
        return ""


def _nonempty_section_present(otool_l_output: str, name_substr: str) -> bool:
    """A Mach-O section by name that actually has nonzero size, not just a
    name string appearing somewhere in `otool -l` output."""
    lines = otool_l_output.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("sectname") and name_substr in stripped:
            for lookahead in lines[i + 1:i + 6]:
                lookahead = lookahead.strip()
                if lookahead.startswith("size"):
                    try:
                        if int(lookahead.split()[-1], 16) > 0:
                            return True
                    except ValueError:
                        pass
                    break
    return False


def _defined_symbol_has_prefix(nm_output: str, prefixes: tuple) -> bool:
    """`nm -g` lists both symbols this binary defines and ones it merely
    imports from a linked dylib (type 'U', no address) - only the former
    indicates this binary's own source language."""
    for line in nm_output.splitlines():
        parts = line.split()
        if not parts or parts[0] == "U":
            continue
        name = parts[-1]
        if any(name.startswith(p) for p in prefixes):
            return True
    return False


def detect_language(binary: Path) -> str:
    """Advisory label only (see main()) - ipsw's own dumpers are the
    authority on whether a binary actually contains Swift/ObjC metadata."""
    sections = _run(["otool", "-l", str(binary)])
    has_swift_sections = _nonempty_section_present(sections, "__swift5_")

    symbols = _run(["nm", "-g", str(binary)])
    has_swift_symbols = _defined_symbol_has_prefix(symbols, ("_$s", "_$S", "_T0"))
    has_objc_symbols = _defined_symbol_has_prefix(symbols, ("_OBJC_CLASS_$_", "_OBJC_METACLASS_$_"))

    is_swift = has_swift_sections or has_swift_symbols
    is_objc = has_objc_symbols

    if is_swift and is_objc:
        return "Mixed (Swift + Objective-C)"
    if is_swift:
        return "Swift"
    if is_objc:
        return "Objective-C"
    return "Unknown/Native (C/C++)"


def is_fairplay_encrypted(binary: Path) -> bool:
    """LC_ENCRYPTION_INFO(_64) cryptid=1 means App Store FairPlay
    encryption is still on: every dumper then fails with errors like
    "macho does not contain objc/swift info". A decrypted dump from a
    jailbroken device (frida-ios-dump, bagbak, flexdecrypt) has cryptid=0."""
    info = _run(["otool", "-l", str(binary)], timeout=30)
    lines = info.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("cmd LC_ENCRYPTION_INFO"):
            for lookahead in lines[i + 1:i + 5]:
                lookahead = lookahead.strip()
                if lookahead.startswith("cryptid"):
                    try:
                        return int(lookahead.split()[-1]) == 1
                    except ValueError:
                        return False
    return False


# --- Decompilation --------------------------------------------------------
#
# Primary engine is `ipsw` (github.com/blacktop/ipsw - `brew install
# blacktop/tap/ipsw`): `class-dump` reconstructs Objective-C interfaces,
# `swift-dump` reconstructs Swift type/method declarations (mangled and
# demangled) from Swift metadata. If `ipsw` isn't installed, falls back to
# class-dump (ObjC only) and nm+demangle (Swift symbol names only).

def decompile_objc_ipsw(binary: Path, out_dir: Path) -> List[str]:
    headers_dir = out_dir / "objc_headers"
    headers_dir.mkdir(exist_ok=True)
    res = subprocess.run(
        ["ipsw", "class-dump", str(binary), "--headers", "-o", str(headers_dir)],
        capture_output=True, text=True, timeout=300,
    )
    if res.returncode == 0 and any(headers_dir.iterdir()):
        return [str(headers_dir)]
    console.print(f"[yellow]⚠ ipsw class-dump produced no headers ({(res.stderr or '').strip()[:200]})[/yellow]")
    return []


def decompile_swift_ipsw(binary: Path, out_dir: Path) -> List[str]:
    produced = []

    mangled = subprocess.run(
        ["ipsw", "swift-dump", str(binary)],
        capture_output=True, text=True, timeout=300,
    )
    if mangled.returncode == 0 and mangled.stdout.strip():
        path = out_dir / f"{binary.name}-swift-mangled.txt"
        path.write_text(mangled.stdout)
        produced.append(str(path))

    demangled = subprocess.run(
        ["ipsw", "swift-dump", str(binary), "--demangle"],
        capture_output=True, text=True, timeout=300,
    )
    if demangled.returncode == 0 and demangled.stdout.strip():
        path = out_dir / f"{binary.name}-swift-demangled.txt"
        path.write_text(demangled.stdout)
        produced.append(str(path))

    if not produced:
        err = ((mangled.stderr or "") + (demangled.stderr or "")).strip()[:200]
        console.print(f"[yellow]⚠ ipsw swift-dump produced no output ({err})[/yellow]")
    return produced


def decompile_objc_classdump_fallback(binary: Path, out_dir: Path) -> List[str]:
    if not shutil.which("class-dump"):
        console.print("[yellow]⚠ class-dump not found either - skipping Objective-C interface reconstruction.[/yellow]")
        return []
    headers_dir = out_dir / "objc_headers"
    headers_dir.mkdir(exist_ok=True)
    res = subprocess.run(
        ["class-dump", "-H", "-o", str(headers_dir), str(binary)],
        capture_output=True, text=True, timeout=120,
    )
    if res.returncode == 0 and any(headers_dir.iterdir()):
        return [str(headers_dir)]
    console.print(f"[yellow]⚠ class-dump produced no headers ({(res.stderr or '').strip()[:200]})[/yellow]")
    return []


def decompile_swift_symbols_fallback(binary: Path, out_dir: Path) -> List[str]:
    """Without ipsw this can only dump demangled symbol *names*, not full
    type/method declarations."""
    produced = []
    symbols_raw = _run(["nm", str(binary)], timeout=60)
    if symbols_raw.strip():
        demangled = subprocess.run(
            ["xcrun", "swift", "demangle"],
            input=symbols_raw, capture_output=True, text=True, timeout=60,
        )
        path = out_dir / "swift_symbols_demangled.txt"
        path.write_text(demangled.stdout if demangled.returncode == 0 else symbols_raw)
        produced.append(str(path))
    return produced


def decompile_objc(binary: Path, out_dir: Path) -> List[str]:
    if shutil.which("ipsw"):
        return decompile_objc_ipsw(binary, out_dir)
    console.print(
        "[yellow]⚠ ipsw not found - falling back to class-dump for Objective-C. "
        "Install ipsw (`brew install blacktop/tap/ipsw`) for proper header reconstruction.[/yellow]"
    )
    return decompile_objc_classdump_fallback(binary, out_dir)


def decompile_swift(binary: Path, out_dir: Path) -> List[str]:
    if shutil.which("ipsw"):
        return decompile_swift_ipsw(binary, out_dir)
    console.print(
        "[yellow]⚠ ipsw not found - falling back to raw demangled symbol names for Swift "
        "(no full declarations). Install ipsw (`brew install blacktop/tap/ipsw`) for real Swift type dumps.[/yellow]"
    )
    return decompile_swift_symbols_fallback(binary, out_dir)


def dump_disassembly(binary: Path, out_dir: Path) -> Optional[str]:
    """arm64 disassembly of the binary (otool -tV). Metadata dumps only give
    declarations - the disassembly is where the actual logic lives."""
    if binary.stat().st_size > 64 * 1024 * 1024:
        console.print(f"[yellow]⚠ Skipping disassembly of {binary.name} (larger than 64 MB).[/]")
        return None
    disasm = _run(["otool", "-tV", str(binary)], timeout=300)
    if not disasm.strip():
        return None
    path = out_dir / f"{binary.name}-disassembly.asm"
    path.write_text(disasm)
    return str(path)


def dump_strings(binary: Path, out_dir: Path) -> Optional[str]:
    """Every printable string in the binary. Often the highest-value
    artifact there is: URLs, query templates, format strings, constants."""
    out = _run(["strings", "-a", str(binary)], timeout=300)
    if not out.strip():
        return None
    path = out_dir / f"{binary.name}-strings.txt"
    path.write_text(out)
    return str(path)


def dump_symbols(binary: Path, out_dir: Path) -> Optional[str]:
    """Symbol table with addresses - the map for the disassembly. Swift
    mangled names decode to full function signatures."""
    out = _run(["nm", "-gU", str(binary)], timeout=120)
    if not out.strip():
        out = _run(["nm", "-a", str(binary)], timeout=120)
    if not out.strip():
        return None
    path = out_dir / f"{binary.name}-symbols.txt"
    path.write_text(out)
    return str(path)


def dump_code_extras(binary: Path, out_dir: Path) -> List[str]:
    produced = []
    for dumper in (dump_strings, dump_symbols, dump_disassembly):
        path = dumper(binary, out_dir)
        if path:
            produced.append(path)
    return produced


def dump_info_plist(info: Dict, out_dir: Path) -> Optional[str]:
    if not info:
        return None
    path = out_dir / "Info.plist.txt"
    with open(path, "w") as f:
        for k in sorted(info.keys()):
            f.write(f"{k}: {info[k]!r}\n")
    return str(path)


# --- Opening the result -------------------------------------------------------

def open_in_editor(target: Path) -> bool:
    for editor in ("code", "cursor", "subl"):
        if shutil.which(editor):
            try:
                subprocess.Popen([editor, str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                console.print(f"[green]✅ Opened in {editor}[/green]")
                return True
            except Exception as e:
                console.print(f"[red]❌ Couldn't launch {editor}: {e}[/red]")
    console.print("[yellow]⚠ No supported text editor (code/cursor/subl) found in PATH.[/yellow]")
    return False


def open_folder(target: Path) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(target))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", str(target)], check=False)
        else:
            subprocess.run(["xdg-open", str(target)], check=False)
        console.print(f"[green]✅ Opened folder: {target}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Failed to open folder: {e}[/red]")


# --- Main flow --------------------------------------------------------------

def main():
    console.print("[bold cyan]IPA Decompile[/bold cyan]")
    console.print("[dim]Detects Swift / Objective-C and dumps declarations via ipsw[/dim]\n")

    if sys.platform != "darwin":
        console.print("[red]❌ This tool requires macOS (otool/nm/xcrun are part of Xcode's command line tools).[/red]")
        sys.exit(1)

    missing = [b for b in ("otool", "nm", "xcrun", "unzip") if not shutil.which(b)]
    if missing:
        console.print(f"[red]❌ Missing required tools: {', '.join(missing)}. Install Xcode Command Line Tools (`xcode-select --install`).[/red]")
        sys.exit(1)

    ipa_dirs = get_ipa_directories()
    console.print(f"[cyan]🔍 Scanning for IPAs in: {ipa_dirs}[/cyan]")

    q: queue.Queue = queue.Queue()
    t = threading.Thread(target=scan_ipas_worker, args=(ipa_dirs, q), daemon=True)
    t.start()
    ipas: List[str] = q.get()

    if not ipas:
        console.print("[red]❌ No IPAs found in the following directories:[/red]")
        for directory in ipa_dirs:
            exists = "✅" if os.path.exists(directory) else "❌"
            console.print(f"  {exists} {directory}")
        sys.exit(1)

    console.print(f"[green]📦 Found {len(ipas)} IPA files[/green]\n")

    table = Table(title="Available IPA Files", show_header=True, header_style="bold magenta")
    table.add_column("Index", justify="center", style="cyan", no_wrap=True, width=8)
    table.add_column("IPA Name", style="green", min_width=20)
    table.add_column("Full Path", style="dim", overflow="ellipsis")
    for i, ap in enumerate(ipas, 1):
        table.add_row(str(i), os.path.basename(ap), ap)
    console.print(table)

    ipa_path = select_from_list(ipas, "IPA")
    console.print(f"\n[green]🎯 Selected:[/green] {os.path.basename(ipa_path)}")

    with tempfile.TemporaryDirectory(prefix="ipa_decompile_") as tmp:
        tmp_path = Path(tmp)
        console.print("[cyan]📂 Extracting IPA...[/cyan]")
        try:
            app_dir = extract_ipa(ipa_path, tmp_path)
        except Exception as e:
            console.print(f"[red]❌ {e}[/red]")
            sys.exit(1)

        info = read_info_plist(app_dir)
        app_name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or app_dir.stem

        binary = find_main_binary(app_dir, info)
        if not binary:
            console.print("[red]❌ Couldn't find the app's main executable inside the bundle.[/red]")
            sys.exit(1)
        console.print(f"[cyan]⚙ Main binary: {binary.name}[/cyan]")

        if is_fairplay_encrypted(binary):
            console.print(
                "[bold red]🔒 This binary is still FairPlay-encrypted (cryptid=1).[/bold red]\n"
                "[yellow]Every decompile/class-dump/swift-dump tool will fail or silently "
                "produce garbage against an encrypted __TEXT segment - that's why you'll "
                "see errors like \"macho does not contain objc/swift info\" below even for "
                "an app that obviously has that code. You need a decrypted IPA dumped from "
                "a jailbroken device (e.g. frida-ios-dump, bagbak, flexdecrypt) before this "
                "tool can produce anything useful.[/yellow]\n"
            )

        console.print("[cyan]🔬 Detecting source language...[/cyan]")
        language = detect_language(binary)
        console.print(f"[bold green]🏷 Detected language: {language}[/bold green]")

        out_dir = get_decompile_output_dir(f"{app_name}_{int(time.time())}")
        console.print(f"[cyan]🚀 Decompiling into: {out_dir}[/cyan]")

        # Always try both regardless of the detected label: the detection
        # heuristic can misclassify, and ipsw no-ops cleanly when a dump
        # doesn't apply.
        produced: List[str] = []
        meta = decompile_objc(binary, out_dir) + decompile_swift(binary, out_dir)
        produced += meta
        produced += dump_code_extras(binary, out_dir)

        if not meta:
            # Debug-dylib builds (and some packers) leave the main
            # executable as a stub with no Swift/ObjC metadata - the real
            # code is in an embedded dylib or framework binary.
            for extra in find_embedded_machos(app_dir, binary):
                console.print(
                    f"[cyan]⚙ Main binary has no Swift/ObjC metadata - "
                    f"trying embedded Mach-O: {extra.name}[/cyan]"
                )
                extra_dir = out_dir / extra.name
                extra_dir.mkdir(exist_ok=True)
                extra_meta = decompile_objc(extra, extra_dir) + decompile_swift(extra, extra_dir)
                if extra_meta:
                    produced += extra_meta
                    produced += dump_code_extras(extra, extra_dir)
                elif extra_dir.is_dir() and not any(extra_dir.iterdir()):
                    extra_dir.rmdir()

        plist_dump = dump_info_plist(info, out_dir)
        if plist_dump:
            produced.append(plist_dump)

        if not produced:
            console.print("[red]❌ Decompilation produced no output - check the warnings above.[/red]")
            sys.exit(1)

        console.print(f"\n[bold green]✨ Done! {len(produced)} file(s)/folder(s) written:[/bold green]")
        for p in produced:
            console.print(f"  [dim]{p}[/dim]")

    try:
        choice = pt_prompt(
            HTML("<cyan>Open (e)ditor, (f)older, or (n)othing? [e/f/n]:</cyan> ")
        ).strip().lower()
    except KeyboardInterrupt:
        choice = "n"

    if choice.startswith("e"):
        open_in_editor(out_dir)
    elif choice.startswith("f"):
        open_folder(out_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
