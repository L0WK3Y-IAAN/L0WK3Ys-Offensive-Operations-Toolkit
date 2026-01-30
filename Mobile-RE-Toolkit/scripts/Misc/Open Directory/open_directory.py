#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional, Union

Pathish = Union[str, os.PathLike]

def _resolve_target() -> Path:
    """
    Always resolve to the '../../../' directory relative to this script's location.
    """
    script_dir = Path(__file__).resolve().parent
    target = (script_dir / '../../../').resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")
    if not target.is_dir():
        raise NotADirectoryError(f"Not a directory: {target}")
    return target

def open_dir() -> None:
    """
    Open a directory in the system file explorer.
    - path=None: opens the directory containing main entry script (main.py).
    - path=<str|Path>: opens that directory (or the parent if a file is given).
    """
    try:
        target = _resolve_target()

        if sys.platform.startswith("win"):
            os.startfile(str(target))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", str(target)], check=False)
        else:
            # POSIX/Linux/BSD
            subprocess.run(["xdg-open", str(target)], check=False)
    except Exception as e:
        print(f"[open_dir] Failed to open directory: {e}", file=sys.stderr)

if __name__ == "__main__":
    # Accept 0 or 1 argument; ignore extras gracefully but warn.
    if len(sys.argv) > 2:
        print("[open_dir] Warning: extra arguments ignored.", file=sys.stderr)
    open_dir()
