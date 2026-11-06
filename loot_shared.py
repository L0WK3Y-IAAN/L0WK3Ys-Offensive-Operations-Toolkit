#!/usr/bin/env python3
"""
Shared helpers for LOOT's Textual launchers - the root main.py and
Mobile-RE-Toolkit/main.py (and any future per-module launcher).

Kept dependency-free (stdlib only) so importing this never requires
textual/rich/etc. to already be installed, and kept tiny so it stays
safe to share between launchers that are otherwise independent
entry points.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict

try:
    import termios
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

# tomllib is stdlib on 3.11+; on 3.10 we fall back to the `tomli` package
# (declared in requirements.txt with a python_version<"3.11" marker). If
# neither is importable, loot.toml support just no-ops everywhere it's
# used - callers fall back to their pre-existing marker/heuristic logic,
# so a toml-less environment still works exactly as before this feature.
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[import-not-found,no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


def reset_terminal() -> None:
    """Reset the terminal to a sane state after a Textual app exits or
    after a launched subprocess (which may have left raw mode, odd
    cursor state, etc. behind) returns control to the launcher."""
    try:
        if HAS_TERMIOS:
            os.system('stty sane 2>/dev/null')
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        else:
            # Windows: clear the terminal buffer if possible.
            os.system('cls 2>nul')
    except Exception:
        pass


def load_loot_toml(directory: Path) -> Dict[str, Any]:
    """Read `<directory>/loot.toml` and return it as a dict, or {} if the
    file doesn't exist, can't be parsed, or no toml backend is available.

    This never raises: a missing or broken loot.toml should mean "no
    metadata override", not "crash the launcher". Callers combine this
    with their own fallback (comment markers, README, docstring, etc.)
    for any key the file doesn't provide.
    """
    if tomllib is None:
        return {}
    path = Path(directory) / "loot.toml"
    if not path.is_file():
        return {}
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
