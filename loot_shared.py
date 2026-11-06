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

try:
    import termios
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False


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
