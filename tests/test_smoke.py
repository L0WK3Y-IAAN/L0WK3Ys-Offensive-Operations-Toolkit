"""Headless smoke tests for the LOOT launchers.

These don't assert much about behavior - they just boot each Textual
app (via Textual's own `run_test()` headless harness) far enough to
catch import-time and on_mount-time breakage: a bad import, a typo in
a binding, a CSS parse error, an exception in startup scanning. That's
the failure mode a "looks fine until you launch it" refactor produces,
and it's cheap to catch here instead of by hand.
"""

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path):
    """Import a script by path without needing it to be a package."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _boot(app) -> None:
    """Mount `app` headlessly and let one event loop tick pass."""

    async def _run():
        async with app.run_test() as pilot:
            await pilot.pause()

    asyncio.run(_run())


def test_root_launcher_boots():
    mod = _load_module("loot_root_main", REPO_ROOT / "main.py")
    _boot(mod.ToolkitLauncher())


def test_mret_launcher_boots():
    mret_main = REPO_ROOT / "Mobile-RE-Toolkit" / "main.py"
    if not mret_main.exists():
        pytest.skip("Mobile-RE-Toolkit/main.py not present")
    mod = _load_module("loot_mret_main", mret_main)
    _boot(mod.MRETApp())


def test_check_system_binaries_returns_sorted_found_and_missing():
    """check_system_binaries() should never raise, and should partition
    every tracked binary into exactly one of the two lists."""
    mret_main = REPO_ROOT / "Mobile-RE-Toolkit" / "main.py"
    mod = _load_module("loot_mret_main_binaries", mret_main)

    found, missing = mod.check_system_binaries()
    assert sorted(found) == found
    assert sorted(missing) == missing
    assert set(found) | set(missing) == set(mod.REQUIRED_BINARIES)
    assert set(found) & set(missing) == set()
