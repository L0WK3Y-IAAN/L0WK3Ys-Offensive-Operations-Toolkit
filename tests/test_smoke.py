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
    """Import a script by path without needing it to be a package.

    Running a script directly (`python main.py`) auto-prepends the
    script's own directory to sys.path, which is how main.py's bare
    `from loot_shared import ...` resolves. Loading it this way via
    importlib doesn't get that for free, so do it explicitly - whether
    this is needed depends on how pytest itself was invoked (`python -m
    pytest` prepends the cwd; a bare `pytest` doesn't), so don't rely on
    that either.
    """
    script_dir = str(path.resolve().parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
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


def test_every_script_module_has_a_parseable_loot_toml():
    """Every module folder under scripts/**  that has loot.toml should
    parse to a non-empty dict - catches a typo breaking the file
    silently (load_loot_toml swallows parse errors by design, so this
    is the one place that would otherwise go unnoticed)."""
    mret_main = REPO_ROOT / "Mobile-RE-Toolkit" / "main.py"
    mod = _load_module("loot_mret_main_toml", mret_main)

    toml_files = list(mod.SCRIPT_DIR.rglob("loot.toml"))
    assert len(toml_files) >= 1, "expected at least one scripts/**/loot.toml"
    for toml_path in toml_files:
        data = mod.load_loot_toml(toml_path.parent)
        assert data, f"{toml_path} parsed to an empty/invalid dict"
        assert isinstance(data.get("name"), str) and data["name"].strip(), (
            f"{toml_path} is missing a non-empty `name`"
        )


def test_mobsf_scan_shows_under_android_and_ios_without_duplicate_files():
    """Regression test for the MobSF Scan dedup: the script should
    resolve under Android, iOS, and Misc from the single canonical copy,
    declared via loot.toml rather than a physical copy in each folder."""
    mret_main = REPO_ROOT / "Mobile-RE-Toolkit" / "main.py"
    mod = _load_module("loot_mret_main_dedup", mret_main)

    for platform in ("Android", "iOS", "Misc"):
        matches = [s for s in mod.discover_scripts(platform, deduplicate=False) if s.name == "MobSF Scan"]
        assert len(matches) == 1, f"expected exactly one MobSF Scan entry under {platform}"
        assert sorted(matches[0].supported_platforms) == ["Android", "iOS"]

    # And it must not have leaked into folders it doesn't declare.
    android_names = {s.name for s in mod.discover_scripts("Android", deduplicate=False)}
    ios_names = {s.name for s in mod.discover_scripts("iOS", deduplicate=False)}
    assert "Open Directory" not in android_names
    assert "Open Directory" not in ios_names
