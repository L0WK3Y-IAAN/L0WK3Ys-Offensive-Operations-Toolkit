#!/usr/bin/env python3
# LOOT: category: Mobile
# LOOT: description: Mobile Reverse Engineering Toolkit for Android & iOS security analysis
"""
M.R.E.T - Mobile Reverse Engineering Toolkit
A modern TUI-based launcher for mobile security scripts.
Rewritten with Textual for enhanced user experience.
"""

from __future__ import annotations

import os
import sys
import re
import subprocess
import shutil
import shlex
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Header, Footer, Static, Button, Label, Input,
    DataTable, ListItem, ListView, Rule
)
from textual.binding import Binding
from textual.reactive import reactive
from textual.message import Message
from textual import on

# Resolve paths relative to this file
HERE = Path(__file__).resolve().parent
SCRIPT_DIR = (HERE / "scripts").resolve()
GITIGNORE_PATH = (HERE / ".gitignore").resolve()

BANNER = """
███╗   ███╗ ██████╗  ███████╗ ████████╗
████╗ ████║ ██╔══██╗ ██╔════╝ ╚══██╔══╝
██╔████╔██║ ██████╔╝ █████╗      ██║   
██║╚██╔╝██║ ██╔══██╗ ██╔══╝      ██║   
██║ ╚═╝ ██║ ██║  ██║ ███████╗    ██║   
╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚══════╝    ╚═╝   
"""

PLATFORMS = ["All", "Android", "iOS", "Misc"]
PLATFORM_ICONS = {"All": "🌐", "Android": "🤖", "iOS": "🍎", "Misc": "📁"}
BOLD_RE = re.compile(r"\*\*(.+?)\*\*", flags=re.DOTALL)
_MAX_WORKERS = min(32, (os.cpu_count() or 1) + 4)


@dataclass
class ScriptInfo:
    """Information about a discovered script."""
    path: Path
    name: str
    description: str
    platform: str
    requires_args: bool
    args_info: str = ""  # Documentation for arguments
    supported_platforms: Optional[List[str]] = None  # Platforms this script supports (for cross-platform scripts)
    
    def __post_init__(self):
        if self.supported_platforms is None:
            self.supported_platforms = [self.platform]
    
    @property
    def folder(self) -> Path:
        return self.path.parent
    
    @property
    def is_cross_platform(self) -> bool:
        """Check if this script supports multiple platforms."""
        return len(self.supported_platforms) > 1


def prettify_script_name(filename: str) -> str:
    """Convert filename to display name."""
    return filename.replace("_", " ").replace(".py", "").title()


def find_readme(folder: Path) -> Path | None:
    """Find README file in a folder."""
    for name in ("README.md", "Readme.md", "readme.md", "README", "Readme", "readme"):
        p = folder / name
        if p.is_file():
            return p
    cand = sorted(
        list(folder.glob("README*.md"))
        + list(folder.glob("readme*.md"))
        + list(folder.glob("Readme*.md"))
    )
    return cand[0] if cand else None


def get_description_from_readme(folder_path: Path) -> str:
    """Extract description from README's first bold segment."""
    readme = find_readme(folder_path)
    if not readme:
        return "No description available"
    try:
        content = readme.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return "No description available"
    m = BOLD_RE.search(content)
    if not m:
        return "No description available"
    desc = m.group(1).strip()
    desc = re.sub(r"`([^`]+)`", r"\1", desc)
    desc = " ".join(desc.split())
    return desc or "No description available"


def get_script_args_info(script_path: Path) -> str:
    """Extract argument documentation from script using MRET marker.
    
    Looks for: # MRET: args_info: <description>
    """
    try:
        if not script_path.exists():
            return ""
        
        content = script_path.read_text(encoding="utf-8", errors="ignore")
        
        # Look for args_info marker
        match = re.search(r"#\s*MRET:\s*args_info:\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        return ""
    except Exception:
        return ""


def get_script_platforms(script_path: Path, default_platform: str) -> List[str]:
    """Extract supported platforms from script using MRET marker.
    
    Looks for: # MRET: platforms: Android, iOS
    Returns list of platforms, or [default_platform] if not specified.
    """
    try:
        if not script_path.exists():
            return [default_platform]
        
        content = script_path.read_text(encoding="utf-8", errors="ignore")
        
        # Look for platforms marker
        match = re.search(r"#\s*MRET:\s*platforms:\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if match:
            platforms_str = match.group(1).strip()
            # Parse comma-separated platforms
            platforms = [p.strip() for p in platforms_str.split(",")]
            # Validate platforms
            valid = [p for p in platforms if p in ["Android", "iOS", "Misc"]]
            return valid if valid else [default_platform]
        
        return [default_platform]
    except Exception:
        return [default_platform]


def check_script_requires_args(script_path: Path, visited: Optional[set] = None) -> bool:
    """Check if a script requires command-line arguments.
    
    Detection methods (in priority order):
    1. # MRET: no_args      -> Force OFF (no args indicator)
    2. # MRET: requires_args -> Force ON (show args indicator)
    3. Auto-detection of argparse, typer, click, sys.argv usage
    """
    if visited is None:
        visited = set()
    
    script_str = str(script_path)
    if script_str in visited:
        return False
    visited.add(script_str)
    
    try:
        if not script_path.exists():
            return False
        
        content = script_path.read_text(encoding="utf-8", errors="ignore")
        
        # Check for explicit "no args" marker (highest priority - overrides everything)
        if re.search(r"#\s*MRET:\s*no_args", content, re.IGNORECASE):
            return False
        
        # Check for explicit "requires args" marker
        if re.search(r"#\s*MRET:\s*requires_args", content, re.IGNORECASE):
            return True
        
        # Auto-detect common argument parsing patterns
        patterns = [
            r"argparse\.ArgumentParser",
            r"typer\.Typer",
            r"@click\.",
            r"sys\.argv\[",
            r"ArgumentParser\(\)",
            r"add_argument",
            r"@app\.command",
            r"typer\.Option",
            r"typer\.Argument",
        ]
        
        for pattern in patterns:
            if re.search(pattern, content):
                return True
        
        return False
    except Exception:
        return False


def _is_main_script(file_path: Path, base_dir: Path) -> bool:
    """Check if a Python file is a main entry point script."""
    filename = file_path.name
    
    if filename == "__init__.py":
        return False
    
    try:
        rel_path = file_path.relative_to(base_dir)
        path_parts = rel_path.parts
    except ValueError:
        path_parts = file_path.parts
    
    skip_dirs = ["geiger", "utils", "core", "detectors", "analyzers", 
                 "reporters", "scanners", "__pycache__"]
    
    if len(path_parts) > 2:
        for part in path_parts[:-2]:
            if part in skip_dirs:
                return False
    
    if len(path_parts) >= 2:
        parent_dir = path_parts[-2]
        if parent_dir in skip_dirs:
            return False
    
    skip_module_names = ["config.py", "utils.py", "core.py"]
    if filename in skip_module_names:
        return False
    
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        has_main = (
            'if __name__ == "__main__"' in content or
            "if __name__ == '__main__'" in content or
            'typer.Typer' in content or
            'argparse.ArgumentParser' in content or
            '@click.command' in content
        )
        return has_main
    except Exception:
        return len(path_parts) <= 2


def discover_scripts(platform: str = "All", deduplicate: bool = True) -> List[ScriptInfo]:
    """Discover all scripts for a platform.
    
    Args:
        platform: Filter by platform ("All", "Android", "iOS", "Misc")
        deduplicate: If True and platform is "All", removes duplicate scripts
                     that exist in multiple platform folders (shows only once)
    """
    scripts: List[ScriptInfo] = []
    
    if platform == "All":
        platforms_to_scan = ["Android", "iOS", "Misc"]
    else:
        platforms_to_scan = [platform]
    
    def scan_platform(plat: str) -> List[ScriptInfo]:
        base_dir = SCRIPT_DIR / plat
        results = []
        if not base_dir.is_dir():
            return results
        
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root) / file
                    if _is_main_script(file_path, base_dir):
                        name = prettify_script_name(file)
                        desc = get_description_from_readme(file_path.parent)
                        requires_args = check_script_requires_args(file_path)
                        args_info = get_script_args_info(file_path) if requires_args else ""
                        supported_platforms = get_script_platforms(file_path, plat)
                        results.append(ScriptInfo(
                            path=file_path,
                            name=name,
                            description=desc,
                            platform=plat,
                            requires_args=requires_args,
                            args_info=args_info,
                            supported_platforms=supported_platforms
                        ))
        return results

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {executor.submit(scan_platform, p): p for p in platforms_to_scan}
        for future in as_completed(futures):
            try:
                scripts.extend(future.result())
            except Exception:
                pass

    # Deduplicate cross-platform scripts when showing "All"
    if platform == "All" and deduplicate:
        seen_names: Dict[str, ScriptInfo] = {}
        for script in scripts:
            name_lower = script.name.lower()
            if name_lower not in seen_names:
                seen_names[name_lower] = script
            else:
                # Prefer the script with more platform support, or keep existing
                existing = seen_names[name_lower]
                # Merge supported platforms
                all_platforms = list(set(existing.supported_platforms + script.supported_platforms))
                existing.supported_platforms = all_platforms
                # If this script is from Misc, prefer it (it's the "canonical" location)
                if script.platform == "Misc":
                    script.supported_platforms = all_platforms
                    seen_names[name_lower] = script
        scripts = list(seen_names.values())

    scripts.sort(key=lambda s: (s.platform, s.name.lower()))
    return scripts


def scan_wip_and_update_gitignore() -> int:
    """Scan for WIP scripts and update .gitignore. Returns count of WIP dirs found."""
    wip_dirs = set()
    if not SCRIPT_DIR.is_dir():
        return 0
    
    for plat in ["Android", "iOS", "Misc"]:
        plat_dir = SCRIPT_DIR / plat
        if not plat_dir.is_dir():
            continue
        for root, _, files in os.walk(plat_dir):
            for file in files:
                if "WIP" in file and file.endswith(".py"):
                    rel_path = os.path.relpath(root, HERE)
                    wip_dirs.add(rel_path)
    
    if wip_dirs:
        if not GITIGNORE_PATH.exists():
            GITIGNORE_PATH.write_text("# Git Ignore File\n", encoding="utf-8")
        existing = set(GITIGNORE_PATH.read_text(encoding="utf-8").splitlines())
        new_entries = [d for d in wip_dirs if d not in existing]
        if new_entries:
            with GITIGNORE_PATH.open("a", encoding="utf-8") as f:
                f.write("\n# Auto-added WIP script directories\n")
                f.write("\n".join(new_entries) + "\n")
    
    return len(wip_dirs)


def organize_scripts():
    """Organize loose scripts into folders."""
    SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    for filename in os.listdir(SCRIPT_DIR):
        file_path = SCRIPT_DIR / filename
        if filename.endswith(".py") and file_path.is_file():
            script_name = prettify_script_name(filename)
            dest_folder = SCRIPT_DIR / script_name
            dest_path = dest_folder / filename
            dest_folder.mkdir(parents=True, exist_ok=True)
            if file_path.resolve() != dest_path.resolve():
                shutil.move(str(file_path), str(dest_path))


# ============================================================================
# Textual Widgets
# ============================================================================

class PlatformSidebar(Vertical):
    """Sidebar for platform selection."""
    
    DEFAULT_CSS = """
    PlatformSidebar {
        width: 18;
        background: #1a0a1a;
        border-right: solid #9932cc;
        padding: 1;
    }
    
    PlatformSidebar Button {
        width: 100%;
        margin: 0 0 1 0;
        background: #2a1a2a;
        color: #e0b0ff;
        border: tall #6a2c6a;
    }
    
    PlatformSidebar Button:hover {
        background: #4a2a4a;
    }
    
    PlatformSidebar Button.selected {
        background: #9932cc;
        color: #ffffff;
        text-style: bold;
    }
    
    PlatformSidebar #sidebar-title {
        text-align: center;
        text-style: bold;
        color: #e0b0ff;
        padding: 0 0 1 0;
    }
    """
    
    class PlatformSelected(Message):
        """Message sent when platform is selected."""
        def __init__(self, platform: str) -> None:
            self.platform = platform
            super().__init__()
    
    def compose(self) -> ComposeResult:
        yield Static("Platforms", id="sidebar-title")
        for plat in PLATFORMS:
            icon = PLATFORM_ICONS.get(plat, "📁")
            btn = Button(f"{icon} {plat}", id=f"plat-{plat}", classes="selected" if plat == "All" else "")
            yield btn
    
    def select_platform(self, platform: str) -> None:
        """Update selection state."""
        for plat in PLATFORMS:
            btn = self.query_one(f"#plat-{plat}", Button)
            if plat == platform:
                btn.add_class("selected")
            else:
                btn.remove_class("selected")
    
    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        plat = event.button.id.replace("plat-", "") if event.button.id else ""
        if plat in PLATFORMS:
            self.select_platform(plat)
            self.post_message(self.PlatformSelected(plat))


class ScriptDetails(Vertical):
    """Panel showing details of selected script."""
    
    DEFAULT_CSS = """
    ScriptDetails {
        height: auto;
        max-height: 12;
        background: #1a0a1a;
        border-top: solid #9932cc;
        padding: 1 2;
    }
    
    ScriptDetails #detail-title {
        text-style: bold;
        color: #da70d6;
    }
    
    ScriptDetails #detail-desc {
        color: #e0b0ff;
        padding: 1 0;
    }
    
    ScriptDetails #detail-path {
        color: #9370db;
    }
    
    ScriptDetails #detail-args {
        color: #ffd700;
    }
    """
    
    def compose(self) -> ComposeResult:
        yield Static("Select a script to view details", id="detail-title")
        yield Static("", id="detail-desc")
        yield Static("", id="detail-path")
        yield Static("", id="detail-args")
    
    def update_details(self, script: ScriptInfo | None) -> None:
        """Update the details panel."""
        if script is None:
            self.query_one("#detail-title", Static).update("Select a script to view details")
            self.query_one("#detail-desc", Static).update("")
            self.query_one("#detail-path", Static).update("")
            self.query_one("#detail-args", Static).update("")
        else:
            # Show cross-platform indicator in title if applicable
            if script.is_cross_platform:
                platforms_str = ", ".join(script.supported_platforms)
                title = f"📋 {script.name} [🔄 {platforms_str}]"
            else:
                title = f"📋 {script.name}"
            
            self.query_one("#detail-title", Static).update(title)
            self.query_one("#detail-desc", Static).update(script.description)
            self.query_one("#detail-path", Static).update(f"📁 {script.path.parent.relative_to(HERE)}")
            if script.requires_args:
                if script.args_info:
                    # Convert | separator to newlines for multi-line display
                    args_display = script.args_info.replace(" | ", "\n   • ").replace("|", "\n   • ")
                    self.query_one("#detail-args", Static).update(f"⚙️  Args:\n   • {args_display}")
                else:
                    self.query_one("#detail-args", Static).update("⚙️  This script accepts command-line arguments")
            else:
                self.query_one("#detail-args", Static).update("")


class FileImportInput(Vertical):
    """Input widget for importing files via drag-and-drop."""
    
    DEFAULT_CSS = """
    FileImportInput {
        display: none;
        height: auto;
        padding: 1 2;
        background: #1a2a1a;
        border: tall #32cd32;
        margin: 1 2;
    }
    
    FileImportInput.visible {
        display: block;
    }
    
    FileImportInput #import-title {
        color: #90ee90;
        text-style: bold;
        padding: 0 0 1 0;
    }
    
    FileImportInput #import-hint {
        color: #6b8e6b;
        padding: 0 0 1 0;
    }
    
    FileImportInput Input {
        margin: 0 0 1 0;
        border: tall #32cd32;
        background: #0a150a;
    }
    
    FileImportInput Input:focus {
        border: tall #90ee90;
    }
    
    FileImportInput #import-status {
        color: #6b8e6b;
    }
    """
    
    class FileImported(Message):
        """Message sent when file is successfully imported."""
        def __init__(self, source: Path, destination: Path) -> None:
            self.source = source
            self.destination = destination
            super().__init__()
    
    def compose(self) -> ComposeResult:
        yield Static("📥 Import File", id="import-title")
        yield Static("Drag & drop a file here or paste the path:", id="import-hint")
        yield Input(placeholder="/path/to/file.apk", id="import-path-input")
        yield Static("[Enter] Import  [Esc] Cancel", id="import-status")
    
    def show(self) -> None:
        self.add_class("visible")
        self.query_one("#import-path-input", Input).focus()
    
    def hide(self) -> None:
        self.remove_class("visible")
        self.query_one("#import-path-input", Input).value = ""
    
    def get_path(self) -> str:
        return self.query_one("#import-path-input", Input).value.strip()


class ArgumentInput(Vertical):
    """Input for script arguments."""
    
    DEFAULT_CSS = """
    ArgumentInput {
        height: auto;
        padding: 0 2;
        display: none;
        background: #2a1a2a;
    }
    
    ArgumentInput.visible {
        display: block;
    }
    
    ArgumentInput #args-label {
        color: #9370db;
        padding: 0 0 0 0;
    }
    
    ArgumentInput Input {
        margin: 0 0 1 0;
        border: tall #9932cc;
        background: #1a0a1a;
    }
    
    ArgumentInput Input:focus {
        border: tall #da70d6;
    }
    """
    
    def compose(self) -> ComposeResult:
        yield Static("Arguments (optional):", id="args-label")
        yield Input(placeholder="e.g., --package com.example.app", id="args-input")
    
    def show(self) -> None:
        self.add_class("visible")
        self.query_one("#args-input", Input).focus()
    
    def hide(self) -> None:
        self.remove_class("visible")
        self.query_one("#args-input", Input).value = ""
    
    def get_args(self) -> List[str]:
        val = self.query_one("#args-input", Input).value.strip()
        if not val:
            return []
        try:
            return shlex.split(val)
        except ValueError:
            return val.split()


# ============================================================================
# Main Application
# ============================================================================

class MRETApp(App):
    """Mobile Reverse Engineering Toolkit - Main Application."""
    
    CSS = """
    Screen {
        background: #0a0510;
    }
    
    Header {
        background: #4b0082;
        color: #ffffff;
    }
    
    Footer {
        background: #2a0a2a;
        color: #e0b0ff;
    }
    
    #main-container {
        height: 100%;
    }
    
    #header-banner {
        height: auto;
        padding: 1 2;
        background: #1a0a1a;
        color: #e0b0ff;
        width: 100%;
        align: center top;
    }
    
    #banner-text {
        color: #da70d6;
        text-style: bold;
        text-align: center;
        width: 100%;
    }
    
    #banner-subtitle {
        color: #9370db;
        text-align: center;
        width: 100%;
    }
    
    #content-area {
        height: 1fr;
    }
    
    #scripts-panel {
        width: 1fr;
        background: #0a0510;
    }
    
    #search-container {
        height: auto;
        padding: 1 2;
        background: #1a0a1a;
    }
    
    #search-input {
        width: 100%;
        border: tall #9932cc;
        background: #0a0510;
    }
    
    #search-input:focus {
        border: tall #da70d6;
    }
    
    #scripts-table-container {
        height: 1fr;
        padding: 0 1;
        background: #0a0510;
    }
    
    DataTable {
        height: 100%;
        background: #0a0510;
    }
    
    DataTable > .datatable--header {
        background: #4b0082;
        color: #ffffff;
        text-style: bold;
    }
    
    DataTable > .datatable--cursor {
        background: #9932cc;
        color: #ffffff;
    }
    
    DataTable > .datatable--hover {
        background: #3a1a3a;
    }
    
    #status-line {
        height: auto;
        padding: 0 2;
        background: #2a0a2a;
        color: #9370db;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "cancel_input", "Cancel", show=False),
        Binding("/", "focus_search", "Search"),
        Binding("enter", "run_script", "Run"),
        Binding("r", "refresh", "Refresh"),
        Binding("i", "import_file", "Import"),
        Binding("1", "select_platform('All')", "All", show=False),
        Binding("2", "select_platform('Android')", "Android", show=False),
        Binding("3", "select_platform('iOS')", "iOS", show=False),
        Binding("4", "select_platform('Misc')", "Misc", show=False),
    ]
    
    current_platform: reactive[str] = reactive("All")
    scripts: reactive[List[ScriptInfo]] = reactive([])
    filtered_scripts: reactive[List[ScriptInfo]] = reactive([])
    selected_script: reactive[ScriptInfo | None] = reactive(None)
    
    def __init__(self):
        super().__init__()
        self._script_to_run: ScriptInfo | None = None
        self._script_args: List[str] = []
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Vertical(id="main-container"):
            # Banner
            with Vertical(id="header-banner"):
                yield Static(BANNER, id="banner-text")
                yield Static("Mobile Reverse Engineering Toolkit", id="banner-subtitle")
            
            # Main content
            with Horizontal(id="content-area"):
                yield PlatformSidebar()
                
                with Vertical(id="scripts-panel"):
                    # Search
                    with Container(id="search-container"):
                        yield Input(placeholder="🔍 Type to filter scripts...", id="search-input")
                    
                    # Scripts table
                    with VerticalScroll(id="scripts-table-container"):
                        yield DataTable(id="scripts-table", cursor_type="row")
                    
                    # Argument input (hidden by default)
                    yield ArgumentInput(id="arg-input")
                    
                    # File import input (hidden by default)
                    yield FileImportInput(id="file-import")
                    
                    # Details panel
                    yield ScriptDetails(id="script-details")
            
            # Status line
            yield Static("Ready", id="status-line")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the app."""
        # Setup table
        table = self.query_one("#scripts-table", DataTable)
        table.add_column("#", width=4)
        table.add_column("Name", width=30)
        table.add_column("Platform", width=10)
        table.add_column("Description")
        table.add_column("Requires Args", width=14)
        table.cursor_type = "row"

        # Initialize
        organize_scripts()
        wip_count = scan_wip_and_update_gitignore()
        if wip_count > 0:
            self.notify(f"Added {wip_count} WIP directories to .gitignore", title="WIP Scan")

        # Load scripts
        self.load_scripts()
    
    def load_scripts(self) -> None:
        """Load scripts for current platform."""
        self.scripts = discover_scripts(self.current_platform)
        self.filtered_scripts = self.scripts.copy()
        self.update_table()
        self.update_status()
    
    def update_table(self) -> None:
        """Update the DataTable with filtered scripts."""
        table = self.query_one("#scripts-table", DataTable)
        table.clear()
        
        for idx, script in enumerate(self.filtered_scripts, 1):
            # Center the gear icon in the column
            args_indicator = "     ⚙️" if script.requires_args else ""
            # Truncate description to fit
            desc = script.description[:60] + "..." if len(script.description) > 60 else script.description
            
            # Show platform with cross-platform indicator
            if script.is_cross_platform and self.current_platform == "All":
                # Show all supported platforms
                platform_display = "🔄 Multi"
            else:
                platform_display = script.platform
            
            table.add_row(
                str(idx),
                script.name,
                platform_display,
                desc,
                args_indicator,
                key=str(script.path)
            )
    
    def update_status(self) -> None:
        """Update the status line."""
        total = len(self.scripts)
        filtered = len(self.filtered_scripts)
        status = f"📊 {filtered}/{total} scripts"
        if self.current_platform != "All":
            status += f" | Platform: {PLATFORM_ICONS.get(self.current_platform, '')} {self.current_platform}"
        self.query_one("#status-line", Static).update(status)
    
    def watch_current_platform(self, platform: str) -> None:
        """React to platform change."""
        self.load_scripts()
        # Clear search
        search = self.query_one("#search-input", Input)
        search.value = ""
    
    @on(PlatformSidebar.PlatformSelected)
    def on_platform_selected(self, event: PlatformSidebar.PlatformSelected) -> None:
        """Handle platform selection from sidebar."""
        self.current_platform = event.platform
    
    @on(Input.Changed, "#search-input")
    def on_search_changed(self, event: Input.Changed) -> None:
        """Filter scripts based on search input."""
        query = event.value.lower().strip()
        
        if not query:
            self.filtered_scripts = self.scripts.copy()
        else:
            self.filtered_scripts = [
                s for s in self.scripts
                if query in s.name.lower() or query in s.description.lower()
            ]
        
        self.update_table()
        self.update_status()
    
    @on(DataTable.RowHighlighted)
    def on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Update details when row is highlighted."""
        if event.row_key and event.row_key.value:
            path = Path(event.row_key.value)
            for script in self.filtered_scripts:
                if script.path == path:
                    self.selected_script = script
                    self.query_one("#script-details", ScriptDetails).update_details(script)
                    break
        else:
            self.selected_script = None
            self.query_one("#script-details", ScriptDetails).update_details(None)
    
    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection (Enter key or double-click)."""
        if self.selected_script:
            if self.selected_script.requires_args:
                # Show argument input
                arg_input = self.query_one("#arg-input", ArgumentInput)
                arg_input.show()
            else:
                # Run directly
                self._run_selected_script()
    
    @on(Input.Submitted, "#args-input")
    def on_args_submitted(self, event: Input.Submitted) -> None:
        """Run script with arguments."""
        if self.selected_script:
            arg_input = self.query_one("#arg-input", ArgumentInput)
            self._script_args = arg_input.get_args()
            arg_input.hide()
            self._run_selected_script()
    
    def _run_selected_script(self) -> None:
        """Prepare to run the selected script."""
        if self.selected_script:
            self._script_to_run = self.selected_script
            self.exit(self._script_to_run)
    
    def action_focus_search(self) -> None:
        """Focus the search input."""
        self.query_one("#search-input", Input).focus()
    
    def action_run_script(self) -> None:
        """Run the currently selected script."""
        table = self.query_one("#scripts-table", DataTable)
        if table.row_count > 0 and self.selected_script:
            if self.selected_script.requires_args:
                arg_input = self.query_one("#arg-input", ArgumentInput)
                arg_input.show()
            else:
                self._run_selected_script()
    
    def action_refresh(self) -> None:
        """Refresh the script list."""
        self.load_scripts()
        self.notify("Scripts refreshed!", title="Refresh")
    
    def action_select_platform(self, platform: str) -> None:
        """Select platform via keyboard shortcut."""
        if platform in PLATFORMS:
            self.current_platform = platform
            sidebar = self.query_one(PlatformSidebar)
            sidebar.select_platform(platform)
    
    def action_import_file(self) -> None:
        """Show the file import input."""
        file_import = self.query_one("#file-import", FileImportInput)
        file_import.show()
    
    def action_cancel_input(self) -> None:
        """Cancel any active input and hide it, or quit if nothing is active."""
        file_import = self.query_one("#file-import", FileImportInput)
        arg_input = self.query_one("#arg-input", ArgumentInput)
        
        if file_import.has_class("visible"):
            file_import.hide()
        elif arg_input.has_class("visible"):
            arg_input.hide()
        else:
            self.exit(None)
    
    @on(Input.Submitted, "#import-path-input")
    def on_import_path_submitted(self, event: Input.Submitted) -> None:
        """Handle file import submission."""
        file_import = self.query_one("#file-import", FileImportInput)
        path_str = file_import.get_path()
        
        if not path_str:
            file_import.hide()
            return

        # Clean path (remove quotes that might be added by drag-drop)
        path_str = path_str.strip().strip('"').strip("'")
        
        # Handle escaped spaces (from terminal drag-drop)
        path_str = path_str.replace("\\ ", " ")
        
        source_path = Path(path_str).expanduser().resolve()
        
        if not source_path.exists():
            self.notify(f"File not found: {path_str}", title="Import Error", severity="error")
            return
        
        if not source_path.is_file():
            self.notify("Please select a file, not a directory", title="Import Error", severity="error")
            return
        
        # Determine destination based on file type
        dest_dir = self._get_import_destination(source_path)
        dest_path = dest_dir / source_path.name
        
        # Handle duplicate names
        if dest_path.exists():
            base = source_path.stem
            ext = source_path.suffix
            counter = 1
            while dest_path.exists():
                dest_path = dest_dir / f"{base}_{counter}{ext}"
                counter += 1
        
        try:
            # Create destination directory if needed
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy the file
            shutil.copy2(source_path, dest_path)
            
            file_import.hide()
            self.notify(
                f"Imported: {source_path.name}\n→ {dest_path.relative_to(HERE)}",
                title="✅ Import Successful",
                timeout=5
            )
            
            # Refresh if we might have added something scannable
            if source_path.suffix.lower() == ".py":
                self.load_scripts()
                
        except PermissionError:
            self.notify("Permission denied", title="Import Error", severity="error")
        except Exception as e:
            self.notify(f"Import failed: {e}", title="Import Error", severity="error")
    
    def _get_import_destination(self, source_path: Path) -> Path:
        """Determine the appropriate destination folder based on file type."""
        suffix = source_path.suffix.lower()
        
        # APK files go to src/pulled_apks (or src/output/pulled_apks)
        if suffix == ".apk":
            apk_dir = HERE / "src" / "output" / "pulled_apks"
            if not apk_dir.exists():
                apk_dir = HERE / "src" / "pulled_apks"
            apk_dir.mkdir(parents=True, exist_ok=True)
            return apk_dir
        
        # IPA files (iOS) go to src/ipa
        if suffix == ".ipa":
            ipa_dir = HERE / "src" / "ipa"
            ipa_dir.mkdir(parents=True, exist_ok=True)
            return ipa_dir
        
        # Android backup files go to src/backups
        if suffix == ".ab":
            backup_dir = HERE / "src" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            return backup_dir
        
        # DEX files go to src/dex
        if suffix == ".dex":
            dex_dir = HERE / "src" / "dex"
            dex_dir.mkdir(parents=True, exist_ok=True)
            return dex_dir
        
        # Frida scripts go to the Frida Script Downloader folder
        if suffix == ".js":
            frida_dir = SCRIPT_DIR / "Android" / "Frida Script Downloader" / "scripts"
            if frida_dir.exists():
                return frida_dir
        
        # Default: src folder
        src_dir = HERE / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        return src_dir
    
    def action_quit(self) -> None:
        """Quit the application."""
        self.exit(None)


def run_script(script: ScriptInfo, args: List[str]) -> int:
    """Run a script and return exit code."""
    print(f"\n{'='*60}")
    print(f"🚀 Running: {script.name}")
    print(f"📁 Path: {script.path}")
    if args:
        print(f"📝 Arguments: {' '.join(args)}")
    print(f"{'='*60}\n")
    
    # Change to script directory
    os.chdir(script.path.parent)
    
    try:
        result = subprocess.run(
            [sys.executable, str(script.path)] + args,
            check=False
        )
        return result.returncode
    except KeyboardInterrupt:
        print("\n⚠️  Script interrupted by user.")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1


def reset_terminal():
    """Reset terminal to sane state."""
    try:
        os.system('stty sane 2>/dev/null')
    except Exception:
        pass


def main():
    """Main entry point."""
    while True:
        os.chdir(HERE)
        
        app = MRETApp()
        selected = app.run()
        
        reset_terminal()
        
        if selected is None:
            print("\n👋 Goodbye!\n")
            break
        
        # Get args if any were entered
        args = app._script_args if hasattr(app, '_script_args') else []
        
        # Run the script
        exit_code = run_script(selected, args)
        
        reset_terminal()
        
        print(f"\n{'='*60}")
        if exit_code == 0:
            print("✅ Script completed successfully.")
        elif exit_code == 2:
            print("✅ Script completed (with findings).")
        else:
            print(f"⚠️  Script exited with code: {exit_code}")
        print(f"{'='*60}")
        
        try:
            input("\nPress Enter to return to MRET...")
        except (KeyboardInterrupt, EOFError):
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        import sys
        print("\n👋 Cancelled by user")
        sys.exit(0)
