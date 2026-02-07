#!/usr/bin/env python3
"""
L0WK3Y's Offensive Operations Toolkit - Main Launcher
A TUI-based launcher for all toolkit modules.
"""

import os
import sys
import subprocess
from pathlib import Path
from dataclasses import dataclass

# Unix-only imports (for terminal control)
try:
    import tty
    import termios
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Static, Button, Label
from textual.binding import Binding

# ASCII Banner for LOOT
LOOT_BANNER = """
██╗      ██████╗  ██████╗ ████████╗
██║     ██╔═══██╗██╔═══██╗╚══██╔══╝
██║     ██║   ██║██║   ██║   ██║   
██║     ██║   ██║██║   ██║   ██║   
███████╗╚██████╔╝╚██████╔╝   ██║   
╚══════╝ ╚═════╝  ╚═════╝    ╚═╝   
"""

# Category definitions
CATEGORIES = ["All", "Mobile", "Web", "Network", "AI"]

# Category detection patterns (folder name contains these patterns)
CATEGORY_PATTERNS = {
    "Mobile": ["mobile", "android", "ios", "apk", "ipa", "frida"],
    "Web": ["web", "http", "api", "burp", "proxy", "xss", "sql"],
    "Network": ["network", "net", "scan", "nmap", "wifi", "packet", "tcp", "udp"],
    "AI": ["ai", "ml", "llm", "gpt", "model", "neural", "machine"],
}


@dataclass
class ToolkitInfo:
    """Information about a toolkit module."""
    name: str
    path: Path
    category: str
    description: str = ""


def reset_terminal():
    """Reset terminal to sane state."""
    try:
        if HAS_TERMIOS:
            os.system('stty sane 2>/dev/null')
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        else:
            # Windows: Clear terminal buffer if possible
            os.system('cls 2>nul')
    except Exception:
        pass


def check_for_updates(repo_root: Path) -> tuple[bool, str]:
    """
    Check if the repo has updates on GitHub (current branch vs origin).
    Returns (update_available, message).
    """
    git_dir = repo_root / ".git"
    if not git_dir.exists():
        return False, "Not a git repository (no .git)"
    try:
        # Get current branch
        r = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return False, "Could not determine current branch"
        branch = r.stdout.strip() or "main"
        remote_ref = f"origin/{branch}"
        # Fetch from origin (quiet)
        subprocess.run(
            ["git", "fetch", "origin", "--quiet"],
            cwd=repo_root,
            capture_output=True,
            timeout=30,
        )
        # Count commits we're behind origin
        r2 = subprocess.run(
            ["git", "rev-list", "--count", f"HEAD..{remote_ref}"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r2.returncode != 0:
            return False, f"Could not compare with {remote_ref}"
        behind = int(r2.stdout.strip() or "0")
        if behind > 0:
            return True, f"{behind} new commit(s) on origin/{branch}. Press U to update."
        return False, "Already up to date."
    except subprocess.TimeoutExpired:
        return False, "Update check timed out."
    except FileNotFoundError:
        return False, "Git not installed."
    except Exception as e:
        return False, str(e)


def pull_updates(repo_root: Path) -> tuple[bool, str]:
    """Pull latest changes from origin. Returns (success, message)."""
    git_dir = repo_root / ".git"
    if not git_dir.exists():
        return False, "Not a git repository"
    try:
        r_branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        branch = (r_branch.stdout or "").strip() or "main"
        r = subprocess.run(
            ["git", "pull", "origin", branch, "--no-edit"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if r.returncode == 0:
            out = (r.stdout or "").strip()
            return True, out or "Pulled successfully. Restart LOOT to use the new version."
        err = (r.stderr or r.stdout or "").strip()
        return False, err or "Pull failed."
    except subprocess.TimeoutExpired:
        return False, "Pull timed out."
    except FileNotFoundError:
        return False, "Git not installed."
    except Exception as e:
        return False, str(e)


def detect_category(folder_name: str, main_py_path: Path) -> str:
    """Detect the category of a toolkit based on markers or folder name."""
    # First, check for explicit marker in main.py
    try:
        content = main_py_path.read_text(encoding='utf-8', errors='ignore')
        for line in content.split('\n')[:30]:  # Check first 30 lines
            if '# LOOT: category:' in line:
                cat = line.split('# LOOT: category:')[1].strip()
                if cat in CATEGORIES:
                    return cat
    except Exception:
        pass
    
    # Fall back to pattern matching on folder name
    folder_lower = folder_name.lower()
    for category, patterns in CATEGORY_PATTERNS.items():
        for pattern in patterns:
            if pattern in folder_lower:
                return category
    
    return "Misc"


def get_toolkit_description(main_py_path: Path) -> str:
    """Get description from toolkit's main.py docstring or marker."""
    try:
        content = main_py_path.read_text(encoding='utf-8', errors='ignore')
        
        # Check for LOOT: description marker
        for line in content.split('\n')[:30]:
            if '# LOOT: description:' in line:
                return line.split('# LOOT: description:')[1].strip()
        
        # Try to extract from docstring
        lines = content.split('\n')
        in_docstring = False
        for line in lines[:20]:
            if '"""' in line or "'''" in line:
                if in_docstring:
                    break
                in_docstring = True
                # Check if description is on same line
                parts = line.split('"""') if '"""' in line else line.split("'''")
                if len(parts) > 1 and parts[1].strip():
                    return parts[1].strip()[:80]
            elif in_docstring:
                stripped = line.strip()
                if stripped:
                    return stripped[:80]
    except Exception:
        pass
    
    return ""


def find_requirements_file(module_path: Path) -> Path | None:
    """Find the requirements.txt file for a module, searching up the tree."""
    current = module_path.parent
    repo_root = Path(__file__).parent.resolve()
    
    while current >= repo_root:
        req_file = current / "requirements.txt"
        if req_file.exists():
            return req_file
        current = current.parent
    
    return None


def check_and_install_deps(module_path: Path) -> bool:
    """Check if dependencies are installed, offer to install if not."""
    req_file = find_requirements_file(module_path)
    
    if not req_file:
        return True
    
    print(f"📋 Found requirements: {req_file}")
    print("🔍 Checking dependencies...")
    
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req_file), "--dry-run", "-q"],
        capture_output=True,
        text=True
    )
    
    if "Would install" in result.stdout or result.returncode != 0:
        print("\n⚠️  Some dependencies are missing or need updating.")
        print(f"   Requirements file: {req_file}\n")
        
        try:
            answer = input("📦 Install dependencies now? [Y/n]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return False
        
        if answer in ('', 'y', 'yes'):
            print("\n📥 Installing dependencies...\n")
            install_result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
                check=False
            )
            
            if install_result.returncode == 0:
                print("\n✅ Dependencies installed successfully!\n")
                return True
            else:
                print("\n❌ Failed to install dependencies.")
                print("   Try running manually: pip install -r", str(req_file))
                return False
        else:
            print("\n⏭️  Skipping dependency installation. Module may fail.\n")
            return True
    
    print("✅ All dependencies are installed.\n")
    return True


def run_toolkit(path: Path) -> bool:
    """Run the selected toolkit module."""
    reset_terminal()
    
    print(f"\n{'='*60}")
    print(f"🚀 Launching: {path.parent.name}")
    print(f"📁 Path: {path}")
    print(f"{'='*60}\n")
    
    if not check_and_install_deps(path):
        print("\n❌ Dependency installation cancelled or failed.")
        try:
            print("\n Returning to the launcher...")
        except (KeyboardInterrupt, EOFError):
            pass
        return True
    
    os.chdir(path.parent)
    
    exit_code = 0
    try:
        result = subprocess.run(
            [sys.executable, str(path)],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
            check=False
        )
        exit_code = result.returncode
    except KeyboardInterrupt:
        print("\n\n⚠️  Module interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error running module: {e}")
        exit_code = 1
    
    reset_terminal()
    
    print(f"\n{'='*60}")
    if exit_code == 0:
        print("✅ Module completed successfully.")
    else:
        print(f"⚠️  Module exited with code: {exit_code}")
    print(f"{'='*60}")
    
    try:
        input("\n Press Enter to return to LOOT...")
    except (KeyboardInterrupt, EOFError):
        pass
    
    return True


class CategoryButton(Button):
    """A button for category selection."""
    
    def __init__(self, category: str, *args, **kwargs):
        # Add emoji based on category
        emoji = {
            "All": "📂",
            "Mobile": "📱",
            "Web": "🌐",
            "Network": "🔌",
            "AI": "🤖",
        }.get(category, "📁")
        super().__init__(f"{emoji} {category}", *args, **kwargs)
        self.category = category


class ToolkitOption(Button):
    """A button representing a toolkit option."""
    
    def __init__(self, toolkit: ToolkitInfo, *args, **kwargs):
        # Add category emoji
        emoji = {
            "Mobile": "📱",
            "Web": "🌐",
            "Network": "🔌",
            "AI": "🤖",
        }.get(toolkit.category, "📁")
        label = f"{emoji} {toolkit.name}"
        super().__init__(label, *args, **kwargs)
        self.toolkit = toolkit


class CategorySidebar(Container):
    """Sidebar for category filtering."""
    
    def __init__(self, categories: list[str], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.categories = categories
        self.selected = "All"
    
    def compose(self) -> ComposeResult:
        yield Static("🏷️ Categories", id="sidebar-title")
        for cat in self.categories:
            btn = CategoryButton(cat, id=f"cat-{cat.lower()}")
            if cat == self.selected:
                btn.add_class("selected")
            yield btn
    
    def select_category(self, category: str) -> None:
        """Update the selected category."""
        self.selected = category
        for btn in self.query(CategoryButton):
            if btn.category == category:
                btn.add_class("selected")
            else:
                btn.remove_class("selected")


class ToolkitLauncher(App):
    """Main TUI application for launching toolkit modules."""
    
    # Red/Crimson theme with sidebar
    CSS = """
    Screen {
        background: #1a0a0a;
    }
    
    Header {
        background: #8b0000;
        color: #ffffff;
    }
    
    Footer {
        background: #4a0000;
        color: #ffcccc;
    }
    
    #banner-container {
        height: auto;
        padding: 1 2;
        background: #2a0a0a;
        align: center middle;
    }
    
    #banner {
        color: #ff4444;
        text-style: bold;
        text-align: center;
        width: auto;
    }
    
    #title-container {
        height: auto;
        padding: 1 2;
        background: #8b0000;
        text-align: center;
    }
    
    #title {
        text-align: center;
        text-style: bold;
        color: #ffffff;
    }
    
    #subtitle {
        text-align: center;
        color: #ffcccc;
    }
    
    #main-content {
        height: 1fr;
    }
    
    CategorySidebar {
        width: 20;
        background: #2a0a0a;
        border-right: solid #ff4444;
        padding: 1;
    }
    
    #sidebar-title {
        text-align: center;
        text-style: bold;
        color: #ff8888;
        padding: 1 0;
        border-bottom: solid #ff4444;
        margin-bottom: 1;
    }
    
    CategoryButton {
        width: 100%;
        margin: 0 0 1 0;
        height: 3;
        background: #3a1a1a;
        color: #ffcccc;
        border: tall #4a0000;
    }
    
    CategoryButton:hover {
        background: #5a1a1a;
    }
    
    CategoryButton:focus {
        background: #6a1a1a;
    }
    
    CategoryButton.selected {
        background: #8b0000;
        color: #ffffff;
        text-style: bold;
        border: tall #ff4444;
    }
    
    #options-container {
        width: 1fr;
        padding: 1 2;
    }
    
    #options-scroll {
        height: 1fr;
        border: solid #ff4444;
        padding: 1;
        background: #1a0a0a;
    }
    
    ToolkitOption {
        width: 100%;
        margin: 1 0;
        height: 3;
        background: #3a1a1a;
        color: #ffffff;
        border: tall #ff4444;
    }
    
    ToolkitOption:hover {
        background: #8b0000;
        color: #ffffff;
    }
    
    ToolkitOption:focus {
        background: #cc0000;
        color: #ffffff;
        text-style: bold;
        border: tall #ff6666;
    }
    
    #no-toolkits {
        text-align: center;
        padding: 2;
        color: #ff8888;
    }
    
    #status-bar {
        height: auto;
        padding: 1 2;
        background: #2a0a0a;
        text-align: center;
        color: #ff8888;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("u", "update", "Update"),
        Binding("escape", "quit", "Quit"),
        Binding("1", "select_category_1", "All", show=False),
        Binding("2", "select_category_2", "Mobile", show=False),
        Binding("3", "select_category_3", "Web", show=False),
        Binding("4", "select_category_4", "Network", show=False),
        Binding("5", "select_category_5", "AI", show=False),
    ]
    
    def __init__(self):
        super().__init__()
        self.all_toolkits: list[ToolkitInfo] = []
        self.filtered_toolkits: list[ToolkitInfo] = []
        self.repo_root = Path(__file__).parent.resolve()
        self.selected_toolkit: Path | None = None
        self.current_category = "All"
    
    def on_mount(self) -> None:
        """Run update check on launch; notify if updates available."""
        has_update, msg = check_for_updates(self.repo_root)
        if has_update:
            self.notify(msg, title="Update available", severity="information", timeout=8)

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        
        with Container(id="banner-container"):
            yield Static(LOOT_BANNER, id="banner")
        
        with Container(id="title-container"):
            yield Static("L0WK3Y's Offensive Operations Toolkit", id="title")
            yield Static("Select a module to launch", id="subtitle")
        
        with Horizontal(id="main-content"):
            yield CategorySidebar(CATEGORIES, id="category-sidebar")
            
            with Container(id="options-container"):
                with VerticalScroll(id="options-scroll"):
                    self.all_toolkits = self._scan_for_toolkits()
                    self.filtered_toolkits = self.all_toolkits.copy()
                    
                    if self.filtered_toolkits:
                        for toolkit in self.filtered_toolkits:
                            yield ToolkitOption(
                                toolkit
                            )
                    else:
                        yield Label("No toolkit modules found!")
        
        yield Static(f"📁 Repo: {self.repo_root} | 1-5 categories | U update", id="status-bar")
        yield Footer()
    
    def _scan_for_toolkits(self) -> list[ToolkitInfo]:
        """Scan immediate child directories for main.py files."""
        toolkits = []
        
        for child_dir in self.repo_root.iterdir():
            if child_dir.name.startswith('.'):
                continue
            
            if not child_dir.is_dir():
                continue
            
            main_py = child_dir / "main.py"
            if main_py.exists() and main_py.is_file():
                name = child_dir.name
                category = detect_category(name, main_py)
                description = get_toolkit_description(main_py)
                toolkits.append(ToolkitInfo(
                    name=name,
                    path=main_py,
                    category=category,
                    description=description
                ))
        
        toolkits.sort(key=lambda x: x.name.lower())
        return toolkits
    
    def _filter_toolkits(self, category: str) -> None:
        """Filter toolkits by category and update the display."""
        self.current_category = category
        
        if category == "All":
            self.filtered_toolkits = self.all_toolkits.copy()
        else:
            self.filtered_toolkits = [t for t in self.all_toolkits if t.category == category]
        
        # Update sidebar selection
        sidebar = self.query_one(CategorySidebar)
        sidebar.select_category(category)
        
        # Update the toolkit list - remove and recreate widgets
        scroll = self.query_one("#options-scroll")
        
        # Remove existing toolkit buttons properly
        for child in list(scroll.children):
            child.remove()
        
        if self.filtered_toolkits:
            for i, toolkit in enumerate(self.filtered_toolkits):
                # Use unique IDs with index to avoid conflicts
                btn = ToolkitOption(toolkit)
                scroll.mount(btn)
        else:
            scroll.mount(Label(f"No {category} toolkits found!"))
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if isinstance(event.button, CategoryButton):
            self._filter_toolkits(event.button.category)
        elif isinstance(event.button, ToolkitOption):
            self.selected_toolkit = event.button.toolkit.path
            self.exit(self.selected_toolkit)
    
    def action_refresh(self) -> None:
        """Refresh the toolkit list."""
        self.all_toolkits = self._scan_for_toolkits()
        self._filter_toolkits(self.current_category)
        self.notify("Toolkit list refreshed!", title="Refresh")

    def action_update(self) -> None:
        """Check for updates from GitHub and pull if available."""
        has_update, msg = check_for_updates(self.repo_root)
        if not has_update:
            self.notify(msg, title="Update")
            return
        self.notify(msg, title="Update available", severity="information")
        ok, pull_msg = pull_updates(self.repo_root)
        if ok:
            self.notify(
                pull_msg + " Restart LOOT to use the new version.",
                title="Update complete",
                severity="information",
            )
        else:
            self.notify(pull_msg, title="Update failed", severity="error")

    def action_quit(self) -> None:
        """Quit the application."""
        self.exit(None)
    
    def action_select_category_1(self) -> None:
        self._filter_toolkits("All")
    
    def action_select_category_2(self) -> None:
        self._filter_toolkits("Mobile")
    
    def action_select_category_3(self) -> None:
        self._filter_toolkits("Web")
    
    def action_select_category_4(self) -> None:
        self._filter_toolkits("Network")
    
    def action_select_category_5(self) -> None:
        self._filter_toolkits("AI")


def main():
    """Entry point for the toolkit launcher."""
    repo_root = Path(__file__).parent.resolve()
    
    while True:
        os.chdir(repo_root)
        
        app = ToolkitLauncher()
        selected = app.run()
        
        reset_terminal()
        
        if selected is None:
            print("\n👋 Goodbye!\n")
            break
        
        should_continue = run_toolkit(selected)
        
        if not should_continue:
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        import sys
        print("\n👋 Cancelled by user")
        sys.exit(0)
