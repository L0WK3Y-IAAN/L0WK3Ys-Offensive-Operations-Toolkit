#!/usr/bin/env python3
"""
GhidraMCP Setup Script
Downloads and installs GhidraMCP extension for Ghidra reverse engineering tool.
"""

import os
import sys
import shutil
import subprocess
import platform
import zipfile
import argparse
import json
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

console = Console()

# GhidraMCP release information
GHIDRAMCP_RELEASE_URL = "https://github.com/LaurieWired/GhidraMCP/releases/download/1.4/GhidraMCP-release-1-4.zip"
GHIDRAMCP_REPO_URL = "https://github.com/LaurieWired/GhidraMCP"
EXTENSION_PROPERTIES = "extension.properties"


def get_toolkit_root() -> Path:
    """Get the absolute path to the Mobile-RE-Toolkit root."""
    script_dir = Path(__file__).resolve().parent
    toolkit_root = script_dir
    for _ in range(10):
        if (toolkit_root / "main.py").exists():
            return toolkit_root
        toolkit_root = toolkit_root.parent
    return script_dir.parent.parent.parent


def find_ghidra_installations(manual_path: Optional[Path] = None) -> list[Path]:
    """
    Find Ghidra installation directories.
    Checks environment variables, PATH, and common installation locations.
    
    Args:
        manual_path: Optional manual path provided via command line
    
    Returns:
        List of potential Ghidra installation paths
    """
    possible_paths = []
    seen_paths = set()
    
    def add_path_if_valid(path: Path) -> None:
        """Add path to list if it's a valid Ghidra installation."""
        if not path or not path.exists() or not path.is_dir():
            return
        
        resolved = path.resolve()
        if resolved in seen_paths:
            return
        seen_paths.add(resolved)
        
        # Check for ghidraRun script or executable
        has_ghidra_run = (
            (resolved / "ghidraRun").exists() or
            (resolved / "ghidraRun.bat").exists() or
            (resolved / "ghidraRun.exe").exists()
        )
        
        if has_ghidra_run:
            possible_paths.append(resolved)
            return
        
        # Check subdirectories (versioned folders like ghidra_10.4)
        for subdir in resolved.iterdir():
            if subdir.is_dir():
                sub_resolved = subdir.resolve()
                if sub_resolved in seen_paths:
                    continue
                seen_paths.add(sub_resolved)
                
                if (
                    (subdir / "ghidraRun").exists() or
                    (subdir / "ghidraRun.bat").exists() or
                    (subdir / "ghidraRun.exe").exists()
                ):
                    possible_paths.append(sub_resolved)
    
    # 1. Check manual path (highest priority)
    if manual_path:
        add_path_if_valid(manual_path)
    
    # 2. Check environment variables
    env_vars = ["GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_INSTALL", "GHIDRA"]
    for env_var in env_vars:
        env_path = os.environ.get(env_var)
        if env_path:
            add_path_if_valid(Path(env_path))
    
    # 3. Check PATH for ghidra executables
    ghidra_exe = shutil.which("ghidraRun")
    if ghidra_exe:
        exe_path = Path(ghidra_exe).resolve()
        # Get parent directory (ghidraRun is typically in the root of Ghidra installation)
        if exe_path.parent.exists():
            add_path_if_valid(exe_path.parent)
    
    # 4. Check common installation locations
    if platform.system() == "Windows":
        common_paths = [
            Path(os.environ.get("ProgramFiles", "")) / "Ghidra",
            Path(os.environ.get("ProgramFiles(x86)", "")) / "Ghidra",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Ghidra",
            Path.home() / "Ghidra",
            Path.home() / "Documents" / "Ghidra",
            Path.home() / "Downloads" / "Ghidra",
            Path("D:") / "tools" / "ghidra",  # User's specific path
        ]
    elif platform.system() == "Darwin":  # macOS
        common_paths = [
            Path("/Applications") / "Ghidra",
            Path.home() / "Applications" / "Ghidra",
            Path.home() / "Ghidra",
        ]
    else:  # Linux
        common_paths = [
            Path("/opt") / "ghidra",
            Path("/usr/local") / "ghidra",
            Path.home() / "ghidra",
            Path.home() / "Ghidra",
        ]
    
    # Check each common path
    for path in common_paths:
        add_path_if_valid(path)
    
    return possible_paths


def get_ghidra_extensions_dir(ghidra_path: Path) -> Path:
    """
    Get the Ghidra extensions directory for a given Ghidra installation.
    
    Args:
        ghidra_path: Path to Ghidra installation
        
    Returns:
        Path to extensions directory
    """
    # Extensions are typically in: <ghidra>/Extensions
    extensions_dir = ghidra_path / "Extensions/Ghidra"
    extensions_dir.mkdir(exist_ok=True)
    return extensions_dir


def download_ghidramcp(download_dir: Path) -> Path:
    """
    Download GhidraMCP release zip file.
    
    Args:
        download_dir: Directory to save the download
        
    Returns:
        Path to downloaded zip file
    """
    download_dir.mkdir(parents=True, exist_ok=True)
    zip_filename = "GhidraMCP-release-1-4.zip"
    zip_path = download_dir / zip_filename
    
    # Check if already downloaded
    if zip_path.exists():
        console.print(f"[green]✓ Found existing download: {zip_path}[/green]")
        return zip_path
    
    console.print("[cyan]📥 Downloading GhidraMCP from GitHub...[/cyan]")
    console.print(f"[dim]URL: {GHIDRAMCP_RELEASE_URL}[/dim]")
    
    try:
        response = requests.get(GHIDRAMCP_RELEASE_URL, stream=True, timeout=60)
        response.raise_for_status()
        
        total_size = int(response.headers.get("content-length", 0))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Downloading...", total=total_size)
            
            with open(zip_path, "wb") as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        progress.update(task, completed=downloaded)
        
        console.print(f"[green]✓ Download complete: {zip_path}[/green]")
        return zip_path
        
    except requests.RequestException as e:
        console.print(f"[red]✗ Failed to download GhidraMCP: {e}[/red]")
        raise


def extract_ghidramcp(zip_path: Path, extract_dir: Path) -> Path:
    """
    Extract outer zip to find nested GhidraMCP zip file.
    The nested zip should NOT be extracted, just located.
    
    Args:
        zip_path: Path to outer zip file
        extract_dir: Directory to extract to
        
    Returns:
        Path to nested GhidraMCP zip file (not extracted)
    """
    console.print("[cyan]📦 Extracting outer zip to find nested GhidraMCP zip...[/cyan]")
    
    extract_dir.mkdir(parents=True, exist_ok=True)
    temp_extract = extract_dir / "ghidramcp_temp"
    
    try:
        # Extract outer zip
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_extract)
        
        # Find nested zip files (the actual extension zip)
        nested_zips = list(temp_extract.rglob("*.zip"))
        
        if not nested_zips:
            # List what we found for debugging
            found_items = list(temp_extract.iterdir()) if temp_extract.exists() else []
            raise RuntimeError(
                f"Could not find nested GhidraMCP zip file in archive.\n"
                f"Found items: {[item.name for item in found_items[:10]]}"
            )
        
        # Find the GhidraMCP zip (prefer files with "GhidraMCP" in the name)
        ghidramcp_zip = None
        for zip_file in nested_zips:
            if "GhidraMCP" in zip_file.name or "ghidramcp" in zip_file.name.lower():
                ghidramcp_zip = zip_file
                break
        
        # If no specific match, use the first zip found
        if not ghidramcp_zip:
            ghidramcp_zip = nested_zips[0]
        
        console.print(f"[green]✓ Found nested zip: {ghidramcp_zip.name}[/green]")
        return ghidramcp_zip
        
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"Invalid zip file: {zip_path} - {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to extract GhidraMCP: {e}")


def install_ghidramcp(ghidramcp_zip: Path, ghidra_extensions_dir: Path) -> Path:
    """
    Install GhidraMCP extension zip to Ghidra extensions directory.
    The zip file is copied as-is (not extracted).
    
    Args:
        ghidramcp_zip: Path to GhidraMCP zip file (nested zip)
        ghidra_extensions_dir: Path to Ghidra Extensions directory
        
    Returns:
        Path to installed extension zip file
    """
    console.print("[cyan]🔧 Installing GhidraMCP extension...[/cyan]")
    
    # Determine extension name from zip filename (without .zip extension)
    extension_name = ghidramcp_zip.stem  # Gets filename without .zip
    
    # Clean up extension name (remove version suffixes if present)
    if "-release-" in extension_name:
        extension_name = extension_name.split("-release-")[0]
    elif extension_name.lower().startswith("ghidramcp"):
        # Ensure it's just "GhidraMCP"
        extension_name = "GhidraMCP"
    
    # Target is the zip file in Extensions directory
    target_zip = ghidra_extensions_dir / f"{extension_name}.zip"
    
    # Remove existing installation if present
    if target_zip.exists():
        console.print(f"[yellow]⚠ Removing existing installation: {target_zip}[/yellow]")
        target_zip.unlink()
    
    # Copy zip file to Ghidra Extensions directory
    shutil.copy2(ghidramcp_zip, target_zip)
    
    console.print(f"[green]✓ GhidraMCP installed to: {target_zip}[/green]")
    return target_zip


def verify_installation(extension_zip: Path) -> bool:
    """
    Verify that GhidraMCP extension zip is properly installed.
    
    Args:
        extension_zip: Path to installed extension zip file
        
    Returns:
        True if installation appears valid
    """
    if not extension_zip.exists():
        console.print(f"[yellow]⚠ Warning: Extension zip not found: {extension_zip}[/yellow]")
        return False
    
    # Verify it's a valid zip file
    try:
        with zipfile.ZipFile(extension_zip, "r") as zip_ref:
            file_list = zip_ref.namelist()
            
            # Check for required files in the zip
            has_properties = any(EXTENSION_PROPERTIES in f for f in file_list)
            has_manifest = any("Module.manifest" in f for f in file_list)
            
            if not has_properties:
                console.print(f"[yellow]⚠ Warning: {EXTENSION_PROPERTIES} not found in zip[/yellow]")
                return False
            
            if not has_manifest:
                console.print("[yellow]⚠ Warning: Module.manifest not found in zip[/yellow]")
                return False
            
            # Check for jar files
            has_jar = any(f.endswith(".jar") for f in file_list)
            if not has_jar:
                console.print("[yellow]⚠ Warning: No .jar files found in extension zip[/yellow]")
                return False
            
    except zipfile.BadZipFile:
        console.print(f"[yellow]⚠ Warning: Invalid zip file: {extension_zip}[/yellow]")
        return False
    except Exception as e:
        console.print(f"[yellow]⚠ Warning: Could not verify zip: {e}[/yellow]")
        return False
    
    console.print("[green]✓ Installation verified[/green]")
    return True


def find_bridge_script(extract_dir: Path) -> Optional[Path]:
    """
    Find the bridge_mcp_ghidra.py script in the extracted directory.
    Also checks the toolkit Tools directory as a fallback.
    
    Args:
        extract_dir: Directory where the outer zip was extracted
        
    Returns:
        Path to bridge_mcp_ghidra.py or None if not found
    """
    # First, search in the extracted directory
    temp_extract = extract_dir / "ghidramcp_temp"
    
    bridge_script = None
    if temp_extract.exists():
        # Search for bridge_mcp_ghidra.py in the extracted files
        for item in temp_extract.rglob("bridge_mcp_ghidra.py"):
            if item.is_file():
                bridge_script = item
                break
    
    # Fallback: check toolkit Tools directory
    if not bridge_script:
        toolkit_root = get_toolkit_root()
        tools_dir = toolkit_root / "Tools" / "ghidramcp" / "extracted" / "ghidramcp_temp"
        if tools_dir.exists():
            for item in tools_dir.rglob("bridge_mcp_ghidra.py"):
                if item.is_file():
                    bridge_script = item
                    break
    
    return bridge_script


def check_mcp_dependencies() -> bool:
    """
    Check if required MCP dependencies are installed.
    
    Returns:
        True if all dependencies are available
    """
    # Check mcp module
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import mcp"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            console.print("[yellow]⚠ Missing dependency: mcp[/yellow]")
            return False
    except Exception:
        console.print("[yellow]⚠ Missing dependency: mcp[/yellow]")
        return False
    
    # Check requests module
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import requests"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            console.print("[yellow]⚠ Missing dependency: requests[/yellow]")
            return False
    except Exception:
        console.print("[yellow]⚠ Missing dependency: requests[/yellow]")
        return False
    
    console.print("[green]✓ MCP dependencies are installed[/green]")
    return True


def install_mcp_dependencies() -> bool:
    """
    Install required MCP dependencies (mcp and requests).
    
    Returns:
        True if installation was successful
    """
    console.print("[cyan]📦 Installing MCP dependencies...[/cyan]")
    
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "mcp>=1.2.0,<2", "requests>=2,<3"],
            check=True,
            capture_output=True,
            text=True
        )
        console.print("[green]✓ MCP dependencies installed successfully[/green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗ Failed to install dependencies: {e}[/red]")
        console.print(f"[dim]Error output: {e.stderr}[/dim]")
        return False


def setup_mcp_config(bridge_script: Path, ghidra_server: str = "http://127.0.0.1:8080/") -> bool:
    """
    Configure Cursor's mcp.json file to include GhidraMCP.
    
    Args:
        bridge_script: Path to bridge_mcp_ghidra.py script
        ghidra_server: URL of Ghidra server (default: http://127.0.0.1:8080/)
        
    Returns:
        True if configuration was successful
    """
    mcp_config_path = Path.home() / ".cursor" / "mcp.json"
    
    # Create .cursor directory if it doesn't exist
    mcp_config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Read existing config or create new one
    if mcp_config_path.exists():
        try:
            with open(mcp_config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[yellow]⚠ Warning: Could not read existing mcp.json: {e}[/yellow]")
            config = {"mcpServers": {}}
    else:
        config = {"mcpServers": {}}
    
    # Ensure mcpServers exists
    if "mcpServers" not in config:
        config["mcpServers"] = {}
    
    # Add or update GhidraMCP configuration
    bridge_script_str = str(bridge_script.resolve())
    
    # Use Python executable from current environment
    python_exe = sys.executable
    
    config["mcpServers"]["ghidra"] = {
        "command": python_exe,
        "args": [
            bridge_script_str,
            "--ghidra-server", ghidra_server,
            "--transport", "stdio"
        ]
    }
    
    # Write updated config
    try:
        with open(mcp_config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        console.print(f"[green]✓ MCP configuration updated: {mcp_config_path}[/green]")
        return True
    except IOError as e:
        console.print(f"[red]✗ Failed to write mcp.json: {e}[/red]")
        return False


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Setup GhidraMCP extension for Ghidra reverse engineering tool"
    )
    parser.add_argument(
        "--ghidra-path",
        type=str,
        help="Manual path to Ghidra installation directory"
    )
    args = parser.parse_args()
    
    console.print(Panel.fit(
        "[bold cyan]GhidraMCP Setup[/bold cyan]\n"
        "[dim]Install GhidraMCP extension for Ghidra reverse engineering tool[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    # Find Ghidra installations
    console.print("[cyan]🔍 Searching for Ghidra installations...[/cyan]")
    
    manual_path = None
    if args.ghidra_path:
        manual_path = Path(args.ghidra_path)
        if not manual_path.exists():
            console.print(f"[red]❌ Specified path does not exist: {manual_path}[/red]")
            sys.exit(1)
        console.print(f"[dim]Using manual path: {manual_path}[/dim]")
    
    ghidra_installations = find_ghidra_installations(manual_path=manual_path)
    
    if not ghidra_installations:
        console.print("[red]❌ No Ghidra installation found![/red]")
        console.print("[yellow]💡 Please install Ghidra first:[/yellow]")
        console.print("[dim]   https://ghidra-sre.org/[/dim]")
        console.print()
        console.print("[yellow]💡 Or specify your Ghidra installation path manually:[/yellow]")
        console.print("[dim]   python setup_ghidramcp.py --ghidra-path /path/to/ghidra[/dim]")
        sys.exit(1)
    
    # Select Ghidra installation
    if len(ghidra_installations) == 1:
        selected_ghidra = ghidra_installations[0]
        console.print(f"[green]✓ Found Ghidra: {selected_ghidra}[/green]")
    else:
        console.print(f"[green]✓ Found {len(ghidra_installations)} Ghidra installation(s):[/green]")
        table = Table(title="Available Ghidra Installations", show_header=True, header_style="bold magenta")
        table.add_column("Index", justify="center", style="cyan", no_wrap=True, width=8)
        table.add_column("Path", style="green")
        
        for i, path in enumerate(ghidra_installations, 1):
            table.add_row(str(i), str(path))
        
        console.print(table)
        console.print()
        
        try:
            choice = input("[cyan]Select Ghidra installation (1-{}): [/cyan]".format(len(ghidra_installations))).strip()
            idx = int(choice) - 1
            if 0 <= idx < len(ghidra_installations):
                selected_ghidra = ghidra_installations[idx]
            else:
                console.print("[red]❌ Invalid selection[/red]")
                sys.exit(1)
        except (ValueError, KeyboardInterrupt):
            console.print("\n[yellow]👋 Cancelled[/yellow]")
            sys.exit(0)
    
    # Get extensions directory
    extensions_dir = get_ghidra_extensions_dir(selected_ghidra)
    console.print(f"[dim]Extensions directory: {extensions_dir}[/dim]")
    console.print()
    
    # Download GhidraMCP
    toolkit_root = get_toolkit_root()
    download_dir = toolkit_root / "Tools" / "ghidramcp"
    download_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        zip_path = download_ghidramcp(download_dir)
    except Exception as e:
        console.print(f"[red]✗ Download failed: {e}[/red]")
        sys.exit(1)
    
    # Extract outer zip to find nested GhidraMCP zip
    try:
        extract_dir = download_dir / "extracted"
        ghidramcp_zip = extract_ghidramcp(zip_path, extract_dir)
    except Exception as e:
        console.print(f"[red]✗ Extraction failed: {e}[/red]")
        sys.exit(1)
    
    # Install extension (copy zip file, don't extract)
    try:
        installed_zip = install_ghidramcp(ghidramcp_zip, extensions_dir)
    except Exception as e:
        console.print(f"[red]✗ Installation failed: {e}[/red]")
        sys.exit(1)
    
    # Verify installation
    if verify_installation(installed_zip):
        console.print()
        
        # Setup MCP configuration
        console.print("[cyan]🔧 Configuring MCP for Cursor...[/cyan]")
        bridge_script = find_bridge_script(extract_dir)
        
        if bridge_script and bridge_script.exists():
            # Check and install MCP dependencies
            if not check_mcp_dependencies():
                console.print("[yellow]⚠ MCP dependencies missing, attempting to install...[/yellow]")
                if not install_mcp_dependencies():
                    console.print("[red]✗ Failed to install MCP dependencies[/red]")
                    console.print("[yellow]💡 Please install manually: pip install 'mcp>=1.2.0,<2' 'requests>=2,<3'[/yellow]")
            
            if setup_mcp_config(bridge_script):
                console.print("[green]✓ MCP configuration complete[/green]")
            else:
                console.print("[yellow]⚠ MCP configuration failed, but extension is installed[/yellow]")
        else:
            console.print("[yellow]⚠ Could not find bridge_mcp_ghidra.py script[/yellow]")
            console.print("[yellow]💡 You may need to configure mcp.json manually[/yellow]")
        
        console.print()
        console.print(Panel.fit(
            "[bold green]✓ GhidraMCP Setup Complete![/bold green]\n\n"
            "[cyan]Next steps:[/cyan]\n"
            "1. Restart Ghidra if it's currently running\n"
            "2. In Ghidra, go to: [bold]File → Configure → Extensions[/bold]\n"
            "3. Enable the [bold]GhidraMCP[/bold] extension\n"
            "4. Restart Ghidra to activate the extension\n"
            "5. Start the Ghidra server (the extension should provide instructions)\n"
            "6. Restart Cursor to load the MCP configuration\n\n"
            f"[dim]Extension zip installed at: {installed_zip}[/dim]",
            border_style="green"
        ))
    else:
        console.print()
        console.print("[yellow]⚠ Installation completed but verification found issues[/yellow]")
        console.print("[yellow]💡 You may need to manually check the extension directory[/yellow]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Setup cancelled[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Unexpected error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
