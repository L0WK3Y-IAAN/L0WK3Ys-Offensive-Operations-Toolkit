"""Nuclei installer utility"""

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console

console = Console()

# GitHub releases API
NUCLEI_RELEASES_API = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
NUCLEI_REPO_URL = "https://github.com/projectdiscovery/nuclei/releases/latest"


def find_nuclei() -> Optional[str]:
    """
    Check if nuclei is installed and available in PATH.
    
    Returns:
        Path to nuclei binary or None if not found
    """
    return shutil.which("nuclei")


def get_platform_info() -> tuple[str, str, str]:
    """
    Get platform information for downloading the correct nuclei binary.
    
    Returns:
        Tuple of (os_name, arch, extension)
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map platform to nuclei naming (GitHub releases use specific casing)
    if system == "darwin":
        os_name = "macOS"  # Note: GitHub uses "macOS" with capital letters
        if machine in ["arm64", "aarch64"]:
            arch = "arm64"
        else:
            arch = "amd64"
    elif system == "linux":
        os_name = "linux"
        if machine in ["arm64", "aarch64"]:
            arch = "arm64"
        else:
            arch = "amd64"
    elif system == "windows":
        os_name = "windows"
        if machine in ["arm64", "aarch64"]:
            arch = "arm64"
        else:
            arch = "amd64"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
    
    # All nuclei releases are zip files
    extension = "zip"
    
    return os_name, arch, extension


def get_latest_release() -> dict:
    """
    Get the latest nuclei release information from GitHub API.
    
    Returns:
        Release information dictionary
    """
    try:
        response = requests.get(NUCLEI_RELEASES_API, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        console.print(f"[red]✗ Failed to fetch nuclei release info: {e}[/red]")
        raise


def download_nuclei(install_dir: Optional[Path] = None) -> Path:
    """
    Download and install the latest nuclei binary.
    
    Args:
        install_dir: Directory to install nuclei (defaults to ~/.local/bin or system PATH)
        
    Returns:
        Path to installed nuclei binary
    """
    console.print("[cyan]📥 Downloading latest nuclei release...[/cyan]")
    
    # Get platform info
    os_name, arch, ext = get_platform_info()
    
    # Get latest release
    release = get_latest_release()
    version_tag = release["tag_name"]
    # Remove 'v' prefix if present (e.g., v3.6.2 -> 3.6.2)
    version = version_tag.lstrip("v")
    console.print(f"[dim]Latest version: {version_tag}[/dim]")
    
    # Find the correct asset
    # GitHub releases use format: nuclei_{version}_{os}_{arch}.zip
    # e.g., nuclei_3.6.2_macOS_arm64.zip (note: no 'v' prefix in filename)
    asset_name = f"nuclei_{version}_{os_name}_{arch}.{ext}"
    asset = None
    
    # First try exact match
    for a in release.get("assets", []):
        if a["name"] == asset_name:
            asset = a
            break
    
    # If not found, try case-insensitive partial match
    if not asset:
        for a in release.get("assets", []):
            name_lower = a["name"].lower()
            # Check if it contains the version (without v prefix), os, arch, and extension
            if (version.lower() in name_lower and 
                os_name.lower() in name_lower and 
                arch in name_lower and 
                ext in name_lower and
                "checksums" not in name_lower and
                "source" not in name_lower):
                asset = a
                break
    
    # Last resort: try matching just os and arch
    if not asset:
        for a in release.get("assets", []):
            name_lower = a["name"].lower()
            if (os_name.lower() in name_lower and 
                arch in name_lower and 
                ext in name_lower and
                "checksums" not in name_lower and
                "source" not in name_lower):
                asset = a
                break
    
    if not asset:
        # List available assets for debugging
        available = [a["name"] for a in release.get("assets", []) if ext in a["name"]]
        raise RuntimeError(
            f"Could not find nuclei binary for {os_name}/{arch}.\n"
            f"Looking for: {asset_name}\n"
            f"Available assets: {', '.join(available[:5])}..."
        )
    
    download_url = asset["browser_download_url"]
    console.print(f"[dim]Downloading: {asset['name']}[/dim]")
    
    # Determine install directory
    if install_dir is None:
        # Try ~/.local/bin first (user-local)
        local_bin = Path.home() / ".local" / "bin"
        if local_bin.exists() or local_bin.parent.exists():
            install_dir = local_bin
        else:
            # Fall back to a temp directory and add to PATH suggestion
            install_dir = Path.home() / ".geiger" / "bin"
            install_dir.mkdir(parents=True, exist_ok=True)
    
    install_dir.mkdir(parents=True, exist_ok=True)
    
    # Download file
    temp_file = install_dir / asset["name"]
    
    console.print("[cyan]Downloading nuclei...[/cyan]")
    response = requests.get(download_url, stream=True, timeout=30)
    response.raise_for_status()
    
    total_size = int(response.headers.get("content-length", 0))
    
    # Use simple file writing without Progress to avoid conflicts with nested Progress contexts
    # Progress bars can conflict when called from within other rich contexts
    with open(temp_file, "wb") as f:
        downloaded = 0
        chunk_size = 8192
        last_update = 0
        
        for chunk in response.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                
                # Update progress every 1MB to avoid too many console updates
                if downloaded - last_update >= 1024 * 1024 or downloaded == total_size:
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        console.print(
                            f"[dim]Downloaded: {downloaded / 1024 / 1024:.1f} MB / "
                            f"{total_size / 1024 / 1024:.1f} MB ({percent:.1f}%)[/dim]",
                            end="\r"
                        )
                    else:
                        console.print(f"[dim]Downloaded: {downloaded / 1024 / 1024:.1f} MB[/dim]", end="\r")
                    last_update = downloaded
    
    console.print()  # New line after download
    
    console.print("[green]✓ Download complete[/green]")
    
    # Extract binary
    console.print("[cyan]📦 Extracting nuclei...[/cyan]")
    
    extract_dir = install_dir / "nuclei_extract"
    extract_dir.mkdir(exist_ok=True)
    
    try:
        # All nuclei releases are zip files
        with zipfile.ZipFile(temp_file, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Find the nuclei binary
        nuclei_binary = None
        is_windows = platform.system() == "Windows"
        
        # First, try to find exact match
        for file in extract_dir.rglob("nuclei*"):
            if not file.is_file():
                continue
            # On Windows, check for .exe extension; on Unix, check if executable
            if is_windows:
                if file.suffix.lower() == ".exe" and "nuclei" in file.name.lower():
                    nuclei_binary = file
                    break
            else:
                # On Unix, check if it's executable or try to make it executable
                if os.access(file, os.X_OK) or file.name == "nuclei":
                    nuclei_binary = file
                    # Make sure it's executable
                    os.chmod(file, 0o755)
                    break
        
        if not nuclei_binary:
            # Try finding any file with "nuclei" in the name
            for file in extract_dir.rglob("*"):
                if file.is_file():
                    name_lower = file.name.lower()
                    if is_windows:
                        if "nuclei" in name_lower and name_lower.endswith(".exe"):
                            nuclei_binary = file
                            break
                    else:
                        if name_lower == "nuclei" or (name_lower.startswith("nuclei") and "." not in name_lower):
                            nuclei_binary = file
                            os.chmod(file, 0o755)
                            break
        
        if not nuclei_binary:
            raise RuntimeError("Could not find nuclei binary in downloaded archive")
        
        # Copy to install directory
        final_path = install_dir / "nuclei"
        if platform.system() == "Windows":
            final_path = install_dir / "nuclei.exe"
        
        shutil.copy2(nuclei_binary, final_path)
        
        # Make executable (Unix-like systems)
        if platform.system() != "Windows":
            os.chmod(final_path, 0o755)
        
        # Cleanup
        temp_file.unlink()
        shutil.rmtree(extract_dir)
        
        console.print(f"[green]✓ Nuclei installed to: {final_path}[/green]")
        
        # Check if it's in PATH
        if str(install_dir) not in os.environ.get("PATH", ""):
            console.print(f"\n[yellow]⚠ Warning: {install_dir} is not in your PATH[/yellow]")
            console.print(f"[yellow]Add it to your PATH or use: {final_path}[/yellow]")
            console.print(f"[dim]Or run: export PATH=\"$PATH:{install_dir}\"[/dim]")
        
        return final_path
        
    except Exception as e:
        # Cleanup on error
        if temp_file.exists():
            temp_file.unlink()
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to extract nuclei: {e}")


def ensure_nuclei_installed(install_if_missing: bool = True) -> Optional[str]:
    """
    Ensure nuclei is installed, installing it if missing.
    
    Args:
        install_if_missing: Whether to install nuclei if not found
        
    Returns:
        Path to nuclei binary or None if not found/installed
    """
    nuclei_path = find_nuclei()
    
    if nuclei_path:
        # Verify it works
        try:
            result = subprocess.run(
                [nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip().split()[1] if result.stdout else "unknown"
                console.print(f"[green]✓ Nuclei found: {nuclei_path} (v{version})[/green]")
                return nuclei_path
        except Exception:
            pass
    
    if not install_if_missing:
        return None
    
    # Try to install
    try:
        console.print("[yellow]⚠ Nuclei not found. Attempting to install...[/yellow]")
        installed_path = download_nuclei()
        
        # Verify installation
        try:
            # Add install directory to PATH temporarily for verification
            install_dir = installed_path.parent
            env = os.environ.copy()
            current_path = env.get("PATH", "")
            if str(install_dir) not in current_path:
                env["PATH"] = f"{install_dir}{os.pathsep}{current_path}"
            
            result = subprocess.run(
                [str(installed_path), "-version"],
                capture_output=True,
                text=True,
                timeout=5,
                env=env
            )
            if result.returncode == 0:
                version = result.stdout.strip().split()[1] if result.stdout else "unknown"
                console.print(f"[green]✓ Nuclei installation verified (v{version})[/green]")
                # Update PATH for current session
                if str(install_dir) not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = f"{install_dir}{os.pathsep}{os.environ.get('PATH', '')}"
                return str(installed_path)
        except Exception as e:
            console.print(f"[yellow]⚠ Installed nuclei may not be working: {e}[/yellow]")
            console.print(f"[yellow]You may need to add it to your PATH: {installed_path.parent}[/yellow]")
            # Still return the path - it might work if added to PATH
            return str(installed_path)
            
    except Exception as e:
        console.print(f"[red]✗ Failed to install nuclei: {e}[/red]")
        console.print(f"[yellow]Please install manually from: {NUCLEI_REPO_URL}[/yellow]")
        return None
