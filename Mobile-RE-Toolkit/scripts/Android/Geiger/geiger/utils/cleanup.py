"""Cleanup utilities for temporary files"""

import shutil
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from rich.console import Console

console = Console()


@contextmanager
def temp_directory(prefix: str = "geiger_", keep: bool = False):
    """
    Context manager for temporary directory cleanup.
    
    Args:
        prefix: Prefix for temporary directory name
        keep: If True, don't delete directory on exit
    
    Yields:
        Path to temporary directory
    """
    import tempfile
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
    
    try:
        yield temp_dir
    finally:
        if not keep and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                console.print(f"[yellow]⚠ Could not clean up {temp_dir}: {e}[/yellow]")


def cleanup_directory(path: Path, force: bool = False) -> bool:
    """
    Clean up a directory.
    
    Args:
        path: Path to directory to clean
        force: Force removal even if directory contains files
    
    Returns:
        True if successful
    """
    if not path.exists():
        return True
    
    try:
        shutil.rmtree(path)
        return True
    except Exception as e:
        if force:
            try:
                import os
                for root, dirs, files in os.walk(path):
                    for f in files:
                        os.chmod(os.path.join(root, f), 0o777)
                        os.unlink(os.path.join(root, f))
                    for d in dirs:
                        os.chmod(os.path.join(root, d), 0o777)
                shutil.rmtree(path)
                return True
            except Exception:
                pass
        console.print(f"[yellow]⚠ Could not clean up {path}: {e}[/yellow]")
        return False
