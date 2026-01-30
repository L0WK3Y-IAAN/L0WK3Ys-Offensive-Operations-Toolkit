"""Configuration and constants"""

from pathlib import Path
import os

# Base directory for geiger cache
GEIGER_HOME = Path.home() / ".geiger"
TEMPLATES_DIR = GEIGER_HOME / "mobile-nuclei-templates"
TEMPLATES_REPO_URL = "https://github.com/optiv/mobile-nuclei-templates"

# Default values
# Try to find workspace root (go up from script location to find main.py or src/)
_script_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
if (_script_dir / "main.py").exists() or (_script_dir / "src").exists():
    DEFAULT_OUTPUT_DIR = _script_dir / "reports" / "geiger_reports"
    # Persistent extraction cache (so we don't re-decompile the same APK repeatedly)
    DEFAULT_EXTRACTION_DIR = _script_dir / "src" / "output" / "geiger"
else:
    # Fallback to current directory
    DEFAULT_OUTPUT_DIR = Path.cwd() / "reports" / "geiger_reports"
    DEFAULT_EXTRACTION_DIR = Path.cwd() / "src" / "output" / "geiger"
DEFAULT_THREADS = 4

# Ensure directories exist
GEIGER_HOME.mkdir(parents=True, exist_ok=True)
DEFAULT_EXTRACTION_DIR.mkdir(parents=True, exist_ok=True)