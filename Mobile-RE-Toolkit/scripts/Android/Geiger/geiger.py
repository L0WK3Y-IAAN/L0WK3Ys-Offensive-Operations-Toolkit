#!/usr/bin/env python3
# MRET: requires_args
# MRET: args_info: scan [APK] [-o OUTPUT] [--reavs] [--threads N] | templates [--update]
"""
Geiger launcher script
Run this script directly or use: python geiger.py [command]
"""

import sys
from pathlib import Path

# Add the current directory to Python path
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

# Import and run main
from geiger.main import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Cancelled by user")
        sys.exit(0)
