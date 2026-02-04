#!/usr/bin/env python3
"""
L0WK3Y's Offensive Operations Toolkit - Setup Script
Install with: pip install -e .
Install with all modules: pip install -e .[all]
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the root requirements
root_requirements = [
    "textual>=0.47.0",  # TUI framework for the launcher
]

# Mobile-RE-Toolkit dependencies
mret_requirements = [
    "rich>=13.0.0",
    "prompt-toolkit>=3.0.0",
    "requests>=2.31.0",
    "frida>=16.0.0",
    "frida-tools>=12.0.0",
    "typer>=0.9.0",
    "beautifulsoup4>=4.12.0",
    "selenium>=4.0.0",
    "colorama>=0.4.6",
    "Pygments>=2.15.0",
    "GitPython>=3.1.0",
]

# All dependencies combined
all_requirements = list(set(root_requirements + mret_requirements))

setup(
    name="l0wk3y-offensive-toolkit",
    version="1.0.0",
    description="L0WK3Y's Offensive Operations Toolkit - A collection of security tools",
    author="L0WK3Y",
    python_requires=">=3.10",
    install_requires=root_requirements,
    extras_require={
        "mret": mret_requirements,
        "mobile-re-toolkit": mret_requirements,
        "all": all_requirements,
    },
    entry_points={
        "console_scripts": [
            "l0wk3y-toolkit=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
