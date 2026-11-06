#!/usr/bin/env python3
"""
L0WK3Y's Offensive Operations Toolkit - Setup Script
Install with: pip install -e .
Install with all modules: pip install -e .[all]
"""

from setuptools import setup, find_packages
from pathlib import Path

HERE = Path(__file__).parent.resolve()


def _read_requirements(req_file: Path) -> list[str]:
    """Parse a requirements.txt into setuptools-friendly specifiers,
    skipping comments/blank lines."""
    if not req_file.exists():
        return []
    reqs = []
    for raw_line in req_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            reqs.append(line)
    return reqs


# Read the root requirements
root_requirements = _read_requirements(HERE / "requirements.txt") or [
    "textual>=0.47.0",  # TUI framework for the launcher
]

# Mobile-RE-Toolkit dependencies - sourced from Mobile-RE-Toolkit/requirements.txt
# so this file and the launcher's own dependency check never drift apart.
mret_requirements = _read_requirements(HERE / "Mobile-RE-Toolkit" / "requirements.txt")

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
