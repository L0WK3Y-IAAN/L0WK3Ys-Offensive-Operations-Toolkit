from setuptools import setup, find_packages
import pathlib

# Read the contents of your README file (handle missing file gracefully)
this_directory = pathlib.Path(__file__).parent
try:
    long_description = (this_directory / "README.md").read_text()
except FileNotFoundError:
    long_description = "Mobile Reverse Engineering Toolkit for Android Security Testing"


def _read_requirements(req_file: pathlib.Path) -> list[str]:
    """Single source of truth: parse requirements.txt (shared with the
    LOOT launcher's own dependency check) instead of hand-duplicating
    the list here, so the two never drift apart."""
    if not req_file.exists():
        return []
    reqs = []
    for raw_line in req_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            reqs.append(line)
    return reqs


core_requirements = _read_requirements(this_directory / "requirements.txt")

setup(
    name="mobile-re-toolkit",
    version="1.0.0",
    author="L0WK3Y-IAAN",
    description="Mobile Reverse Engineering Toolkit for Android Security Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/L0WK3Y-IAAN/",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=core_requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "scan": [
            # Semgrep Scan script shells out to the `semgrep` CLI
            "semgrep>=1.151.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mret=main:main",
            "mobile-re-toolkit=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
