from setuptools import setup, find_packages
import pathlib

# Read the contents of your README file (handle missing file gracefully)
this_directory = pathlib.Path(__file__).parent
try:
    long_description = (this_directory / "README.md").read_text()
except FileNotFoundError:
    long_description = "Mobile Reverse Engineering Toolkit for Android Security Testing"

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
    install_requires=[
        # Core dependencies from your requirements
        "beautifulsoup4>=4.13.0",
        "colorama>=0.4.6",
        "requests>=2.32.0",
        "rich>=14.0.0",
        "selenium>=4.34.0",
        "setuptools>=80.0.0",
        
        # Supporting libraries
        "trio>=0.30.0",
        "websocket-client>=1.8.0",
        "prompt_toolkit>=3.0.50",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "interactive": [
            "pygments>=2.19.0",
            "trio-websocket>=0.12.0",
        ],
        "full": [
            "sortedcontainers>=2.4.0",
            "typing_extensions>=4.14.0",
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
