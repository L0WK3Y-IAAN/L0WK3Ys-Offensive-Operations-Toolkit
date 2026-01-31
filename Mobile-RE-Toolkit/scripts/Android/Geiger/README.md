# Geiger - Android APK Security Scanner

🔍 **Comprehensive static analysis for Android APKs using Nuclei templates and reAVS taint analysis**

Geiger is a Python-based security scanner that combines multiple analysis engines to identify vulnerabilities in Android applications. It provides beautiful, structured output with severity-based findings.

## Features

- 🚀 **Nuclei Integration**: Uses [optiv/mobile-nuclei-templates](https://github.com/optiv/mobile-nuclei-templates) for pattern-based detection
- 🔬 **reAVS Taint Analysis**: Optional deep taint analysis using [reAVS](https://github.com/aimardcr/reAVS) (auto-cloned if not installed)
- 🔄 **Hybrid Decompilation**: Uses both `apktool` (for smali) and `jadx` (for Java source)
- 📊 **Smart Reporting**: JSON and HTML reports with severity indicators
- ⚡ **Caching**: Reuses previous decompilation to speed up repeat scans
- 🎨 **Rich CLI**: Beautiful colored output with progress indicators
- 🎯 **Interactive APK Selection**: Fuzzy search for APK files

## Installation

### Prerequisites

- Python 3.10+
- `apktool` - [Installation Guide](https://ibotpeaches.github.io/Apktool/install/)
- `nuclei` - [Installation Guide](https://docs.projectdiscovery.io/nuclei/getting-started/installation)
- `jadx` (optional) - For Java source decompilation
- `git` - For cloning templates and reAVS

### Install Dependencies

```bash
# Navigate to Geiger directory
cd "Mobile-RE-Toolkit/scripts/Android/Geiger"

# Install Python dependencies
pip install -r requirements.txt
```

## Usage

### From MRET Launcher

Select "Geiger" from the MRET menu and provide arguments:
- `scan` - Scan an APK for vulnerabilities
- `templates --update` - Update nuclei templates

### Command Line

```bash
# Scan an APK (interactive file selection)
python geiger.py scan

# Scan a specific APK
python geiger.py scan path/to/app.apk

# Scan with reAVS taint analysis (auto-installs if needed)
python geiger.py scan --reavs

# Update nuclei templates
python geiger.py templates --update

# Custom output directory
python geiger.py scan -o ./my_reports/

# Keep decompiled source files
python geiger.py scan --keep-source
```

### Command Options

```
Usage: geiger scan [OPTIONS] [TARGET]

Arguments:
  TARGET                  APK file (optional - interactive selection if not provided)

Options:
  -o, --output PATH       Output directory for reports [default: reports/geiger_reports]
  --keep-source           Keep decompiled source files after scanning
  --reavs / --no-reavs    Also run reAVS taint analysis [default: False]
  -t, --threads INTEGER   Number of parallel threads [default: 4]
  -f, --format TEXT       Report format: json, html, all [default: all]
  --help                  Show this message and exit
```

## Analysis Engines

### Nuclei (Default)
Uses mobile-specific templates from [optiv/mobile-nuclei-templates](https://github.com/optiv/mobile-nuclei-templates) to detect:
- Hardcoded secrets and API keys
- Insecure configurations
- Vulnerable code patterns
- Privacy issues

### reAVS (Optional)
When enabled with `--reavs`, performs deep taint analysis using [reAVS](https://github.com/aimardcr/reAVS):
- Source-to-sink data flow analysis
- Entry point vulnerability detection
- Component security analysis
- High-confidence vulnerability identification

**Note**: reAVS is automatically cloned and set up when first used.

## Output

### Reports Location

Reports are saved to:
```
Mobile-RE-Toolkit/reports/geiger_reports/<apk_name>/
├── <apk_name>_report.json    # Structured JSON data
└── <apk_name>_report.html    # Formatted HTML report
```

### Cached Extractions

Decompiled APKs are cached for faster repeat scans:
```
Mobile-RE-Toolkit/src/output/geiger/<apk_name>_EXTRACTION/
├── apktool/    # Smali/resources from apktool
└── jadx/       # Java source from jadx
```

## How It Works

1. **Template Management**: Clones/updates `optiv/mobile-nuclei-templates` to `~/.geiger/mobile-nuclei-templates`

2. **Decompilation**:
   - Uses `apktool` for smali and resource extraction
   - Uses `jadx` for readable Java source code

3. **Scanning**:
   - Runs `nuclei` against decompiled directory
   - Optionally runs `reAVS` for taint analysis

4. **Reporting**:
   - Parses and merges findings from both engines
   - Generates JSON and HTML reports with severity indicators

## Exit Codes

- `0` - Success, no findings
- `1` - Error occurred during scanning
- `2` - Success, but findings were detected

## Credits

- **Original bash script**: [utkarsh24122/apknuke](https://github.com/utkarsh24122/apknuke)
- **Nuclei templates**: [optiv/mobile-nuclei-templates](https://github.com/optiv/mobile-nuclei-templates)
- **reAVS taint analysis**: [aimardcr/reAVS](https://github.com/aimardcr/reAVS) by [Aimar Sechan Adhitya](https://github.com/aimardcr)

## License

MIT
