# Quick Start Guide

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Ensure apktool, nuclei, and optionally jadx are in PATH
which apktool nuclei jadx
```

## Basic Examples

### Scan Single APK

```bash
python geiger.py scan app.apk
```

### Scan Directory of APKs

```bash
python geiger.py scan ./apks/ --threads 8
```

### Keep Decompiled Source

```bash
python geiger.py scan app.apk --keep-source
```

### Custom Output Directory

```bash
python geiger.py scan app.apk -o ./my_reports/
```

### Update Templates Manually

```bash
python geiger.py templates --update
```

## Output

Reports are saved to:
- `{output_dir}/{apk_name}/{apk_name}_report.json`
- `{output_dir}/{apk_name}/{apk_name}_report.html`

Console output shows a formatted table with all findings.
