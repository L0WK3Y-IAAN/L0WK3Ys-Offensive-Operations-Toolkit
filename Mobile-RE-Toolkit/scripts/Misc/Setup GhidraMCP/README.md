# 📌 GhidraMCP Setup

**Automated setup script for GhidraMCP extension**

🔹 **Author**: L0WK3Y  
🔹 **Category**: Reverse Engineering / Ghidra Extension  
🔹 **License**: MIT

---

## 🎯 Overview

The **GhidraMCP Setup** script automates the installation of the [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) extension for Ghidra reverse engineering tool. GhidraMCP provides Model Context Protocol (MCP) integration for Ghidra, enabling AI-powered reverse engineering workflows.

✅ **Automatically finds** Ghidra installations  
✅ **Downloads** latest GhidraMCP release from GitHub  
✅ **Installs** extension to Ghidra Extensions directory  
✅ **Verifies** installation integrity  
✅ **Cross-platform** support (Windows, macOS, Linux)

---

## 🛠️ Features

### 🔍 **Automatic Ghidra Detection**
- Searches common installation locations
- Supports multiple Ghidra installations
- Interactive selection if multiple found

### 📥 **Download & Installation**
- Downloads GhidraMCP release zip from GitHub
- Extracts and installs to Ghidra Extensions directory
- Handles existing installations (removes old version)

### ✅ **Verification**
- Checks for required extension files
- Validates extension structure
- Confirms installation success

---

## 🔧 Usage

### **Prerequisites**
- Python 3.10+
- Ghidra installed on your system
- Internet connection (for download)

### **Run the Script**

```bash
python setup_ghidramcp.py
```

The script will:
1. Search for Ghidra installations
2. Let you select which installation to use (if multiple found)
3. Download GhidraMCP from GitHub
4. Extract and install to Ghidra Extensions directory
5. Verify the installation

### **After Installation**

1. **Restart Ghidra** if it's currently running
2. **Enable the extension**:
   - Go to `File → Configure → Extensions`
   - Check the box next to `GhidraMCP`
   - Click `OK`
3. **Restart Ghidra** to activate the extension

---

## 📁 Installation Locations

The script searches for Ghidra in these locations:

**Windows:**
- `C:\Program Files\Ghidra\`
- `C:\Program Files (x86)\Ghidra\`
- `%LOCALAPPDATA%\Ghidra\`
- `%USERPROFILE%\Ghidra\`
- `%USERPROFILE%\Documents\Ghidra\`

**macOS:**
- `/Applications/Ghidra/`
- `~/Applications/Ghidra/`
- `~/Ghidra/`

**Linux:**
- `/opt/ghidra/`
- `/usr/local/ghidra/`
- `~/ghidra/`
- `~/Ghidra/`

---

## 📖 About GhidraMCP

**GhidraMCP** is a Ghidra extension that integrates Model Context Protocol (MCP) capabilities, enabling AI-assisted reverse engineering workflows. It allows you to interact with Ghidra through MCP-compatible AI assistants.

**Repository:** [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)

---

## 🔗 References

- [GhidraMCP GitHub](https://github.com/LaurieWired/GhidraMCP) - The extension repository
- [Ghidra Official Site](https://ghidra-sre.org/) - Ghidra reverse engineering framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification

---

## ⚠️ Notes

- The extension is installed to `<Ghidra>/Extensions/GhidraMCP/`
- You must restart Ghidra and enable the extension in the Extensions menu
- The script downloads the release zip to `Tools/ghidramcp/` for caching
- If Ghidra is not found, you'll need to install it first

---

## 🐛 Troubleshooting

**Ghidra not found:**
- Ensure Ghidra is installed
- Check that it's in one of the common installation locations
- You can manually specify the path (feature to be added)

**Download fails:**
- Check your internet connection
- Verify GitHub is accessible
- The release URL may have changed - check the repository

**Installation fails:**
- Ensure you have write permissions to the Ghidra Extensions directory
- Close Ghidra before running the setup script
- Check that the zip file downloaded correctly

**Extension doesn't appear:**
- Restart Ghidra completely
- Check `File → Configure → Extensions` to see if it's listed
- Verify the extension directory exists and contains required files

---

## 📝 License

MIT License - See main project LICENSE file
