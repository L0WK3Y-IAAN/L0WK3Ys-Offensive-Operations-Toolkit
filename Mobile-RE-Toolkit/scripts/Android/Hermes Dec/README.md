# 📌 Hermes Bytecode Decompiler

**Decompiles React Native Hermes bytecode bundles from extracted APKs**

🔹 **Author**: L0WK3Y  
🔹 **Category**: Mobile Reverse Engineering / React Native Analysis  
🔹 **License**: MIT

---

## 🎯 Overview

The **Hermes Bytecode Decompiler** automatically scans for React Native Hermes bundle files (`index.android.bundle`) in APK extraction directories and decompiles them using the [hermes-dec](https://github.com/P1sec/hermes-dec) tool.

✅ **Automatically scans** `src/output/` for Hermes bundle files  
✅ **Lists bundles by package name** with fuzzy search  
✅ **Auto-clones hermes-dec** tool if not present  
✅ **Decompiles to disassembly and pseudo-code**  
✅ **Outputs results** to the extraction directory

---

## 🛠️ Features

### 🔍 **Bundle Discovery**
- Recursively scans `src/output/` for `index.android.bundle` files
- Expected location: `<PACKAGE_NAME>_EXTRACTION/source/resources/assets/index.android.bundle`
- Lists all found bundles by package name

### 📋 **Interactive Selection**
- Rich table display showing all available bundles
- Number-based selection (type `1`, `2`, `3`, etc.)
- Fuzzy search by package name
- Tab completion support

### 🔧 **Automatic Tool Setup**
- Automatically clones `hermes-dec` to `Mobile-RE-Toolkit/Tools/hermes-dec` if not present
- Uses Git to clone from the official repository
- Verifies tool installation before proceeding

### 📝 **Decompilation Process**
1. **File Parser** - Extracts and displays bundle file headers
2. **Disassembler** - Converts bytecode to assembly (`.hasm` format)
3. **Decompiler** - Converts bytecode to pseudo-code (`.js` format)

### 📊 **Output Location**
Results are saved to:
```
<PACKAGE_NAME>_EXTRACTION/hermes_decompiled/
├── file_headers.txt      # Bundle file headers
├── disassembly.hasm      # Disassembled bytecode
└── decompiled.js         # Decompiled pseudo-code
```

---

## 🔧 Usage

### **Prerequisites**
- Python 3.10+
- Git (for cloning hermes-dec)
- APK extraction directory with Hermes bundle files

### **Run the Script**

```sh
python hermes_dec.py
```

The script will:
1. Check for `hermes-dec` tool (clone if needed)
2. Scan `src/output/` for bundle files
3. Display a table of available bundles
4. Prompt for selection
5. Decompile the selected bundle

### **Selection Methods**

**By Number:**
```
Enter # or start typing package name: 1
```

**By Package Name (Fuzzy Search):**
```
Enter # or start typing package name: com.example
```

---

## 📁 Expected Directory Structure

```
Mobile-RE-Toolkit/
├── src/
│   └── output/
│       ├── com.example.app_EXTRACTION/
│       │   └── source/
│       │       └── resources/
│       │           └── assets/
│       │               └── index.android.bundle  ← Found here
│       └── another.app_EXTRACTION/
│           └── source/
│               └── resources/
│                   └── assets/
│                       └── index.android.bundle
└── Tools/
    └── hermes-dec/  ← Auto-cloned here
        ├── hbc_file_parser.py
        ├── hbc_disassembler.py
        └── hbc_decompiler.py
```

---

## 📖 About Hermes

**Hermes** is a JavaScript engine optimized for React Native applications. Since React Native 0.70, Hermes is the default compilation target for Android apps.

Hermes bytecode files are typically located at:
```
assets/index.android.bundle
```

These files are compiled JavaScript bytecode, not plain JavaScript, which is why specialized tools like `hermes-dec` are needed for reverse engineering.

---

## 🔗 References

- [hermes-dec GitHub](https://github.com/P1sec/hermes-dec) - The decompiler tool used by this script
- [React Native Hermes Documentation](https://reactnative.dev/docs/hermes)
- [Hermes VM Design Documents](https://github.com/facebook/hermes)

---

## ⚠️ Notes

- The decompiled output is **pseudo-code** and may not be valid JavaScript
- Some complex React Native apps may have obfuscated or minified code
- The disassembly (`.hasm`) format is useful for understanding the bytecode structure
- Results are saved in the same extraction directory for easy access

---

## 🐛 Troubleshooting

**No bundles found:**
- Ensure APKs have been extracted to `src/output/`
- Check that the extraction includes the `source/resources/assets/` directory
- Verify the bundle file is named `index.android.bundle`

**Git clone fails:**
- Ensure Git is installed and in PATH
- Check internet connection
- Verify GitHub access

**Decompilation errors:**
- Some Hermes bytecode versions may not be fully supported
- Check the hermes-dec repository for version compatibility
- Review error messages for specific issues

---

## 📝 License

MIT License - See main project LICENSE file
