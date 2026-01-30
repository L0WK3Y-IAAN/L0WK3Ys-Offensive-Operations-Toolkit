# 📌 Android APK String Extractor  

**Extracts readable strings from decompiled APKs and DEX files**  

🔹 **Author**: L0WK3Y  
🔹 **Category**: Mobile Reverse Engineering / APK Analysis  
🔹 **License**: MIT  

---

## 🎯 Overview  

The **Android APK String Extractor** automates the process of decompiling APKs and extracting **printable ASCII strings** from files within the APK. This tool is useful for **reverse engineering**, **malware analysis**, and **security research**.  

✅ **Automatically detects APKs** in root and `src/` folders  
✅ **Uses `apktool`** to decompile APKs into readable files  
✅ **Recursively extracts** strings from all decompiled files  
✅ **Filters printable ASCII strings** with a configurable length  
✅ **Outputs results in CSV format** for easy analysis  

---

## 🛠️ Features  

### 🔍 **APK Selection**  
- Automatically scans for APKs in the **current directory** and `src/` folder  
- Prompts the user to select an APK if no path is provided  

### 🔄 **Decompilation with apktool**  
- Uses `apktool` to **fully decompile** the selected APK  
- Cleans up previous extraction folders to ensure fresh results  

### 📑 **String Extraction**  
- Recursively scans **all files** in the decompiled APK  
- Extracts **printable ASCII strings**  
- Filters strings based on **minimum length** (default: 4 characters)  

### 📊 **CSV Output**  
- Saves extracted strings to a CSV file in:  

  ```
  src/output/{APK_NAME}_EXTRACTION/{APK_NAME}_strings.csv
  ```
- CSV Format:  

  | File Path | Extracted String |
  |-----------|-----------------|
  | smali/com/example/Main.smali | secret_api_key |
  | res/values/strings.xml | admin_password |

---

## 🔧 Usage  

### **Run the Script**  

To analyze an APK:  

```sh
python string_extraction.py
```

To analyze a specific APK or folder:  

```sh
python string_extraction.py my_app.apk
```

To set a custom **minimum string length** (default is 4 characters):  

```sh
python string_extraction.py my_app.apk --min-length 6
```

---

## 📄 Example Output  

```sh
📦 Available APKs:
  [1] src/malicious_app.apk
  [2] src/safe_app.apk

🔹 Select an APK by number: 1
🔍 Decompiling APK: src/malicious_app.apk -> src/output/malicious_app_EXTRACTION

📑 Extracting strings from: src/output/malicious_app_EXTRACTION
✅ Extracted strings saved to: src/output/malicious_app_EXTRACTION/malicious_app_strings.csv
```

---

## 📌 Use Cases  

✅ **Pentesting** – Extract hardcoded secrets, API keys, and credentials  
✅ **Reverse Engineering** – Analyze decompiled APKs for hidden functionality  
✅ **Malware Analysis** – Identify malicious strings, URLs, or obfuscation patterns  
✅ **Forensics** – Recover embedded data from Android applications  

---

## ⚙️ Troubleshooting  

### ❌ **apktool not found!**  
🔹 **Fix:** Install `apktool` and ensure it's in your system's PATH.  

```sh
apt install apktool  # Debian-based (Kali, Ubuntu)
brew install apktool  # macOS
```

### ❌ **No APKs found!**  
🔹 **Fix:** Ensure your target APK is in the root folder or `src/` folder.  

```sh
mv my_app.apk src/
python string_extraction.py
```

### ❌ **No strings extracted!**  
🔹 **Fix:** Try lowering the minimum string length with `--min-length 3`.  

---

## 📜 License  
This project is licensed under the **MIT License** – feel free to modify and use it as needed.  


Happy Hunting! 🚀