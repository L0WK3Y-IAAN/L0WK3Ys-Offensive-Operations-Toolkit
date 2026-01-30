# 📦 Android Backup Extractor  

**Extract & Convert `.ab` Android Backup Files for Analysis**  

🔹 **Author**: L0WK3Y  
🔹 **Category**: Mobile Reverse Engineering  
🔹 **License**: MIT  

---

## 🎯 Overview  
The **Android Backup Extractor** is a Python script that allows users to extract `.ab` (Android Backup) files, convert them into `.tar` format, and extract their contents. This tool is useful for **mobile forensic analysis**, **application data recovery**, and **reverse engineering**.  

---

## 🚀 Features  
✅ **Automatically detects `.ab` files** in the root and `src/` directories  
✅ **Converts** Android backup files to `.tar` format  
✅ **Handles both compressed & uncompressed backups**  
✅ **Extracts `.tar` contents** into structured directories  
✅ **Deletes temporary `.tar` files** after extraction  
✅ **Interactive file selection** for ease of use  
✅ **Color-coded CLI output** using `colorama` for better readability  

---

## 🛠️ Prerequisites  

Ensure you have the following installed before running the script:  

### 📌 **Requirements**  
- Python 3.x  
- `colorama` for enhanced terminal output  
  ```sh
  pip install colorama
  ```
---

## 🔧 Usage  

### **Run the Script**  
To extract an `.ab` file and its contents:  

```sh
python android_backup_extractor.py
```

### **How it Works**  
1. The script scans the root and `src/` folders for `.ab` backup files.  
2. It prompts the user to select a file for extraction.  
3. Converts the `.ab` backup to `.tar`, decompressing if necessary.  
4. Extracts the `.tar` contents into `src/output/<backup_name>/`.  
5. Deletes the temporary `.tar` file after extraction.  

---

## 🔍 Example Output  

```sh
=== Android Backup Extractor ===

[*] Found the following .ab backups:
[1] src/device_backup.ab

[?] Select a file to extract (number): 1
[+] Selected Backup: src/device_backup.ab
[*] Backup version: 5, Compression: Yes
[*] Decompressing backup...
[+] Converted src/device_backup.ab -> src/output/device_backup.tar
[*] Extracting src/output/device_backup.tar to src/output/device_backup/...
[+] Extracted src/output/device_backup.tar -> src/output/device_backup/
[+] Deleted temporary file: src/output/device_backup.tar

[✓] All done! Extracted files are in: src/output/device_backup/
```

---

## 🛠️ Troubleshooting  

### ❌ **Error: "Not a valid Android backup file!"**  
🔹 **Fix:** Ensure the `.ab` file is a valid Android backup and not a corrupted or partial file.  

### ❌ **Error: "No .ab files found!"**  
🔹 **Fix:** Move your `.ab` file into the root or `src/` directory and rerun the script.  

---

## 🎯 Use Cases  

✅ **Forensics** – Analyze extracted app data for forensic investigations.  
✅ **Reverse Engineering** – Examine app data for security research.  
✅ **Data Recovery** – Restore lost or deleted app data from backups.  
✅ **CTF Challenges** – Useful for Capture The Flag (CTF) forensic analysis.  

---

## 📜 License  
This project is licensed under the **MIT License** – feel free to modify and use it as needed.  

---

## 🤝 Contributing  
💡 **Want to improve this tool?** Feel free to open an issue or submit a pull request!  


Happy Hacking! 🔥