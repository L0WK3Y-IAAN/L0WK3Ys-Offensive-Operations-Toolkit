# APK Puller

**This script allows you to list and extract APKs from a connected Android device using `adb`.** It provides options to:
- List installed applications.
- Filter out system/default applications.
- Select an application and pull its APK to your local system.

## 🚀 Features
- 📜 **Lists all installed packages** on the device.
- 🔍 **Filters out system apps** like `com.google`, `com.android`, etc.
- 🎛️ **Interactive selection** to choose which APK to pull.
- ⚡ **Multithreaded APK path retrieval** for faster performance.
- 📂 **Saves APKs in** `src/output/pulled_apks`.

## 📋 Requirements
- Python 3.x
- `adb` (Android Debug Bridge) installed and accessible from the command line.
- Device with **USB Debugging enabled** or **wireless ADB connection**.
- Install required Python dependencies:
  ```sh
  pip install rich
  ```

## 🔧 Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/apk-puller.git
   cd apk-puller
   ```
2. Ensure `adb` is installed and accessible:
   ```sh
   adb devices
   ```
   If your device appears in the list, you're good to go!

## 📌 Usage
1. **Run the script:**
   ```sh
   python apk_puller.py
   ```
2. **Choose filtering options:**
   - You will be prompted to exclude system applications.
   - The script will display a numbered list of installed APKs.
3. **Select an APK to pull:**
   - Enter the corresponding number to extract the APK.
   - The APK will be saved in `src/output/pulled_apks/`.

### 🎯 Example Run
```
[*] Checking connected devices...
[*] Would you like to filter out system-related packages (com.google, com.android, etc.)? (y/N): y

📋 Installed Applications:
--------------------------------------------------------
| Index | Package                                      |
--------------------------------------------------------
| 1     | com.example.myapp                            |
| 2     | com.someapp.tool                            |
--------------------------------------------------------
Enter the number of the APK you want to pull: 2
📦 Pulling APK: com.someapp.tool -> src/output/pulled_apks/com.someapp.tool.apk
✔ Successfully pulled com.someapp.tool.apk to src/output/pulled_apks
```

## 🛠 Troubleshooting
- **No devices found?**
  - Ensure your device is connected via USB and **USB Debugging is enabled**.
  - If using wireless ADB, connect using:
    ```sh
    adb connect <device_ip>:5555
    ```
  - Restart ADB:
    ```sh
    adb kill-server
    adb start-server
    ```

- **APK path not found?**
  - Some system apps or hidden apps may not be accessible without root.

## 📜 License
This project is licensed under the MIT License. See `LICENSE` for details.

## 📬 Contact
For any issues or contributions, feel free to open an issue or submit a pull request on GitHub.

