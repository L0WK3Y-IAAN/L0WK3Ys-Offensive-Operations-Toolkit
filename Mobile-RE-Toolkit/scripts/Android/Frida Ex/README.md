# FridaEX - Frida Automation Tool 🚀  


**FridaEX is an automation tool designed to simplify Frida script injection for Android applications. It automatically detects connected devices, manages Frida server installation and execution, lists installed apps, and allows seamless Frida script injection. The tool also provides an interactive Frida shell after injection for real-time debugging and analysis.**

## **Features**
✅ **Automated Device & Process Detection** – Lists connected devices and running processes.  
✅ **Frida Server Management** – Checks if Frida server is running, installs it if missing, and starts it automatically.  
✅ **Package Enumeration** – Lists all installed applications on the device and allows selection.  
✅ **Frida Script Execution** – Lets you choose a Frida script from a predefined directory and inject it into an app.  
✅ **Interactive Frida Shell** – Attaches or spawns the app with Frida and provides an interactive debugging shell.  
✅ **Cross-Platform Compatibility** – Works on Windows, Linux, and macOS.  

---

## **Installation**
### **🔹 Prerequisites**
Before running FridaEX, ensure you have the following installed:
- Python 3.x
- **Frida & Frida-Tools**
  ```sh
  pip install frida frida-tools rich requests
  ```
- **ADB (Android Debug Bridge)** installed and accessible via `$PATH`.  
  - **Windows:** Install [ADB](https://developer.android.com/studio/releases/platform-tools) and add it to `System Variables`.
  - **Linux/macOS:** Install via:
    ```sh
    sudo apt install adb  # Debian-based
    brew install android-platform-tools  # macOS
    ```


### **🔹 Grant Execution Permissions**
If running on **Linux/macOS**, you may need to grant execution permissions:
```sh
chmod +x frida_ex.py
```

---

## **Usage**
### **🔹 Running FridaEX**
To start the tool, execute:
```sh
python frida_ex.py
```

### **🔹 Steps**
1️⃣ **Select a device** from the list of connected devices.  
2️⃣ **Ensure Frida Server is running** (auto-installs if missing).  
3️⃣ **Choose an installed application** from the list.  
4️⃣ **Select a Frida script** from the predefined `frida scripts` directory.  
5️⃣ **Launch interactive Frida shell** for real-time analysis.  

---

## **How It Works**
### **1️⃣ Device Detection**
FridaEX first **enumerates connected devices** using `frida.enumerate_devices()`. If no devices are found, it exits.

### **2️⃣ Checking/Starting Frida Server**
- Uses `adb shell pidof frida-server` to check if Frida server is running.
- If not running, it:
  - Searches `/data/local/tmp/frida-server`.
  - Attempts to start Frida server.
  - If missing, **downloads & installs Frida server** from GitHub.

### **3️⃣ Package Enumeration**
- Uses `adb shell pm list packages` to retrieve all installed applications.
- Displays them in a numbered table for easy selection.

### **4️⃣ Frida Script Injection**
- Lists available `.js` scripts in `scripts/Frida Ex Wip/frida scripts/`.
- Lets the user select a script for injection.
- **Spawns or attaches** to the selected application:
  - **If app is NOT running:** Uses `frida -U -f <package> -l <script.js>` to spawn.
  - **If app is already running:** Uses `frida -U -n <package> -l <script.js>` to attach.

### **5️⃣ Interactive Frida Shell**
- Provides an **interactive Frida session** after script injection.
- Allows users to explore the app's memory, hooks, and functions in real-time.

---

## **Example Usage**
### **🔹 Start FridaEX**
```sh
python frida_ex.py
```
### **🔹 Select a Device**
```
📱 Available Devices:
┏━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Index ┃ Device ID     ┃ Type    ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│   1   │ emulator-5554 │ USB     │
└───────┴───────────────┴─────────┘
```
✅ **Enter device number to continue.**

### **🔹 Ensure Frida Server is Running**
```
🔍 Checking if Frida server is running...
❌ Frida server is NOT running.
🔍 Checking if Frida server exists in /data/local/tmp...
✅ Frida server found. Attempting to start it...
✅ Frida server successfully started!
```

### **🔹 Select an Application**
```
🔍 Retrieving installed packages...
┏━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Index ┃ Package Name                 ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   1   │ com.example.app               │
│   2   │ com.android.settings          │
└───────┴──────────────────────────────┘
```
✅ **Enter the number of the package to analyze.**

### **🔹 Choose a Frida Script**
```
📜 Available Frida Scripts:
┏━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Index ┃ Script Name                   ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   1   │ dump_credentials.js            │
│   2   │ bypass_ssl.js                   │
└───────┴────────────────────────────────┘
```
✅ **Enter the script number to inject.**

### **🔹 Injection & Frida Shell**
```
🚀 Ensuring com.example.app is running before injection...
✅ App is already running. Attaching Frida...

    ____  
   / _  |   Frida 16.6.6 - Dynamic Instrumentation Toolkit
  | (_| |  
   > _  |   Commands:
  /_/ |_|       help -> Show help
                exit -> Quit session
                object? -> Inspect object

Connected to Android Emulator 5554 (id=emulator-5554)
[Android Emulator 5554::com.example.app] ->
```
🎉 **You're now inside an interactive Frida shell!**

---

## **Supported Frida Scripts**
📂 **Place your Frida scripts (`.js`) inside:**
```sh
scripts/Frida Ex Wip/frida scripts/
```
💡 Some common **Frida scripts** you can use:
- `dump_credentials.js` – Hooks into credential fields and logs entered passwords.
- `bypass_ssl.js` – Disables SSL pinning for security testing.
- `trace_functions.js` – Traces all function calls in an app.
- `hook_java_methods.js` – Hooks and logs Java method calls dynamically.

---

## **Troubleshooting**
### **❌ Frida Server Not Starting**
- Ensure **ADB debugging** is enabled on the target device.
- Try **manually starting Frida server**:
  ```sh
  adb shell /data/local/tmp/frida-server &
  ```
- Reinstall Frida server:
  ```sh
  python frida_ex.py --install-frida
  ```

### **❌ App Not Spawning in Frida**
- Some apps prevent spawning; try **attaching instead**:
  ```sh
  frida -U -n com.example.app -l script.js
  ```
- If the app crashes, try spawning **without suspending**:
  ```sh
  frida -U -n com.example.app --no-pause -l script.js
  ```

---

## **Contributing**
💡 **Want to improve FridaEX?**  
- Fork the repository and submit a pull request.
- Add more Frida scripts to enhance functionality.
- Report any issues you encounter in the **Issues** section.

---

## **License**
📜 **MIT License** – Free to use, modify, and distribute.

---

🚀 **Enjoy hacking with FridaEX!**  
🎯 **By L0WK3Y** | [GitHub](https://github.com/L0WK3Y-IAAN)