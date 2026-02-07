# Android Screen Mirror

Mirror an Android device screen to your computer using [scrcpy](https://github.com/Genymobile/scrcpy). Part of the Mobile-RE-Toolkit.

## Requirements

- **Python 3**
- **ADB** – either on your PATH or bundled with the auto-installed scrcpy
- **Android device** – USB debugging enabled and authorized

## Supported platforms

- **Linux** – x86_64
- **macOS** – ARM64 (Apple Silicon) and x86_64 (Intel)

## Usage

```bash
python screen_mirror.py
```

1. **scrcpy** – If `scrcpy` is not on your PATH, the script downloads the matching scrcpy release (v3.3.4) into a local `scrcpy-tool` directory in the current working directory.
2. **Device list** – Connected ADB devices are listed with serial and model.
3. **Selection** – Choose a device by number.
4. **Mirror** – scrcpy launches for that device. Output is logged to `scrcpy_<serial>.log`.

## Binary preference

1. Local binary: `./scrcpy-tool/scrcpy` (created by the script if it installs scrcpy).
2. System: `scrcpy` from your PATH.

## Notes

- On macOS, quarantine attributes are removed from the downloaded binaries so they can run.
- Log files (`scrcpy_*.log`) are written in the directory where you run the script.
