# Frida Script Downloader

**A Frida Script Downloader that fetches scripts from [codeshare.frida.re](https://codeshare.frida.re). It also supports interactive search with auto-completion**.

## Features

- **Multithreaded Fetching**: Scrapes all pages concurrently to speed up the process.
- **Dynamic Code Extraction**: Uses Selenium to grab scripts embedded in Ace Editor.
- **Interactive Search**: Allows users to search scripts interactively with auto-completion.
- **Rich Table Display**: Displays script results in a structured table format.

## Requirements

Ensure you have the following dependencies installed:

```bash
pip install requests beautifulsoup4 rich prompt_toolkit selenium
```

Additionally, **Google Chrome** and the **Chromedriver** must be installed for Selenium to work.

## Usage

Run the script with:

```bash
python3 frida_script_downloader.py
```

### Steps:
1. The script scrapes all available Frida scripts from `codeshare.frida.re`.
2. Users can search scripts interactively.
3. Once a script is selected, it is downloaded and saved locally in the `scripts/` directory.

## Configuration

- **Thread Pooling**: Uses `ThreadPoolExecutor` to fetch pages concurrently.
- **Dynamic Content Handling**: Falls back to Selenium if static HTML parsing fails.
- **Auto-completion**: Extracts keywords from script titles, authors, and descriptions.

## Example Output

```
Fetching page 1 to detect pagination...
Detected up to page 5
Spawning threads to fetch pages 2..5

Frida Scripts on codeshare.frida.re
---------------------------------------------------------
| Index | Title                  | Author  | Description |
---------------------------------------------------------
| 1     | Bypass SSL Pinning      | JohnDoe | Script to bypass SSL pinning on Android. |
| 2     | Hooking System Calls    | JaneDoe | Hooking system calls using Frida.         |
---------------------------------------------------------

Type your search (press Enter to skip). Auto-completion enabled!
Search Query: SSL

[1] Bypass SSL Pinning - JohnDoe
Enter the number of the script to download (or 'q' to quit): 1
Downloading script: Bypass SSL Pinning
Script saved to: scripts/bypass_ssl_pinning.js
```

## Troubleshooting

- **No scripts found?**  
  Ensure that `codeshare.frida.re` is accessible and not blocking requests.

- **Selenium fails?**  
  Make sure Chrome and `chromedriver` are installed and updated.

## License

This project is licensed under the MIT License.

---

🚀 **Happy Reversing!**
