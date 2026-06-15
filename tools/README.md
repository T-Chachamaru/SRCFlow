# Tools

Portable CLI tools should be placed in `tools/bin`.

Install or refresh:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_tools.ps1
python ai_src.py tools
```

The installer tries:

1. Existing `PATH`.
2. Existing `%USERPROFILE%\go\bin`.
3. `go install`.
4. GitHub latest release Windows amd64 zip.

If a tool still cannot be installed, `tools/TO_DOWNLOAD.txt` lists what to download and where to place it.

The workspace wrappers prefer `tools/bin` before `PATH`:

- `python ai_src.py subdomains <target> <domain>` uses `subfinder`.
- `python ai_src.py httpx-live <target> <input>` uses `httpx`.
- `python ai_src.py katana-crawl <target> <url>` uses `katana`.
- `python ai_src.py ffuf-safe <target> <url-with-FUZZ> <wordlist>` uses `ffuf`.
- `python ai_src.py nuclei-safe <target> <url>` uses `nuclei`.

These wrappers are signal generators only. Their output must be manually verified before it can influence a report.
