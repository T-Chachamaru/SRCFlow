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

- `python ai_src.py katana-crawl <target> <url>` uses `katana`.
- `python ai_src.py ffuf-safe <target> <url> <wordlist>` uses `ffuf`.

Local wordlists and payload references are under `payloads/src-payload/`. Read `payloads/src-payload/README.md` before selecting a list.

`katana-crawl` writes scoped crawl seeds to `targets/<target>/state/katana_seeds.txt`; `crawl` consumes that file automatically.

`ffuf-safe` accepts `FUZZ` in the URL, `--header`, or `--data`, then writes reviewed candidates to `targets/<target>/state/ffuf_candidates.json`.

Both wrappers support small profiles plus native passthrough:

```powershell
python ai_src.py katana-crawl demo https://example.com --profile routes -- -iqp
python ai_src.py ffuf-safe demo https://example.com/api/FUZZ .\payloads\src-payload\fuzzing\api-paths\api路径\API字典.txt --profile paths -- -fc 404
```

The passthrough area keeps native tool flexibility, but the wrapper rejects arguments that would override target URL, output path/format, scope, rate, concurrency, or raw request execution.

These wrappers are signal generators only. Their output must be manually verified before it can influence a report.
