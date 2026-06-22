# Tools

Portable CLI tools should be placed in `tools/bin`.

Install or refresh:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_tools.ps1
python ai_src.py tools
```

The installer tries existing `PATH`, local Go/Python script locations, `go install`, GitHub release archives, and Python `pip` where appropriate.

If a tool still cannot be installed, `tools/TO_DOWNLOAD.txt` lists what to install and where to place it.

The workspace wrappers prefer `tools/bin` before `PATH`:

- `python ai_src.py gau-urls <target> <domain>` uses `gau` for broad passive historical URL discovery.
- `python ai_src.py paramspider-urls <target> <domain>` uses `paramspider` for passive parameterized URL discovery.
- `python ai_src.py katana-crawl <target> <url>` uses `katana` for live scoped crawling and seed enrichment.
- `python ai_src.py ffuf-safe <target> <url> <wordlist>` uses `ffuf` for narrow scoped fuzzing questions.

Local wordlists and payload references are under `payloads/src-payload/`. Read `payloads/src-payload/README.md` before selecting a list.

## Passive Discovery

```powershell
python ai_src.py gau-urls demo example.com --fp
python ai_src.py paramspider-urls demo example.com
```

Passive wrappers write:

- `targets/demo/state/gau_urls.txt`
- `targets/demo/state/paramspider_urls.txt`
- `targets/demo/state/passive_urls.txt`
- `targets/demo/state/passive_seeds.txt`
- `targets/demo/state/passive_params.json`

`crawl` consumes `state/passive_seeds.txt` automatically unless `--no-passive-seeds` is passed.

## Live Crawl And Fuzzing

```powershell
python ai_src.py katana-crawl demo https://example.com --profile routes -- -iqp
python ai_src.py ffuf-safe demo https://example.com/api/FUZZ .\payloads\src-payload\fuzzing\api-paths\api路径\API字典.txt --profile paths -- -fc 404
```

`katana-crawl` writes scoped crawl seeds to `targets/<target>/state/katana_seeds.txt`; `crawl` consumes that file automatically.

`ffuf-safe` accepts `FUZZ` in the URL, `--header`, or `--data`, then writes reviewed candidates to `targets/<target>/state/ffuf_candidates.json`.

Both katana and ffuf wrappers support small profiles plus native passthrough. The passthrough area keeps native tool flexibility, but the wrapper rejects arguments that would override target URL, output path/format, scope, rate, concurrency, or raw request execution. Use `--process-timeout 0` only when a long authorized run is intentional.

These wrappers are signal generators only. Their output must be manually verified before it can influence a report.
