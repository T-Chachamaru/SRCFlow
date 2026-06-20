# Targets

Each target should live in its own directory to keep scope and context isolated.

Recommended commands:

```powershell
python ai_src.py init-target demo --wizard
python ai_src.py audit-target demo --config demo
python ai_src.py crawl demo --config demo --mode pages --threads 10 --depth 2
python ai_src.py extract demo --config demo
python ai_src.py status demo
```

For scripted setup, `init-target` still accepts `--domain`, `--seed`, and `--config`, but the wizard is preferred for complete scope and config capture.

At Agent startup, audit the target, summarize existing scope/config/auth profile names, ask only for missing or explicitly changed configuration, then continue the soft loop.

Do not run active testing against unauthorized targets.
