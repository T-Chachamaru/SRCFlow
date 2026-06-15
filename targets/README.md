# Targets

Each target should live in its own directory to keep scope and context isolated.

Recommended commands:

```powershell
python ai_src.py init-target demo --domain example.com --seed https://www.example.com/ --config default
python ai_src.py crawl demo --config demo --mode pages --threads 10 --depth 2
python ai_src.py extract demo --config demo
python ai_src.py status demo
```

Do not run active testing against unauthorized targets.
