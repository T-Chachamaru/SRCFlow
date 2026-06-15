Endpoint discovery must converge through iteration; never trust a single script pass.

# Endpoint Discovery Workflow

## Goal

Recover API hosts, base paths, endpoints, methods, parameters, and auth patterns from authorized HTML/JS/SPA assets.

## Phase 1: Browser Network Sampling

Before crawling:

1. Read the target scope.
2. Run `python ai_src.py tools` and identify which optional CLI tools are available.
3. Visit multiple allowed seed domains with the browser MCP.
4. Open representative SPA and HTML pages.
5. Exercise normal read-only workflows with approved test accounts when available.
6. When authorized, add more seeds with:
   - `python ai_src.py subdomains <target> <domain>`
   - `python ai_src.py httpx-live <target> targets/<target>/state/subdomains.txt`
   - `python ai_src.py katana-crawl <target> <seed-url>`
7. Collect:
   - API hosts and domain keywords.
   - Base paths and endpoint path patterns.
   - Static asset hosts and chunk naming patterns.
   - Request wrappers and dynamic path construction.
   - Query keys, JSON body keys, and auth header names.
   - SPA routes that reveal more pages to visit.
8. Update `config/<target>.json`.
9. Run `python ai_src.py validate-config <target>`.

## Phase 2: Crawl

Run:

```powershell
python ai_src.py crawl <target> --config <target> --depth 2 --threads 10 --mode pages
```

Adjust depth, threads, cookies, and rendering only within scope and safety limits.

## Phase 3: Extract And Review

1. Run:
   `python ai_src.py extract <target> --config <target>`
2. Rank files:
   `python ai_src.py rank-js targets/<target>/raw/remote_sites --limit 30`
3. Review high-value JS/HTML files for:
   - `baseURL`
   - `fetch`
   - `axios`
   - `request`
   - `service`
   - `api`
   - `router`
   - `path`
   - `url`
   - dynamic string concatenation
4. Compare extracted endpoints with browser Network observations.
5. Add missing patterns to config.
6. Rerun extraction. The command writes automatic snapshots under `targets/<target>/state/snapshots/`.
7. Compare rounds with `diff-endpoints` using the printed snapshot paths.

## Phase 4: Convergence

Stop endpoint discovery when two consecutive rounds produce only duplicates, known endpoints, or low-value false positives.

## Config Fields

- `target_keywords`: target domains or domain keywords.
- `extra_seeds`: known entry URLs.
- `api_prefixes`: prefixes that make a relative path API-like.
- `api_path_regexes`: API path classification regexes.
- `extract_patterns`: regexes with `(?P<endpoint>...)`.
- `known_endpoints`: low-risk endpoints worth checking even if not linked.
- `garbage_substrings`: obfuscation false-positive filters.

## Checkpoint Fields

Each round should record:

- Newly discovered endpoint count.
- Miss source: Network, JS review, HTML review, manifest, links, or HAR.
- Config changes and rationale.
- False-positive patterns and filters.
- Next pages or files to inspect.
- Snapshot paths compared.
