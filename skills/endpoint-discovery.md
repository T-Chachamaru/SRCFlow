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
6. When authorized, add more URL seeds with katana for each high-value in-scope seed, SPA route, or page family:
   - `python ai_src.py katana-crawl <target> <seed-url>`
7. Collect:
   - API hosts and domain keywords.
   - Base paths and endpoint path patterns.
   - Static asset hosts and chunk naming patterns.
   - Request wrappers and dynamic path construction.
   - Query keys, JSON body keys, and auth header names.
   - SPA routes that reveal more pages to visit.
8. Keep `targets/<target>/state/katana_seeds.txt` as a crawl input. The main crawl includes it automatically unless `--no-katana-seeds` is passed.
9. Update `config/<target>.json`.
10. Run `python ai_src.py validate-config <target>`.

## Phase 2: Crawl

Run:

```powershell
python ai_src.py crawl <target> --config <target> --depth 2 --threads 10 --mode pages
```

If `katana-crawl` has run, this command automatically adds scoped katana URLs from `targets/<target>/state/katana_seeds.txt`.

Adjust depth, threads, cookies, and rendering only within scope and safety limits.
Use `--profile` for common katana modes and `--` passthrough for advanced native katana options when route coverage needs it; passthrough cannot override target, output, scope, rate, or concurrency.

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
   When importing HAR files, prefer `python ai_src.py import-har <file.har> --workspace-target <target> --as-endpoints` so requests are filtered through `targets/<target>/scope.md`.
5. If a small API route search space is justified, use `ffuf-safe` with a narrow list from `payloads/src-payload/fuzzing/api-paths/`.
6. If high-value routes or JS bundles look missing, run `katana-crawl` against the relevant in-scope route, rerun `crawl`, then rerun extraction.
7. Add missing patterns to config.
8. Rerun extraction. The command writes automatic snapshots under `targets/<target>/state/snapshots/`.
9. Compare rounds with `diff-endpoints` using the printed snapshot paths.
10. Run `python ai_src.py metrics <target>` when deciding whether discovery is converging. Treat hints as soft guidance; do not repeat or stop only because a metric says so.

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
- Miss source: Network, katana, JS review, HTML review, manifest, links, or HAR.
- Config changes and rationale.
- False-positive patterns and filters.
- Next pages or files to inspect.
- Snapshot paths compared.
- Metrics or flywheel notes that changed the next prompt/config decision.
