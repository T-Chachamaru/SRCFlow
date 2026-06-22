Endpoint discovery must converge through iteration; never trust a single script pass.

# Endpoint Discovery Workflow

## Goal

Recover API hosts, base paths, endpoints, methods, parameters, auth patterns, and normal request sources from authorized browser traffic, HTML/JS/SPA assets, and passive URL archives.

## Phase 1: Browser Network Sampling

Before crawling:

1. If the target workspace is incomplete, use `python ai_src.py init-target <target> --wizard` or `skills/target-setup.md` first. Do not guess scope; store credentials/session material only in local ignored auth profiles.
2. Run `python ai_src.py audit-target <target> --config <target>` when a target config exists, otherwise run `python ai_src.py audit-target <target>`.
3. Resolve audit blockers through narrow user questions only when the Agent cannot infer the answer safely.
4. Read the target scope.
5. Run `python ai_src.py tools` and identify which optional CLI tools are available.
6. Read auth profiles with `python ai_src.py auth-profiles <target> --show-secrets` when approved credentials/session values are needed for browser login or authenticated requests.
7. Visit multiple allowed seed domains with the browser MCP.
8. Open representative SPA and HTML pages.
9. Exercise normal workflows with approved test accounts when available. Do not skip this: normal traffic is the best source of required parameters, resource IDs, CSRF behavior, tenant keys, and success indicators.
10. Export or otherwise capture useful browser traffic and import it:
    `python ai_src.py import-har <file.har> --workspace-target <target> --as-endpoints --as-recipes`
11. Collect:
    - API hosts and domain keywords.
    - Base paths and endpoint path patterns.
    - Static asset hosts and chunk naming patterns.
    - Request wrappers and dynamic path construction.
    - Query keys, JSON body keys, and auth header names.
    - SPA routes that reveal more pages to visit.
    - Request recipes that represent known-good normal behavior.

## Phase 2: Passive URL And Parameter Enrichment

Use passive archive tools early, before the main crawl, and again when discovery stalls.

- gau is broad URL history across public providers:
  `python ai_src.py gau-urls <target> <domain> --fp`
- ParamSpider is focused on parameterized historical URLs:
  `python ai_src.py paramspider-urls <target> <domain>`

The wrappers scope-filter output and write:

- `targets/<target>/state/gau_urls.txt`
- `targets/<target>/state/paramspider_urls.txt`
- `targets/<target>/state/passive_urls.txt`
- `targets/<target>/state/passive_seeds.txt`
- `targets/<target>/state/passive_params.json`

Read `state/passive_params.json` before parameter fuzzing. If passive URLs reveal useful route families, update config or use them as crawl enrichment.

## Phase 3: Live URL Enrichment

When authorized, add more URL seeds with katana for each high-value in-scope seed, SPA route, or page family:

```powershell
python ai_src.py katana-crawl <target> <seed-url>
```

Use `--profile` for common katana modes and `--` passthrough for advanced native katana options when route coverage needs it. Passthrough cannot override target, output, scope, rate, or concurrency.

`katana-crawl` writes `targets/<target>/state/katana_seeds.txt`.

## Phase 4: Crawl

Run:

```powershell
python ai_src.py crawl <target> --config <target> --depth 2 --threads 10 --mode pages
```

`crawl` automatically includes scoped katana seeds and passive seeds:

- `state/katana_seeds.txt`, unless `--no-katana-seeds` is passed.
- `state/passive_seeds.txt`, unless `--no-passive-seeds` is passed.

Adjust depth, threads, cookies, auth profile, and rendering only within scope.

## Phase 5: Extract And Review

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
4. Compare extracted endpoints with browser Network observations, request recipes, and passive URL/parameter inventory.
5. If a small API route search space is justified, use `ffuf-safe` with a narrow list from `payloads/src-payload/fuzzing/api-paths/`.
6. If high-value routes or JS bundles look missing, rerun the relevant passive/katana step, update config, rerun `crawl`, then rerun extraction.
7. Add missing patterns to config.
8. Rerun extraction. The command writes automatic snapshots under `targets/<target>/state/snapshots/`.
9. Compare rounds with `diff-endpoints` using the printed snapshot paths.
10. Run `python ai_src.py metrics <target>` when deciding whether discovery is converging. Treat hints as soft guidance; do not repeat or stop only because a metric says so.

## Phase 6: Convergence

Endpoint discovery is converging when two consecutive rounds produce only duplicates, already-reviewed endpoints, or low-value false positives, and passive parameter names are no longer producing meaningful new normal flows or attack-surface leads.

Before leaving discovery, confirm:

- Representative normal request recipes exist for high-value endpoint families, or the reason they cannot be captured is logged.
- `state/passive_params.json` has been reviewed for parameter names that map to current endpoint families.
- High-score JS/HTML files have been reviewed.
- Browser Network observations and extracted endpoints are reconciled.

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
- Miss source: Network, gau, ParamSpider, katana, JS review, HTML review, manifest, links, or HAR.
- Config changes and rationale.
- Passive parameter names that affected direction.
- Request recipes imported or still missing.
- False-positive patterns and filters.
- Next pages, files, routes, or normal workflows to inspect.
- Snapshot paths compared.
- Metrics or flywheel notes that changed the next prompt/config decision.
