Never report: CORS-only findings, missing security headers, version disclosure, Self-XSS, no PoC, or configuration observations without demonstrated impact.

# SRC Quick Card

This project runs on top of existing agent tools such as Codex, Claude Code, and Gemini CLI. The repository provides workspace structure, configuration, prompts, scripts, and quality gates.

## Hard Rules

- No PoC means no vulnerability.
- Report impact, not observations.
- A report must include curl, an executable command, or clear reproducible steps.
- Do not test until the authorization scope is understood.
- Do not delete data, change passwords, send business notifications, or perform destructive actions.
- Do not run high-pressure scans that may affect availability.
- Do not export bulk sensitive data; collect minimum evidence only.
- Do not write reports for best-practice issues below meaningful impact.

## Priority

- Spend most time on IDOR, authorization bypass, tenant isolation, and unauthenticated access.
- More JS/HTML usually means more hidden interfaces.
- If login exists, test horizontal and vertical authorization first.
- If the target is API-heavy, test unauthenticated and low-privilege access first.
- If upload exists, test validation, access control, and retrieval chains.
- If search or filter exists, inspect input validation and sorting parameters.
- If GraphQL exists, inspect schema exposure and authorization on queries/mutations.
- If no entry is obvious, keep mining JS, manifests, routes, source maps, and Network traffic.

## Pattern Sampling Before Crawling

- Run `python ai_src.py tools` before relying on optional CLIs.
- Use browser Network observations before running the crawler.
- Visit multiple allowed seed domains, SPA routes, and HTML pages.
- Collect API host keywords, base paths, request wrappers, asset hosts, JS chunk patterns, query keys, body keys, and auth header names.
- When authorized, use conservative wrappers for more seeds: `subdomains`, `httpx-live`, and `katana-crawl`.
- Translate observations into `config/<target>.json`.
- Validate config before crawling.

## Endpoint Discovery Loop

- Never trust one extraction pass.
- Crawl HTML/JS after config is seeded from browser Network patterns.
- Run extraction, rank JS/HTML, review high-value files, compare against Network observations, update config, and rerun.
- Use the automatic endpoint snapshots from `extract` when comparing rounds with `diff-endpoints`.
- Stop only when new endpoint discovery clearly converges.

## Per-Endpoint Loop

Use `skills/endpoint-testing.md` for detailed endpoint verification and result recording.

1. Find parameters from JS/HTML, HAR/Network, request bodies, query strings, and response fields.
2. Determine endpoint function.
3. Choose likely attack surface.
4. Verify safely with approved accounts and minimum requests.
5. Record status and evidence.
6. Reflect on the result and choose the next endpoint.

## High-Value Clues

- `userId`, `uid`, `ownerId`, `tenantId`, `orgId`, `deptId`.
- `fileId`, `recordId`, `taskId`, `orderId`, `projectId`.
- `/admin/`, `/system/`, `/security/`, `/api/`, `/gateway/`.
- `/export`, `/download`, `/preview`, `/delete`, `/batch`.
- `sort`, `orderBy`, `filter`, `where`, `keyword`.
- Swagger, OpenAPI, GraphQL, Actuator.

## Do Not Report

- CORS headers without demonstrated sensitive-data theft.
- Missing security headers.
- Version or framework disclosure alone.
- Existing endpoints with no sensitive data, no state change, and no authorization bypass.
- Self-XSS requiring the victim to paste code into the console.
- Errors, stack traces, 404/403/500, or configuration observations without real impact.
- Raw `nuclei`, `ffuf`, `httpx`, `katana`, or `subfinder` output without manual impact verification.

## Evidence Rules

- Keep only minimum necessary evidence.
- Redact tokens, phone numbers, ID numbers, email bodies, and sensitive fields.
- For IDOR, test multiple IDs or explain why only one can be tested.
- For unauthenticated access, compare no-cookie, low-privilege, and normal-cookie behavior when possible.
- For state-changing operations, use test data and stop before irreversible actions.

## Time Rules

- No progress after 20 minutes: switch direction.
- Every 30 minutes: write a checkpoint.
- Before report output: reread this file and the report template.

## Seven Gates

1. Is there a reproducible PoC, curl, or executable command?
2. Is the report about real impact rather than an observation?
3. Were multiple IDs or parameters tested, or is the limitation explained?
4. Were all actions inside scope?
5. Were CORS, headers, version disclosure, Self-XSS, and other false positives excluded?
6. Was cross-endpoint parameter migration attempted or explained as not applicable?
7. Is impact concrete across confidentiality, integrity, and availability?
