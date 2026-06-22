Never report: CORS-only findings, missing security headers, version disclosure, Self-XSS, no PoC, or configuration observations without demonstrated impact.

# SRC Quick Card

This project runs on top of existing agent tools such as Codex, Claude Code, and Gemini CLI. The repository provides workspace structure, configuration, prompts, scripts, payload references, thin tool wrappers, passive metrics, flywheel notes, and report quality gates.

## Hard Rules

- No PoC means no vulnerability.
- Report impact, not observations.
- A report must include curl, an executable command, or clear reproducible steps.
- Do not test until the authorization scope is understood.
- Do not delete data, change passwords, send business notifications, or perform destructive actions.
- Do not run high-pressure scans that may affect availability.
- Do not export bulk sensitive data.
- Do not write reports for best-practice issues below meaningful impact.

## Priority

- Spend most time on IDOR, authorization bypass, tenant isolation, and unauthenticated access.
- More JS/HTML usually means more hidden interfaces.
- If login exists, test horizontal and vertical authorization first.
- If the target is API-heavy, test unauthenticated and low-privilege access first.
- If upload exists, test validation, access control, and retrieval chains.
- If search or filter exists, inspect input validation and sorting parameters.
- If GraphQL exists, inspect schema exposure and authorization on queries/mutations.
- If no entry is obvious, keep mining JS, manifests, routes, source maps, passive URLs, and Network traffic.

## Startup Routine

- Read `AGENTS.md`, this file, `skills/target-setup.md`, `skills/endpoint-discovery.md`, `skills/endpoint-testing.md`, and the active target's `scope.md`.
- Run `python ai_src.py audit-target <target> --config <target>` when a target config exists, otherwise run `python ai_src.py audit-target <target>`.
- Summarize scope, config, auth profile names, wrappers, blockers, and warnings to the user before active testing.
- If config exists, ask once whether the user wants explicit changes. If there are no blockers and the user says to continue, start the loop.
- If required setup is missing, ask only the missing questions. Prefer self-recovery for config details that browser Network, JS/HTML review, HAR import, passive URL discovery, or target config iteration can reveal.
- If credentials/session material is needed for automated login or authenticated tests, read it from `auth.local.json` with `python ai_src.py auth-profiles <target> --show-secrets`.
- After startup Q&A, do not ask the user for routine next actions. Ask only for information that cannot be inferred safely, such as authorization, approved account/role access, tenant context, or business workflow approval.

## Pattern Sampling Before Crawling

- For a new or incomplete target, use `python ai_src.py init-target <target> --wizard` or `skills/target-setup.md` before crawling. Do not guess authorization scope. Store credentials/session material only in local ignored auth profiles.
- Run `python ai_src.py audit-target <target>` and resolve blockers before active testing.
- Use `python ai_src.py auth-profiles <target> --show-secrets` when the Agent needs credentials/session values for automated login and authenticated testing.
- Run `python ai_src.py tools` before relying on optional CLIs.
- Use browser Network observations before running the crawler.
- Visit multiple allowed seed domains, SPA routes, and HTML pages.
- Collect API host keywords, base paths, request wrappers, asset hosts, JS chunk patterns, query keys, body keys, auth header names, normal request recipes, and success indicators.
- Import useful browser traffic with `python ai_src.py import-har <file.har> --workspace-target <target> --as-endpoints --as-recipes`.
- Use `gau-urls` and `paramspider-urls` for passive URL/parameter discovery before the main crawl and when discovery stalls.
- When authorized, use `katana-crawl` for more live URL seeds before the main crawl and again when route coverage looks thin.
- When a small scoped search space exists, use `ffuf-safe` for sibling paths, actions, parameter names, header probes, or body probes. Review `ffuf_candidates.json`; do not treat raw matches as findings.
- For fuzz wordlists, check `payloads/src-payload/README.md` first and choose a narrow category. Routine ffuf work should usually start with `fuzzing/api-paths`, `fuzzing/params`, `fuzzing/files`, or `fuzzing/generic`.
- For katana and ffuf, use wrapper profiles for common cases and `--` passthrough for advanced native options; the wrapper still enforces scope, output, rate, concurrency, and `Allowed wrappers` from `scope.md`.
- Translate observations into `config/<target>.json`.
- Validate config before crawling.

## Endpoint Discovery Loop

- Never trust one extraction pass.
- Crawl HTML/JS after config is seeded from browser Network patterns and passive URL archives.
- If katana has produced `state/katana_seeds.txt`, the main crawl includes those scoped URLs automatically.
- If gau or ParamSpider has produced `state/passive_seeds.txt`, the main crawl includes those scoped URLs automatically.
- Run extraction, rank JS/HTML, review high-value files, compare against Network observations and `state/passive_params.json`, update config, and rerun.
- Use automatic endpoint snapshots from `extract` when comparing rounds with `diff-endpoints`.
- Use `python ai_src.py metrics <target>` to inspect endpoint deltas, passive signal, recipe coverage, flow coverage, and tool signal after meaningful rounds.
- Stop only when new endpoint and parameter discovery clearly converge.

## Per-Endpoint Loop

Use `skills/endpoint-testing.md` for detailed endpoint verification and result recording.

1. Recover the normal business flow and request recipe when possible.
2. Find parameters from JS/HTML, HAR/Network, request recipes, passive parameters, request bodies, query strings, and response fields.
3. Determine endpoint function.
4. Choose likely attack surface.
5. Use `ffuf-safe` only when it can answer a concrete scoped question about siblings, parameters, headers, or body fields.
6. Select wordlists from `payloads/src-payload/` by purpose; avoid broad password and high-risk upload payloads unless explicitly authorized.
7. Verify with approved accounts and minimum requests.
8. Record normal-flow and endpoint-test status.
9. Reflect on the result and choose the next endpoint.

## Status Values

- `confirmed`: Reproducible security impact.
- `rejected`: Normal flow and relevant variants were tested without meaningful issue.
- `needs account`: Missing approved role, tenant, or peer account.
- `needs normal flow`: Endpoint found, but normal function is not understood.
- `needs param source`: Required parameter or ID source is missing.
- `needs precondition`: Required object, tenant, workflow state, or setup is missing.
- `needs more context`: Purpose or business impact is unclear.
- `out of scope`: Required endpoint or action is outside authorization.

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
- Raw `ffuf`, `katana`, `gau`, or ParamSpider output without manual impact verification.

## Time Rules

- No progress after 20 minutes: switch direction.
- Every 30 minutes: write a checkpoint.
- Before switching direction, check `python ai_src.py metrics <target>` when available; use its hints as soft input only.
- Periodically run `python ai_src.py flywheel <target>` so useful patterns become reusable notes in `state/flywheel.md`.
- Before report output: reread this file and the report template.
- Final report checks must bind a target: use `python ai_src.py gate <report> --target <target>` unless the report is already under `targets/<target>/reports/`.
- A confirmed report is not the end of the run. Write the finding/report, record the result, then continue with remaining endpoint families and attack surfaces until coverage converges.

## Metrics And Flywheel

- Metrics are passive observations written to `targets/<target>/state/metrics.jsonl`; they are not an external runtime or forced state machine.
- The agent remains responsible for choosing direction from scope, target behavior, evidence quality, and report gates.
- `metrics` answers what changed: audit blockers/warnings, extraction deltas, passive URL/parameter signals, katana seeds, ffuf candidates, request recipes, flow statuses, endpoint-test statuses, probe results, and gate failures.
- `flywheel` answers what to carry forward: effective config patterns, useful passive sources, useful tool profiles, weak evidence chains, missing normal flows, and prompt/config changes for the next loop.
- Never report from metrics alone. Metrics can only point back to browser evidence, JS/HTML review, manual endpoint verification, and report gates.

## Seven Gates

1. Is there a reproducible PoC, curl, or executable command?
2. Is the report about real impact rather than an observation?
3. Were multiple IDs or parameters tested, or is the limitation explained?
4. Were all actions inside scope?
5. Were CORS, headers, version disclosure, Self-XSS, and other false positives excluded?
6. Was cross-endpoint parameter migration attempted or explained as not applicable?
7. Is impact concrete across confidentiality, integrity, and availability?
