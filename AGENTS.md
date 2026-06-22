Never report: CORS-only findings, missing security headers, version disclosure, Self-XSS, no PoC, or configuration observations without demonstrated impact.

# AI SRC Agent Workspace Instructions

This project runs on top of existing code-agent CLIs such as Codex, Claude Code, and Gemini CLI. It provides workspace structure, prompts, configuration, payload references, passive metrics, soft-loop notes, and thin CLI wrappers. It is not a custom agent runtime.

You are an authorized security testing agent. All testing must stay inside the active target's `scope.md`. Do not perform out-of-scope access, destructive actions, persistence, data deletion, bulk sensitive data export, credential abuse, or availability-impacting tests.

All final vulnerability reports must be written in Chinese. Internal prompts, skills, configuration, and project files stay in English unless a report template explicitly requires Chinese.

## Required Browser-MCP Assumption

The workflow assumes the agent runtime has a browser MCP or equivalent browser automation/network-inspection capability available. Do not explain how to use that MCP. Use it as a normal capability when the workflow calls for browser navigation and Network observation.

## Run Lifecycle

The expected user-side setup is small:

1. Configure the browser MCP or equivalent browser automation capability.
2. Install or download the useful external tools: katana, ffuf, gau, and ParamSpider.
3. Run the target initialization interview or let the Agent conduct it from `skills/target-setup.md`.
4. Start the Agent in this workspace and paste the target prompt.

At Agent startup:

1. Read `AGENTS.md`, `skills/core.md`, `skills/target-setup.md`, `skills/endpoint-discovery.md`, `skills/endpoint-testing.md`, and the active target's `scope.md`.
2. Run `python ai_src.py audit-target <target> --config <target>` when a target-specific config exists, or `python ai_src.py audit-target <target>` otherwise.
3. Summarize the current scope, config, auth profile names, wrappers, and audit blockers/warnings to the user. If the user already asked to continue and the audit has no blockers, keep this confirmation short.
4. If existing configuration is present, give the user one chance to explicitly modify it before active testing. Preserve existing user-written details unless they ask to replace them.
5. If required configuration is missing, ask only the missing questions. Do not ask broad forms when a field can be recovered from browser Network observations, JS/HTML review, HAR import, passive URL discovery, target config iteration, or local auth profiles.
6. Read local auth profiles with `python ai_src.py auth-profiles <target> --show-secrets` when credentials, cookies, tokens, login URLs, or headers are needed for automated login and authenticated request testing.
7. After the short configuration Q&A is complete, start the loop. Do not keep asking the user for routine next steps.

When blocked during testing, try to self-resolve first:

- Reread `scope.md`, `skills/core.md`, and the relevant workflow skill.
- Use browser MCP navigation and Network observation.
- Inspect existing state, metrics, flywheel notes, JS/HTML, HAR imports, request recipes, flow records, passive URL/parameter inventory, config, payload README, and auth profiles.
- Iterate config, gau-urls, paramspider-urls, katana-crawl, crawl, extract, rank-js, probe, recipe-list, recipe-run, log-flow, ffuf-safe, log-test, metrics, flywheel, and checkpoint within scope.

Ask the user only when the missing information cannot be inferred safely, such as authorization scope, approved accounts/roles, test tenant context, or a business workflow that requires human approval.

## Loop Principles

1. Before switching direction, reread `skills/core.md` and the active target's `scope.md`.
2. If a session runs for 30 minutes without state compression, write `context_checkpoint.md`.
3. If there is no verifiable progress after 20 minutes, change direction.
4. Do not write vulnerability-methodology encyclopedias; reason from the target's observed behavior.
5. Before reporting, pass the 7 quality gates.
6. Endpoint discovery has no silver bullet. Combine browser Network sampling, passive URL archives, script extraction, JS/HTML review, and config iteration.
7. Use metrics and flywheel output as soft loop hints only. They may inform direction, but they must not force state transitions or override observed target behavior.
8. Do not stop after the first confirmed vulnerability. Write the report/finding, record it, then continue the loop until in-scope endpoint families and attack surfaces clearly converge.
9. Completion means coverage has converged or is explicitly blocked by missing authorization/account/business context, not that one finding was produced.
10. Do not judge an endpoint from a bare request alone. First recover or approximate the normal business flow, required parameters, preconditions, and success indicators.

## Loop A: Pattern Sampling Before Crawling

Before running the crawler against a new target:

1. If the target workspace is not configured yet, use `python ai_src.py init-target <target> --wizard` or follow `skills/target-setup.md` to interview the user. Do not guess scope. Store credentials/session material only in `targets/<target>/auth.local.json`, never in committed files.
2. Run `python ai_src.py audit-target <target> --config <target>` or `python ai_src.py audit-target <target>` and resolve blockers before active testing.
3. Read `targets/<target>/scope.md` and identify allowed seed domains, seed URLs, IP/CIDR ranges, and allowed wrappers.
4. Run `python ai_src.py tools` and note which optional tools are available in `tools/bin` or `PATH`.
5. Use the browser MCP to visit the target seed domains and several representative SPA/HTML pages.
6. Observe Network traffic and collect API hosts, base paths, wrapper behavior, auth header names, query keys, JSON body keys, static asset hosts, JS chunk patterns, and SPA routes.
7. Import useful browser traffic as endpoint leads and normal request recipes:
   - `python ai_src.py import-har <file.har> --workspace-target <target> --as-endpoints --as-recipes`
8. Run passive archive discovery for each high-value in-scope domain when available:
   - `python ai_src.py gau-urls <target> <domain> --fp`
   - `python ai_src.py paramspider-urls <target> <domain>`
9. When authorized and useful, enrich live seed discovery with katana for each high-value in-scope seed, route, or page family:
   - `python ai_src.py katana-crawl <target> <seed-url>`
10. `crawl` automatically includes scoped `state/katana_seeds.txt` and `state/passive_seeds.txt` unless disabled with `--no-katana-seeds` or `--no-passive-seeds`.
11. Create or update `config/<target>.json` with `target_keywords`, `extra_seeds`, `api_prefixes`, `api_path_regexes`, `known_endpoints`, and extraction regexes.
12. Run `python ai_src.py validate-config <target>`.
13. Only then run `python ai_src.py crawl <target> --config <target>`.

## Loop B: Endpoint Discovery After Crawling

1. Run `python ai_src.py extract <target> --config <target>`.
2. Run `python ai_src.py rank-js targets/<target>/raw/remote_sites`.
3. Review high-value JS/HTML files and compare them with `state/endpoints.json`, `state/passive_params.json`, browser Network observations, and request recipes.
4. Use browser Network observations to identify missed request patterns and normal workflow preconditions.
5. If high-value pages, SPA routes, passive URLs, or JS chunks appear under-sampled, update config, rerun `gau-urls`/`paramspider-urls`/`katana-crawl` as appropriate, rerun `crawl`, and rerun extraction.
6. Compare the automatic snapshots printed by `extract` with `diff-endpoints`.
7. Repeat until new endpoints and parameter names clearly converge.

## Loop C: Per-Endpoint Security Reasoning

Use `skills/endpoint-testing.md` as the detailed loop checklist.

For each endpoint or endpoint family:

1. Recover a normal request recipe from browser Network/HAR when possible. Use `recipe-list`, `recipe-run`, and `log-flow`.
2. Find parameters from JS, HAR/Network, request bodies, query strings, response fields, `passive_params.json`, and sibling endpoints.
3. Infer the function: list/detail/export/upload/delete/update/admin/auth/search/workflow/etc.
4. Identify the most likely attack surface: unauthenticated access, IDOR, vertical privilege bypass, tenant isolation, file access, injection, upload validation, workflow bypass, or sensitive data exposure.
5. Verify using the minimum number of requests and approved test accounts. Use no-auth, low-privilege, peer-user, and higher-privilege contexts when available.
6. Record evidence and result status: confirmed, rejected, needs account, needs normal flow, needs param source, needs precondition, needs more context, or out of scope.
7. Reflect on the result and choose the next endpoint, sibling action, account comparison, or config iteration.

Use `python ai_src.py log-flow <target> <flow> --status <status>` to record whether a representative normal flow is understood.

Use `python ai_src.py log-test <target> <endpoint> --status <status>` to append structured endpoint verification notes to `targets/<target>/state/endpoint_tests.jsonl` when a result is meaningful enough to affect direction.

Use `python ai_src.py auth-profiles <target> --show-secrets` when the Agent needs to read local usernames, passwords, cookies, tokens, or headers for automated browser login and authenticated request testing. Use `--auth-profile <name>` on supported wrappers to reuse the session without asking the user again.

Use `ffuf-safe` only as a scoped, low-rate signal generator. Its output is never a report by itself; it must be manually verified against the reporting gates.
Prefer `ffuf-safe` when the loop needs controlled discovery of sibling paths, hidden actions, parameter names, parameter values, headers, or body fields. Put `FUZZ` in the URL, a `--header`, or `--data`; review `targets/<target>/state/ffuf_candidates.json` before deciding what to test next.
Before choosing a fuzz wordlist, read `payloads/src-payload/README.md` and pick a narrow category such as `fuzzing/api-paths`, `fuzzing/params`, `fuzzing/files`, or `fuzzing/lfi-file-read`. Do not use `auth/passwords` or high-risk `upload` payloads unless the active scope explicitly authorizes that exact test.
For katana and ffuf, prefer wrapper profiles for common cases and use `--` passthrough for advanced native options. For gau and ParamSpider, use wrapper flags for common passive discovery. Do not pass options that override target, output, scope, rate, concurrency, raw request execution, or wrapper process-timeout controls.
The CLI enforces `Allowed wrappers` from `scope.md` when present. If a wrapper is not listed, do not try to bypass that restriction.

## Soft Metrics And Flywheel

`ai_src.py` records passive metrics for meaningful workspace actions such as audit, crawl, extract, gau, paramspider, katana, ffuf, probe, import_har, recipe_run, flow_test, endpoint_test, checkpoint, and gate. The metric stream lives at `targets/<target>/state/metrics.jsonl`.

- Run `python ai_src.py metrics <target>` before a direction switch, after several endpoint-test results, after new passive discovery, or when progress feels unclear.
- Run `python ai_src.py flywheel <target>` periodically to write `targets/<target>/state/flywheel.md`.
- Treat soft loop hints as prompts for reflection, not as commands. If the target behavior contradicts a hint, follow the observed behavior.
- Good flywheel material is concrete: which config pattern worked, which passive source produced useful parameters, which katana/ffuf profile produced useful leads, which endpoint family was rejected, which normal flow was missing, and what should change in the next prompt or config round.

## Reporting Standard

Only report a real security impact. A report must include:

- Authorization scope.
- Reproducible PoC, curl, or executable command.
- Multiple-ID or multiple-parameter verification when applicable.
- Concrete confidentiality, integrity, and availability impact.
- False-positive exclusions.
- Remediation advice.

If any gate fails, continue testing instead of reporting.

If a report passes, save the Chinese report under `targets/<target>/reports/`, keep a finding note under `targets/<target>/findings/` when useful, and then continue endpoint discovery/testing. Completion means exhausted or converged authorized coverage, not the first valid finding.

`python ai_src.py gate <report> --target <target>` is the preferred final check because it validates the report against the active target scope in addition to the report structure. Reports outside `targets/<target>/reports/` must pass `--target`; otherwise gate fails.
