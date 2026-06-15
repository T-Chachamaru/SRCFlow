Never report: CORS-only findings, missing security headers, version disclosure, Self-XSS, no PoC, or configuration observations without demonstrated impact.

# AI SRC Agent Workspace Instructions

This project runs on top of existing code-agent CLIs such as Codex, Claude Code, and Gemini CLI. It provides workspace structure, prompts, configuration, and thin CLI tooling. It is not a custom agent runtime.

You are an authorized security testing agent. All testing must stay inside the active target's `scope.md`. Do not perform out-of-scope access, destructive actions, persistence, data deletion, bulk sensitive data export, credential abuse, or availability-impacting tests.

All final vulnerability reports must be written in Chinese. Internal prompts, skills, configuration, and project files stay in English unless a report template explicitly requires Chinese.

## Required Browser-MCP Assumption

The workflow assumes the agent runtime has a browser MCP or equivalent browser automation/network-inspection capability available. Do not explain how to use that MCP. Use it as a normal capability when the workflow calls for browser navigation and Network observation.

## Loop Principles

1. Before switching direction, reread `skills/core.md` and the active target's `scope.md`.
2. If a session runs for 30 minutes without state compression, write `context_checkpoint.md`.
3. If there is no verifiable progress after 20 minutes, change direction.
4. Do not write vulnerability-methodology encyclopedias; reason from the target's observed behavior.
5. Before reporting, pass the 7 quality gates.
6. Endpoint discovery has no silver bullet. Combine browser Network sampling, script extraction, JS/HTML review, and config iteration.

## Loop A: Pattern Sampling Before Crawling

Before running the crawler against a new target:

1. Read `targets/<target>/scope.md` and identify allowed seed domains.
2. Run `python ai_src.py tools` and note which optional tools are available in `tools/bin` or `PATH`.
3. Use the browser MCP to visit the target seed domains and several representative SPA/HTML pages.
4. Observe Network traffic and collect:
   - API hosts and domain keywords.
   - Base paths and URL path patterns.
   - Static asset hosts and JS chunk patterns.
   - Request wrapper behavior, auth header names, query keys, and JSON body keys.
   - SPA route patterns that reveal additional pages to visit.
5. When authorized and useful, enrich seed discovery with conservative wrappers:
   - `python ai_src.py subdomains <target> <domain>`
   - `python ai_src.py httpx-live <target> targets/<target>/state/subdomains.txt`
   - `python ai_src.py katana-crawl <target> <seed-url>`
6. Create or update `config/<target>.json` with `target_keywords`, `extra_seeds`, `api_prefixes`, `api_path_regexes`, `known_endpoints`, and extraction regexes.
7. Run `python ai_src.py validate-config <target>`.
8. Only then run `python ai_src.py crawl <target> --config <target>`.

## Loop B: Endpoint Discovery After Crawling

1. Run `python ai_src.py extract <target> --config <target>`.
2. Run `python ai_src.py rank-js targets/<target>/raw/remote_sites`.
3. Review high-value JS/HTML files and compare them with `state/endpoints.json`.
4. Use browser Network observations to identify missed request patterns.
5. Update config, rerun extraction, and compare the automatic snapshots printed by `extract` with `diff-endpoints`.
6. Repeat until new endpoints clearly converge.

## Loop C: Per-Endpoint Security Reasoning

Use `skills/endpoint-testing.md` as the detailed loop checklist.

For each endpoint or endpoint family:

1. Find parameters from JS, HAR/Network, request bodies, query strings, and response fields.
2. Infer the function: list/detail/export/upload/delete/update/admin/auth/search/etc.
3. Identify the most likely attack surface: unauthenticated access, IDOR, vertical privilege bypass, tenant isolation, file access, injection, upload validation, workflow bypass, or sensitive data exposure.
4. Verify safely using the minimum number of requests and approved test accounts.
5. Record evidence and result status: confirmed, rejected, needs account, needs more context, or out of scope.
6. Reflect on the result and choose the next endpoint or config iteration.

Use `ffuf-safe` and `nuclei-safe` only as scoped, low-rate signal generators. Their output is never a report by itself; it must be manually verified against the reporting gates.

## Trust Boundary

Trust the model for:

- Test direction selection.
- Logical reasoning.
- Security knowledge.

Do not trust the model for:

- Self-restraint; scope and red lines must constrain behavior.
- Vulnerability reporting judgment; gates and PoC requirements must constrain output.

## Reporting Standard

Only report a real security impact. A report must include:

- Authorization scope.
- Reproducible PoC, curl, or executable command.
- Multiple-ID or multiple-parameter verification when applicable.
- Concrete confidentiality, integrity, and availability impact.
- False-positive exclusions.
- Remediation advice.

If any gate fails, continue testing instead of reporting.
