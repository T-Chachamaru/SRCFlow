Endpoint testing must move from normal function to verified impact; do not report guesses.

# Endpoint Testing Workflow

## Goal

For each endpoint or endpoint family, recover the normal business flow, determine function and parameters, choose the likely attack surface, verify behavior with approved accounts, and decide whether a Chinese vulnerability report is justified.

## Normal Flow First

Do not judge an endpoint by only sending a bare request to a discovered URL.

Before security variants, try to answer:

- What user action triggers this endpoint?
- Which page, route, button, form, or workflow is it part of?
- Which query keys, path IDs, JSON body keys, headers, CSRF tokens, tenant keys, or pagination fields are required?
- What preconditions are required, such as a created object, selected tenant, uploaded file, or workflow state?
- What does a successful normal response look like?
- Which auth profile or browser session represents the normal user?

Preferred sources:

- Browser MCP Network traffic.
- HAR imported with `--as-recipes`.
- `targets/<target>/state/request_recipes.jsonl`.
- JS/HTML source and ranked bundles.
- `targets/<target>/state/passive_params.json`.
- Response fields from list/detail endpoints.
- Related endpoints with similar resource names.

Useful commands:

```powershell
python ai_src.py import-har .\captures\target.har --workspace-target <target> --as-endpoints --as-recipes
python ai_src.py recipe-list <target>
python ai_src.py recipe-run <target> <recipe-id-or-method-path> --auth-profile low
python ai_src.py log-flow <target> "resource detail normal flow" --recipe <recipe-id> --status normal-flow-ok --param-sources "Network + response field id"
```

If normal behavior cannot be recovered yet, log `needs-normal-flow`, `needs-param-source`, or `needs-precondition` instead of treating the endpoint as rejected.

## Endpoint Family Loop

1. Select an endpoint family, not a random single URL, when paths share a base path, resource name, workflow, or data object.
2. Recover or approximate a normal request recipe.
3. Find parameters from:
   - Browser Network requests.
   - HAR imports and request recipes.
   - JS/HTML source.
   - Passive URL parameters.
   - Query strings.
   - JSON bodies.
   - Response fields.
   - Related endpoints with similar resource names.
   - Scoped `ffuf-safe` runs when sibling paths, actions, parameter names, header names, or body keys are likely but not visible.
4. Determine function:
   - list
   - detail
   - export
   - upload
   - download
   - preview
   - create
   - update
   - delete
   - admin
   - auth
   - search
   - workflow action
5. Reason about likely attack surfaces:
   - unauthenticated access
   - horizontal authorization bypass
   - vertical authorization bypass
   - tenant isolation bypass
   - file access control
   - mass assignment
   - injection
   - upload validation
   - business workflow bypass
   - sensitive data exposure
6. Verify with the minimum required requests and approved test accounts.
7. Record status and evidence.
8. If the result is confirmed and reportable, write the Chinese report/finding, gate it, then continue testing sibling endpoints and remaining attack surfaces.
9. Reflect on what the result implies for sibling endpoints, config patterns, passive parameters, recipes, and the next test.

## ffuf In The Loop

Use `ffuf-safe` as the default low-rate discovery aid when manual evidence suggests a small, scoped search space:

- Sibling paths or actions: `python ai_src.py ffuf-safe <target> https://host/api/resource/FUZZ wordlist.txt`
- Query parameter names or values: place `FUZZ` in the query string.
- Header probes: use `--header "X-Feature: FUZZ"` or another scoped test header.
- Body key/value probes: use `--method POST --data '{"key":"FUZZ"}'` or a test-body variant.

Review `targets/<target>/state/ffuf_candidates.json` after each run. Treat entries as leads only, then verify them manually and record the result with `log-test`.
Before picking `wordlist.txt`, read `payloads/src-payload/README.md` and choose the narrowest relevant directory:

- `payloads/src-payload/fuzzing/api-paths/` for API route, action, and object discovery.
- `payloads/src-payload/fuzzing/params/` for query, header, and body key discovery.
- `payloads/src-payload/fuzzing/files/` for common file names and file-like endpoints.
- `payloads/src-payload/fuzzing/lfi-file-read/` only when file-read behavior is already suspected.
- `payloads/src-payload/injection/` only after endpoint behavior suggests a specific injection class.

Use `--profile` for common ffuf modes and `--` passthrough for advanced native ffuf matchers, filters, encoders, recursion, or transport options. Passthrough cannot override target URL, output, output format, rate, threads, raw request, or input command execution.
If `scope.md` restricts `Allowed wrappers`, the CLI enforces that list.

## Status Values

- `confirmed`: Reproducible security impact with evidence.
- `rejected`: A normal flow and relevant variants were tested and no meaningful issue was found.
- `needs account`: Blocked by missing authorized role, tenant, or peer account.
- `needs normal flow`: The endpoint was found, but its normal business flow is not understood.
- `needs param source`: Required parameters or IDs cannot yet be sourced.
- `needs precondition`: A required object, tenant, workflow state, or setup condition is missing.
- `needs more context`: Endpoint purpose or business impact is not clear enough.
- `out of scope`: The endpoint or required action is outside authorization.

## Verification Rules

- Compare no-cookie, low-privilege, peer-user, and normal-user behavior when possible.
- Use local auth profiles for automated authenticated requests: `python ai_src.py auth-profiles <target> --show-secrets` for Agent-readable credentials and `--auth-profile <name>` on supported commands.
- If a role, tenant, cookie, password, or session is missing, first check `auth.local.json`, browser MCP session state, scope account labels, endpoint tests, flow records, and prior findings. Ask the user only if the authorized material is still unavailable.
- For IDOR, test multiple IDs or explain why only one can be tested.
- For tenant isolation, compare at least two tenant contexts when authorized.
- For state-changing operations, use test data and stop before irreversible actions.
- For file endpoints, verify both metadata and file content access control.
- For export endpoints, prove impact with the smallest useful sample.
- For upload endpoints, avoid malware, persistence, public payloads, archive bombs, and web shells unless explicitly authorized in an isolated test environment.
- `probe` is only a liveness or status signal. It is not endpoint testing by itself.

## Notes To Record

Record each endpoint test in the target state or finding notes with:

- Endpoint and method.
- Recipe ID or Network/HAR source.
- Normal-flow status.
- Parameter sources.
- Function judgment.
- Test account context.
- Requests attempted.
- Response comparison.
- Evidence location.
- Status.
- Next endpoint or pattern to test.

Prefer:

```powershell
python ai_src.py log-flow <target> "<flow-name>" --status normal-flow-ok
python ai_src.py log-test <target> <endpoint> --status needs-normal-flow
```

After several meaningful endpoint results, run `python ai_src.py metrics <target>` to review status distribution and unresolved candidates. Use `python ai_src.py flywheel <target>` to preserve lessons about effective parameters, accounts, tool profiles, normal flows, and rejected patterns. These outputs are soft reflection aids, not report evidence.

## Report Decision

Only write a Chinese vulnerability report when the result is `confirmed` and all seven gates in `skills/core.md` can pass. After writing a valid report, continue the loop; do not stop until authorized endpoint families and attack surfaces are exhausted or clearly converged.

When a report passes, record the tested endpoint family with `log-test`, save the report/finding, then return to sibling endpoints, related parameters, other roles, other tenants, passive discoveries, or config iteration. A valid finding is progress signal, not a stopping condition.
