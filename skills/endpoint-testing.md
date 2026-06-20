Endpoint testing must move from observed behavior to verified impact; do not report guesses.

# Endpoint Testing Workflow

## Goal

For each endpoint or endpoint family, determine function, parameters, attack surface, verification status, and whether a Chinese vulnerability report is justified.

## Loop

1. Select an endpoint family, not a random single URL, when paths share a base path or resource name.
2. Find parameters from:
   - Browser Network requests.
   - HAR imports.
   - JS/HTML source.
   - Query strings.
   - JSON bodies.
   - Response fields.
   - Related endpoints with similar resource names.
   - Scoped `ffuf-safe` runs when sibling paths, actions, parameter names, header names, or body keys are likely but not visible.
3. Determine function:
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
4. Reason about likely attack surfaces:
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
5. Verify safely with the minimum required requests and approved test accounts.
6. Record status and evidence.
7. If the result is confirmed and reportable, write the Chinese report/finding, then continue testing sibling endpoints and remaining attack surfaces.
8. Reflect on what the result implies for sibling endpoints, config patterns, and the next test.

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
- `rejected`: Tested and no meaningful issue found.
- `needs account`: Blocked by missing authorized role, tenant, or peer account.
- `needs more context`: Endpoint purpose or parameter source is not clear enough.
- `out of scope`: The endpoint or required action is outside authorization.

## Verification Rules

- Compare no-cookie, low-privilege, peer-user, and normal-user behavior when possible.
- Use local auth profiles for automated authenticated requests: `python ai_src.py auth-profiles <target> --show-secrets` for Agent-readable credentials and `--auth-profile <name>` on supported commands.
- If a role, tenant, cookie, password, or session is missing, first check `auth.local.json`, browser MCP session state, scope account labels, endpoint tests, and prior findings. Ask the user only if the authorized material is still unavailable.
- For IDOR, test multiple IDs or explain why only one can be tested.
- For tenant isolation, compare at least two tenant contexts when authorized.
- For state-changing operations, use test data and stop before irreversible actions.
- For file endpoints, verify both metadata and file content access control.
- For export endpoints, avoid bulk export; prove impact with the smallest possible sample.
- For upload endpoints, avoid malware, persistence, public payloads, archive bombs, and web shells unless explicitly authorized in an isolated test environment.

## Notes To Record

Record each endpoint test in the target state or finding notes with:

- Endpoint and method.
- Parameter sources.
- Function judgment.
- Test account context.
- Requests attempted.
- Response comparison.
- Evidence location.
- Status.
- Next endpoint or pattern to test.

Prefer `python ai_src.py log-test <target> <endpoint> --status <status>` for records that should survive context compression or guide the next direction.

After several meaningful endpoint results, run `python ai_src.py metrics <target>` to review status distribution and unresolved candidates. Use `python ai_src.py flywheel <target>` to preserve lessons about effective parameters, accounts, tool profiles, and rejected patterns. These outputs are soft reflection aids, not report evidence.

## Report Decision

Only write a Chinese vulnerability report when the result is `confirmed` and all seven gates in `skills/core.md` can pass. After writing a valid report, continue the loop; do not stop until authorized endpoint families and attack surfaces are exhausted or clearly converged.

When a report passes, record the tested endpoint family with `log-test`, save the report/finding, then return to sibling endpoints, related parameters, other roles, other tenants, or discovery/config iteration. A valid finding is progress signal, not a stopping condition.
