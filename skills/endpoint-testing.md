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
7. Reflect on what the result implies for sibling endpoints, config patterns, and the next test.

## Status Values

- `confirmed`: Reproducible security impact with evidence.
- `rejected`: Tested and no meaningful issue found.
- `needs account`: Blocked by missing authorized role, tenant, or peer account.
- `needs more context`: Endpoint purpose or parameter source is not clear enough.
- `out of scope`: The endpoint or required action is outside authorization.

## Verification Rules

- Compare no-cookie, low-privilege, peer-user, and normal-user behavior when possible.
- For IDOR, test multiple IDs or explain why only one can be tested.
- For tenant isolation, compare at least two tenant contexts when authorized.
- For state-changing operations, use test data and stop before irreversible actions.
- For file endpoints, verify both metadata and file content access control.
- For export endpoints, avoid bulk export; prove impact with the smallest possible sample.
- For upload endpoints, avoid malware, persistence, or public payloads.

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

## Report Decision

Only write a Chinese vulnerability report when the result is `confirmed` and all seven gates in `skills/core.md` can pass. Otherwise keep testing notes and continue the loop.
