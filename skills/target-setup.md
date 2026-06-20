# Target Setup Interview

Use this skill when creating or updating a target workspace from user answers.

## Goal

Collect enough target-specific configuration to create:

- `targets/<target>/scope.md`
- `targets/<target>/domains.txt`
- `targets/<target>/seeds.txt`
- `config/<target>.json`

The setup interview is only an initialization aid. It must not become a hard runtime state machine.

## Required Context

Read these files before asking questions:

- `targets/_template/scope.md`
- `examples/scope.example.md`
- `examples/target-config.example.json`
- `examples/auth.local.example.json`
- `AGENTS.md`

## Startup Audit

For an existing target, do not immediately rebuild templates. First run:

```powershell
python ai_src.py audit-target <target> --config <target>
```

If the target-specific config does not exist, run:

```powershell
python ai_src.py audit-target <target>
```

Summarize the current scope, config path, allowed wrappers, auth profile names, blockers, and warnings. Ask the user once whether they want to modify existing configuration before active testing. If there are no blockers and the user confirms there are no changes, continue the SRC loop.

## Interview Rules

- Ask only for fields that are missing or unclear.
- Do not guess authorization scope.
- Credentials and session material are allowed only in `targets/<target>/auth.local.json`, which is gitignored and intended for Agent automation.
- Never put passwords, cookies, bearer tokens, API keys, private keys, or one-time codes in `scope.md`, `config/*.json`, reports, findings, metrics, or committed docs.
- Test account fields in `scope.md` should summarize roles and labels; auth profiles store the actual username/password/session values.
- If the user is unsure, write `TODO` or `N/A` instead of inventing a value.
- Prefer small focused questions over long forms.
- Prefer self-recovery for config details that can be learned from browser Network, JS/HTML, HAR import, endpoint extraction, katana, or ffuf-safe.
- Ask the user only for authorization boundaries, approved account access, tenant/role context, credentials/session material, or business workflow approval that cannot be inferred safely.
- Before writing files, summarize the intended target name, domains, IP/CIDR ranges, seed URLs, allowed wrappers, and config path.
- If updating an existing target, preserve user-written details unless the user explicitly asks to replace them.

## Minimum Questions

Collect these fields:

- Target name.
- Authorization status, source, window, owner/SRC, and tester identity.
- In-scope domains and seed URLs.
- In-scope IP/CIDR ranges, or `N/A`.
- Apps/packages, or `N/A`.
- Allowed environments.
- Extra out-of-scope items beyond the template defaults.
- Test account labels: anonymous baseline, low privilege, peer user, admin/high privilege, tenant/org.
- Auth profiles for automated testing: role, username, password, login URL, tenant, cookie, authorization header, and any extra headers.
- Safety limits: max threads, max request rate, allowed wrappers, disallowed scan types.
- Evidence rules: redaction, max records, screenshots, response body storage.
- Config fields: target keywords, extra seeds, API prefixes, API regexes, known endpoints, garbage substrings.

## Preferred CLI Path

When the user wants a guided local setup, prefer the built-in wizard:

```powershell
python ai_src.py init-target <target> --wizard
```

The wizard writes the target files, can create local auth profiles, and validates the generated config.

## Manual Agent Path

If the user wants the Agent to write files directly:

1. Read the templates listed above.
2. Ask the missing questions.
3. Generate `scope.md` using the same section structure as `targets/_template/scope.md`.
4. Generate `domains.txt` and `seeds.txt` from the in-scope answers.
5. Generate `config/<target>.json` with:
   - `extends: "default.json"`
   - `target_keywords`
   - `extra_seeds`
   - optional `api_prefixes`
   - optional `api_path_regexes`
   - optional `known_endpoints`
   - optional `garbage_substrings`
6. If credentials or session material are provided, write them only to `targets/<target>/auth.local.json`.
7. Run:

```powershell
python ai_src.py validate-config <target>
python ai_src.py audit-target <target> --config <target>
python ai_src.py status <target>
python ai_src.py auth-profiles <target>
```

8. Report any TODOs that still block safe testing.

## Completion Criteria

Setup is complete only when:

- The target has at least one in-scope domain or IP/CIDR range, or the user knowingly leaves it blocked.
- Scope, domains, seeds, and config agree with each other.
- `Allowed wrappers` contains only wrappers the user authorized.
- Secrets exist only in `targets/<target>/auth.local.json` or environment variables.
- `validate-config` succeeds.
