"""srcflow.audit - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path

from srcflow.auth import auth_profile_names, auth_store_path
from srcflow.constants import CONFIG_DIR, CONFIG_LIST_FIELDS, KNOWN_WRAPPERS, TOOLS_DIR
from srcflow.exec_helpers import find_tool_path
from srcflow.io_helpers import append_metric, metrics_path, read_endpoint_tests, read_flow_tests, read_json_file, read_metric_events, read_request_recipes, write_json
from srcflow.scope import endpoint_export_count, missing_setup_value, parse_scope, raw_scope_field, scope_list, target_state_config
from srcflow.utils import counter_dict, eprint, load_config, read_lines_file, target_dir, utc_now

def build_target_audit(base: Path, config_label: str) -> dict[str, object]:
    blockers: list[str] = []
    warnings: list[str] = []
    self_resolvable: list[str] = []
    ask_user_if_needed: list[str] = []
    next_actions: list[str] = []

    if not base.exists():
        return {
            "target": base.name,
            "path": str(base),
            "status": "blocked",
            "blockers": [f"target workspace does not exist: {base}"],
            "warnings": [],
            "self_resolvable": [],
            "ask_user_if_needed": [f"Run: python ai_src.py init-target {base.name} --wizard"],
            "next_actions": [],
        }

    scope_path = base / "scope.md"
    scope_text = scope_path.read_text(encoding="utf-8", errors="ignore") if scope_path.exists() else ""
    scope = parse_scope(base)
    domains = scope_list(scope, "domains")
    seeds = scope_list(scope, "seeds")
    ip_ranges = scope_list(scope, "ip_ranges")
    allowed_wrappers = scope.get("allowed_wrappers")

    if not scope_path.exists():
        blockers.append(f"missing scope file: {scope_path}")
        ask_user_if_needed.append("Create the target with init-target --wizard or complete targets/<target>/scope.md.")
    if not domains and not ip_ranges:
        blockers.append("no in-scope domain or IP/CIDR range is configured")
        ask_user_if_needed.append("Ask for at least one authorized domain or IP/CIDR range before active testing.")
    if not seeds:
        warnings.append("no seed URLs are configured; the Agent may derive safe seeds from in-scope domains, but explicit seeds are better")

    required_auth_fields = [
        "Status",
        "Authorization source",
        "Window",
    ]
    optional_auth_fields = [
        "Owner / SRC",
        "Tester identity",
    ]
    missing_required_auth = [
        label for label in required_auth_fields
        if missing_setup_value(raw_scope_field(scope_text, label))
    ]
    missing_optional_auth = [
        label for label in optional_auth_fields
        if missing_setup_value(raw_scope_field(scope_text, label))
    ]
    if missing_required_auth:
        blockers.append("authorization metadata is incomplete: " + ", ".join(missing_required_auth))
        ask_user_if_needed.append("Ask the user to confirm authorization status, source, and test window.")
    if missing_optional_auth:
        warnings.append("scope metadata is incomplete: " + ", ".join(missing_optional_auth))

    if isinstance(allowed_wrappers, list):
        unknown = sorted(set(allowed_wrappers) - KNOWN_WRAPPERS)
        if unknown:
            blockers.append("unknown allowed wrapper(s): " + ", ".join(unknown))
        if not allowed_wrappers:
            warnings.append("scope allows no wrappers; browser-only work may continue, but katana/ffuf must not be used")
    else:
        warnings.append("Allowed wrappers is not explicit; wrappers are permitted only if scope allows them")

    selected_config = config_label or target_state_config(base)
    config_info: dict[str, object] = {"label": selected_config}
    try:
        config_path, config = load_config(selected_config)
        config_info["path"] = str(config_path)
        config_info["exists"] = True
        failures, config_warnings = validate_config_object(config)
        if failures:
            blockers.extend(f"config invalid: {item}" for item in failures)
        warnings.extend(f"config warning: {item}" for item in config_warnings)
        if selected_config == "default" and (CONFIG_DIR / f"{base.name}.json").exists():
            self_resolvable.append(f"Use target-specific config: python ai_src.py audit-target {base.name} --config {base.name}")
        if not config.get("target_keywords") and domains:
            self_resolvable.append("Seed target_keywords from scope domains after browser Network sampling.")
        if not config.get("extra_seeds") and seeds:
            self_resolvable.append("Seed extra_seeds from scope seed URLs or observed in-scope SPA routes.")
    except Exception as exc:
        config_info["exists"] = False
        config_info["error"] = f"{type(exc).__name__}: {exc}"
        blockers.append(f"selected config cannot be loaded: {selected_config}")
        self_resolvable.append(f"Create or fix config/{base.name}.json, then run validate-config.")

    tool_rows = tool_status_rows()
    missing_tools = [str(row["tool"]) for row in tool_rows if not row.get("installed")]
    if missing_tools:
        warnings.append("missing optional tool(s): " + ", ".join(missing_tools))
        self_resolvable.append("Install/refresh tools with scripts/install_tools.ps1 or place binaries in tools/bin.")

    profiles, auth_error = auth_profile_names(base)
    if auth_error:
        warnings.append(auth_error)
        self_resolvable.append("Fix targets/<target>/auth.local.json or recreate profiles with auth-set.")
    elif not profiles:
        ask_user_if_needed.append("If authenticated testing is required and no browser session can be reused, ask for an approved auth profile.")

    raw_dir = base / "raw" / "remote_sites"
    endpoints = base / "state" / "endpoints.json"
    endpoint_unique, endpoint_raw = endpoint_export_count(endpoints)
    endpoint_tests = read_endpoint_tests(base)
    request_recipes = read_request_recipes(base)
    flow_tests = read_flow_tests(base)
    status_counts = Counter(str(row.get("status", "")) for row in endpoint_tests if row.get("status"))
    reports_count = count_files(base / "reports", (".md", ".txt"))
    findings_count = count_files(base / "findings", (".md", ".txt", ".json", ".jsonl"))
    passive_seed_count = len(read_lines_file(base / "state" / "passive_seeds.txt"))

    if not count_files(raw_dir, (".html", ".htm", ".js")):
        next_actions.append("Start with browser Network sampling, passive URL enrichment, then katana-crawl on useful in-scope seeds if authorized.")
    elif endpoint_unique == 0:
        next_actions.append("Run extract, rank-js, compare with browser Network observations, then refine config.")
    elif not request_recipes:
        next_actions.append("Capture/import normal browser Network flows with import-har --as-recipes before judging endpoint behavior.")
    elif not flow_tests:
        next_actions.append("Replay representative recipes and record normal-flow status with log-flow.")
    elif not endpoint_tests:
        next_actions.append("Start endpoint-family verification and record meaningful results with log-test.")
    else:
        next_actions.append("Continue unresolved endpoint families; use metrics/flywheel before changing direction.")
    if passive_seed_count:
        next_actions.append("The next crawl will include scoped passive seeds unless --no-passive-seeds is used.")
    if reports_count:
        next_actions.append("Do not stop at existing reports; continue until authorized coverage converges.")

    status = "blocked" if blockers else "ready_with_warnings" if warnings else "ready"
    return {
        "target": base.name,
        "path": str(base),
        "status": status,
        "scope": {
            "path": str(scope_path),
            "domains": domains,
            "ip_ranges": ip_ranges,
            "seeds": seeds,
            "allowed_wrappers": allowed_wrappers,
        },
        "config": config_info,
        "tools": tool_rows,
        "auth_profiles": {
            "path": str(auth_store_path(base)),
            "profiles": profiles,
            "error": auth_error,
        },
        "state": {
            "raw_html": count_files(raw_dir, (".html", ".htm")),
            "raw_js": count_files(raw_dir, (".js",)),
            "endpoint_unique": endpoint_unique,
            "endpoint_raw": endpoint_raw,
            "passive_seeds": passive_seed_count,
            "request_recipes": len(request_recipes),
            "flow_tests": len(flow_tests),
            "endpoint_tests": len(endpoint_tests),
            "endpoint_test_statuses": counter_dict(status_counts),
            "reports": reports_count,
            "findings": findings_count,
            "metrics": len(read_metric_events(base)),
        },
        "blockers": blockers,
        "warnings": warnings,
        "self_resolvable": self_resolvable,
        "ask_user_if_needed": ask_user_if_needed,
        "next_actions": next_actions,
    }



def print_target_audit(audit: dict[str, object]) -> None:
    print(f"Target audit: {audit.get('target')}")
    print(f"Status: {audit.get('status')}")
    print(f"Path: {audit.get('path')}")

    scope = audit.get("scope", {})
    if isinstance(scope, dict) and scope.get("path"):
        print(f"Scope: {scope.get('path')}")
        print(f"- Domains: {', '.join(scope.get('domains', []) or []) or '-'}")
        print(f"- IP/CIDR: {', '.join(scope.get('ip_ranges', []) or []) or '-'}")
        print(f"- Seeds: {', '.join(scope.get('seeds', []) or []) or '-'}")
        wrappers = scope.get("allowed_wrappers")
        if isinstance(wrappers, list):
            print(f"- Allowed wrappers: {', '.join(wrappers) or 'none'}")

    config = audit.get("config", {})
    if isinstance(config, dict) and config.get("label"):
        if config.get("exists"):
            print(f"Config: {config.get('label')} ({config.get('path')})")
        else:
            print(f"Config: {config.get('label')} unavailable ({config.get('error', '-')})")

    tools = audit.get("tools", [])
    if isinstance(tools, list) and tools:
        installed = [
            f"{row.get('tool')}={'yes' if row.get('installed') else 'no'}"
            for row in tools if isinstance(row, dict)
        ]
        print("Tools: " + (", ".join(installed) or "-"))

    auth = audit.get("auth_profiles", {})
    if isinstance(auth, dict) and auth.get("path"):
        profiles = auth.get("profiles", [])
        print(f"Auth profiles: {', '.join(profiles or []) or '-'}")

    state = audit.get("state", {})
    if isinstance(state, dict) and state:
        print(
            "State: "
            f"raw_html={state.get('raw_html', 0)} raw_js={state.get('raw_js', 0)} "
            f"endpoints={state.get('endpoint_unique', 0)}/{state.get('endpoint_raw', 0)} "
            f"passive_seeds={state.get('passive_seeds', 0)} "
            f"recipes={state.get('request_recipes', 0)} flows={state.get('flow_tests', 0)} "
            f"tests={state.get('endpoint_tests', 0)} reports={state.get('reports', 0)}"
        )

    for title, key in (
        ("Blockers", "blockers"),
        ("Warnings", "warnings"),
        ("Agent self-resolvable", "self_resolvable"),
        ("Ask user only if needed", "ask_user_if_needed"),
        ("Suggested next actions", "next_actions"),
    ):
        values = audit.get(key, [])
        if isinstance(values, list) and values:
            print(f"{title}:")
            for value in values:
                print(f"- {value}")



def cmd_audit_target(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    config_label = args.config or target_state_config(base)
    audit = build_target_audit(base, config_label)
    if args.json:
        print(json.dumps(audit, ensure_ascii=False, indent=2))
    else:
        print_target_audit(audit)
    if base.exists():
        append_metric(base, "audit", {
            "status": audit.get("status"),
            "blockers": len(audit.get("blockers", [])) if isinstance(audit.get("blockers"), list) else 0,
            "warnings": len(audit.get("warnings", [])) if isinstance(audit.get("warnings"), list) else 0,
            "config": config_label,
        })
    return 2 if audit.get("status") == "blocked" else 0



def cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        path, config = load_config(args.config)
    except Exception as exc:
        print(f"Config invalid: {type(exc).__name__}: {exc}")
        return 1

    failures, warnings = validate_config_object(config)

    if failures:
        print(f"Config invalid: {path}")
        for item in failures:
            print(f"- {item}")
        return 1

    print(f"Config OK: {path}")
    if config.get("_extends_path"):
        print(f"Extends: {config['_extends_path']}")
    for item in warnings:
        print(f"Warning: {item}")
    print(f"extract_patterns={len(config.get('extract_patterns', []))} api_prefixes={len(config.get('api_prefixes', []))} known_endpoints={len(config.get('known_endpoints', []))}")
    return 0



def validate_config_object(config: dict[str, object]) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    for field in CONFIG_LIST_FIELDS:
        if field in config and not isinstance(config[field], list):
            failures.append(f"`{field}` must be a list")

    for pattern in config.get("api_path_regexes", []):
        try:
            re.compile(str(pattern))
        except re.error as exc:
            failures.append(f"api_path_regex invalid: {pattern}: {exc}")

    for item in config.get("extract_patterns", []):
        if not isinstance(item, dict):
            failures.append(f"extract_patterns item must be object: {item!r}")
            continue
        name = item.get("name", "UNNAMED")
        pattern = str(item.get("pattern", ""))
        if "?P<endpoint>" not in pattern:
            failures.append(f"extract pattern `{name}` missing (?P<endpoint>...)")
        try:
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            failures.append(f"extract pattern `{name}` invalid: {exc}")

    if not config.get("target_keywords"):
        warnings.append("target_keywords is empty; pass --target/--target-kw or fill target config")
    if not config.get("extra_seeds"):
        warnings.append("extra_seeds is empty; target must provide seeds via scope/seeds.txt/CLI")
    return failures, warnings



def cmd_tools(args: argparse.Namespace) -> int:
    rows = tool_status_rows()
    write_json(TOOLS_DIR / "tool_status.json", {"checked_at": utc_now(), "tools": rows})
    for row in rows:
        status = row["path"] if row["installed"] else "missing"
        print(f"{row['tool']}: {status}")
    print(f"Status JSON: {TOOLS_DIR / 'tool_status.json'}")
    return 0



def tool_status_rows() -> list[dict[str, object]]:
    rows = []
    for tool in ("katana", "ffuf", "gau", "paramspider"):
        path = find_tool_path(tool)
        rows.append({"tool": tool, "path": path, "installed": bool(path)})
    return rows



def cmd_status(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    scope = parse_scope(base)
    raw = base / "raw" / "remote_sites"
    endpoints = base / "state" / "endpoints.json"
    last_extract = base / "state" / "last_extract.json"
    test_log = base / "state" / "endpoint_tests.jsonl"
    domains = scope_list(scope, "domains")
    ip_ranges = scope_list(scope, "ip_ranges")
    allowed_wrappers = scope.get("allowed_wrappers")
    seeds = scope_list(scope, "seeds")

    print(f"Target: {base.name}")
    print(f"Path:   {base}")
    print(f"Domains ({len(domains)}): {', '.join(domains) or '-'}")
    print(f"IP ranges ({len(ip_ranges)}): {', '.join(ip_ranges) or '-'}")
    print(f"Seeds   ({len(seeds)}): {', '.join(seeds) or '-'}")
    if isinstance(allowed_wrappers, list):
        print(f"Allowed wrappers: {', '.join(allowed_wrappers) or 'none'}")
    if scope.get("max_threads"):
        print(f"Max threads: {scope.get('max_threads')}")
    if scope.get("max_request_rate"):
        print(f"Max request rate: {scope.get('max_request_rate')} req/s")
    auth_path = auth_store_path(base)
    if auth_path.exists():
        try:
            raw_auth = read_json_file(auth_path, {})
            profiles = raw_auth.get("profiles", raw_auth) if isinstance(raw_auth, dict) else {}
            if isinstance(profiles, dict):
                print(f"Auth profiles ({len(profiles)}): {', '.join(sorted(str(key) for key in profiles.keys())) or '-'}")
        except Exception as exc:
            print(f"Auth profiles: invalid ({exc})")
    print(f"Raw files: HTML={count_files(raw, ('.html', '.htm'))} JS={count_files(raw, ('.js',))}")
    if endpoints.exists():
        data = json.loads(endpoints.read_text(encoding="utf-8-sig", errors="ignore"))
        print(f"Endpoints: {data.get('total_unique')} unique / {data.get('total_raw')} raw")
        print(f"Endpoint file: {endpoints}")
    else:
        print("Endpoints: not extracted")
    if last_extract.exists():
        data = json.loads(last_extract.read_text(encoding="utf-8-sig", errors="ignore"))
        if data.get("previous_snapshot"):
            print(f"Previous snapshot: {data.get('previous_snapshot')}")
        if data.get("current_snapshot"):
            print(f"Current snapshot:  {data.get('current_snapshot')}")
    for name in (
        "katana_urls.txt",
        "katana_seeds.txt",
        "gau_urls.txt",
        "paramspider_urls.txt",
        "passive_urls.txt",
        "passive_seeds.txt",
        "passive_params.json",
        "crawl_seeds.txt",
        "last_katana.json",
        "last_gau.json",
        "last_paramspider.json",
        "probe_results.json",
        "ffuf-safe.json",
        "ffuf_candidates.json",
        "request_recipes.jsonl",
        "recipe_run_results.jsonl",
        "flow_tests.jsonl",
    ):
        path = base / "state" / name
        if path.exists():
            print(f"State artifact: {path}")
    if test_log.exists():
        count = sum(1 for line in test_log.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())
        print(f"Endpoint tests: {count} records ({test_log})")
    metric_log = metrics_path(base)
    if metric_log.exists():
        events = read_metric_events(base)
        print(f"Metrics: {len(events)} events ({metric_log})")
    flywheel = base / "state" / "flywheel.md"
    if flywheel.exists():
        print(f"Flywheel: {flywheel}")
    return 0



def count_files(path: Path, suffixes: tuple[str, ...]) -> int:
    if not path.exists():
        return 0
    return sum(1 for p in path.rglob("*") if p.is_file() and p.suffix.lower() in suffixes)

