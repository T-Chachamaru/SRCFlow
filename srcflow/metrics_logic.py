"""srcflow.metrics_logic - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from srcflow.io_helpers import endpoint_tests_path, flow_tests_path, metrics_path, read_endpoint_tests, read_flow_tests, read_json_file, read_metric_events, read_request_recipes, request_recipes_path
from srcflow.utils import counter_dict, eprint, event_data, latest_event, metric_display, number_value, read_lines_file, row_time, target_dir, utc_now

def summarize_target_metrics(base: Path) -> dict[str, object]:
    events = read_metric_events(base)
    event_counts = Counter(str(row.get("event", "")) for row in events if row.get("event"))

    endpoint_tests = read_endpoint_tests(base)
    request_recipes = read_request_recipes(base)
    flow_tests = read_flow_tests(base)
    if endpoint_tests:
        test_rows = endpoint_tests
    else:
        test_rows = [
            event_data(row)
            for row in events
            if row.get("event") == "endpoint_test"
        ]
    test_status_counts = Counter(
        str(row.get("status", "")).strip()
        for row in test_rows
        if str(row.get("status", "")).strip()
    )
    flow_status_counts = Counter(
        str(row.get("status", "")).strip()
        for row in flow_tests
        if str(row.get("status", "")).strip()
    )

    katana_events = [row for row in events if row.get("event") == "katana"]
    ffuf_events = [row for row in events if row.get("event") == "ffuf"]
    gau_events = [row for row in events if row.get("event") == "gau"]
    paramspider_events = [row for row in events if row.get("event") == "paramspider"]
    extract_events = [row for row in events if row.get("event") == "extract"]
    gate_events = [row for row in events if row.get("event") == "gate"]
    audit_events = [row for row in events if row.get("event") == "audit"]
    import_har_events = [row for row in events if row.get("event") == "import_har"]
    recipe_run_events = [row for row in events if row.get("event") == "recipe_run"]
    flow_test_events = [row for row in events if row.get("event") == "flow_test"]

    latest_audit = latest_event(events, "audit")
    latest_katana = latest_event(events, "katana")
    latest_ffuf = latest_event(events, "ffuf")
    latest_gau = latest_event(events, "gau")
    latest_paramspider = latest_event(events, "paramspider")
    latest_extract = latest_event(events, "extract")
    latest_crawl = latest_event(events, "crawl")
    latest_endpoint_test = latest_event(events, "endpoint_test")
    latest_gate = latest_event(events, "gate")
    latest_import_har = latest_event(events, "import_har")
    latest_recipe_run = latest_event(events, "recipe_run")
    latest_flow_test = latest_event(events, "flow_test")
    latest_passive = max(
        [row for row in (latest_gau, latest_paramspider) if row],
        key=lambda row: row_time(row),
        default=None,
    )

    katana_total = sum(number_value(event_data(row).get("scoped_url_count")) for row in katana_events)
    ffuf_total = sum(number_value(event_data(row).get("candidate_count")) for row in ffuf_events)
    gau_total = sum(
        number_value(event_data(row).get("raw_scoped_url_count", event_data(row).get("url_count")))
        for row in gau_events
    )
    paramspider_total = sum(
        number_value(event_data(row).get("raw_scoped_url_count", event_data(row).get("url_count")))
        for row in paramspider_events
    )
    extract_unique_counts = [
        number_value(event_data(row).get("total_unique"), -1)
        for row in extract_events
        if event_data(row).get("total_unique") is not None
    ]
    extract_unique_counts = [value for value in extract_unique_counts if value >= 0]

    gate_counts = Counter(
        "passed" if event_data(row).get("passed") else "failed"
        for row in gate_events
    )
    katana_profiles = Counter(
        str(event_data(row).get("profile") or "default")
        for row in katana_events
    )
    ffuf_profiles = Counter(
        str(event_data(row).get("profile") or "default")
        for row in ffuf_events
    )

    latest_audit_data = event_data(latest_audit)
    latest_extract_data = event_data(latest_extract)
    latest_katana_data = event_data(latest_katana)
    latest_ffuf_data = event_data(latest_ffuf)
    latest_gau_data = event_data(latest_gau)
    latest_paramspider_data = event_data(latest_paramspider)
    latest_gate_data = event_data(latest_gate)
    latest_import_har_data = event_data(latest_import_har)
    latest_recipe_run_data = event_data(latest_recipe_run)
    latest_flow_test_data = event_data(latest_flow_test)
    endpoint_test_time = (
        str(endpoint_tests[-1].get("time", ""))
        if endpoint_tests else row_time(latest_endpoint_test)
    )
    passive_url_file = base / "state" / "passive_urls.txt"
    passive_seed_file = base / "state" / "passive_seeds.txt"
    passive_params_file = base / "state" / "passive_params.json"
    passive_url_count = len(read_lines_file(passive_url_file))
    passive_seed_count = len(read_lines_file(passive_seed_file))
    passive_param_name_count = 0
    if passive_params_file.exists():
        passive_params = read_json_file(passive_params_file, {})
        if isinstance(passive_params, dict):
            passive_param_name_count = number_value(passive_params.get("total_param_names"))

    hints: list[str] = []
    if latest_audit_data.get("status") == "blocked":
        hints.append("Latest target audit is blocked; resolve audit blockers before active testing.")
    elif latest_audit_data.get("status") == "ready_with_warnings":
        hints.append("Latest target audit has warnings; keep them in mind but continue if no blocker affects the current direction.")
    if number_value(latest_katana_data.get("scoped_url_count")) > 0 and row_time(latest_katana) > row_time(latest_crawl):
        hints.append("Katana produced scoped seeds after the last crawl; consider recrawling before another extraction pass.")
    if passive_seed_count > 0 and row_time(latest_passive) > row_time(latest_crawl):
        hints.append("gau/ParamSpider produced passive seeds after the last crawl; include them in the next crawl/extract round.")
    if number_value(latest_ffuf_data.get("candidate_count")) > 0 and row_time(latest_ffuf) > endpoint_test_time:
        hints.append("ffuf produced candidates after the last logged endpoint test; review and manually verify them before reporting.")
    if len(extract_events) >= 2:
        last_total = event_data(extract_events[-1]).get("total_unique")
        prev_total = event_data(extract_events[-2]).get("total_unique")
        if (last_total is not None and prev_total is not None
                and number_value(last_total) == number_value(prev_total)):
            hints.append("Endpoint totals are flat across the last two extracts; prefer Network review, high-value JS review, or config refinement over repeating the same extraction.")
    if number_value(latest_extract_data.get("total_unique")) > 0 and not test_rows:
        hints.append("Endpoints exist but no endpoint tests are logged; start endpoint-family verification and record results with log-test.")
    if number_value(latest_extract_data.get("total_unique")) > 0 and not request_recipes:
        hints.append("Endpoints exist but no normal request recipes are logged; import HAR with --as-recipes or capture Network flows before judging behavior.")
    if request_recipes and not flow_tests:
        hints.append("Normal request recipes exist but no flow records exist; replay/compare representative recipes and record normal-flow status with log-flow.")
    if test_status_counts.get("needs normal flow", 0) or flow_status_counts.get("needs normal flow", 0):
        hints.append("Some tests still need a working normal business flow; prioritize browser Network observation and recipe replay before more probing.")
    if test_status_counts.get("needs param source", 0) or flow_status_counts.get("needs param source", 0):
        hints.append("Some tests lack parameter sources; review JS/HAR/passive_params.json and use narrow ffuf parameter discovery if justified.")
    if test_status_counts.get("needs more context", 0) > test_status_counts.get("confirmed", 0) + test_status_counts.get("rejected", 0):
        hints.append("Many tests need more context; revisit parameter sources, related endpoints, and browser Network traces.")
    if latest_gate and not latest_gate_data.get("passed"):
        hints.append("The latest report gate failed; fix gate failures before treating a finding as reportable.")
    if not hints:
        hints.append("No strong metric signal yet; continue with the current soft loop and log meaningful results.")

    return {
        "target": base.name,
        "metrics_file": str(metrics_path(base)),
        "endpoint_tests_file": str(endpoint_tests_path(base)),
        "event_count": len(events),
        "last_event_time": str(events[-1].get("time", "")) if events else "",
        "events_by_type": counter_dict(event_counts),
        "audit": {
            "runs": len(audit_events),
            "latest_status": str(latest_audit_data.get("status", "")) if latest_audit else "",
            "latest_blockers": number_value(latest_audit_data.get("blockers"), 0),
            "latest_warnings": number_value(latest_audit_data.get("warnings"), 0),
        },
        "endpoint_tests": {
            "records": len(endpoint_tests),
            "status_counts": counter_dict(test_status_counts),
        },
        "flows": {
            "records": len(flow_tests),
            "latest_status": str(latest_flow_test_data.get("status", "")) if latest_flow_test else "",
            "status_counts": counter_dict(flow_status_counts),
            "file": str(flow_tests_path(base)),
        },
        "recipes": {
            "records": len(request_recipes),
            "file": str(request_recipes_path(base)),
            "import_har_runs": len(import_har_events),
            "latest_import_total": number_value(latest_import_har_data.get("recipes_total"), -1),
            "runs": len(recipe_run_events),
            "latest_run_status": str(latest_recipe_run_data.get("status", "")) if latest_recipe_run else "",
            "latest_run_code": latest_recipe_run_data.get("status_code"),
        },
        "katana": {
            "runs": len(katana_events),
            "total_scoped_urls": katana_total,
            "latest_scoped_urls": number_value(latest_katana_data.get("scoped_url_count")),
            "profiles": counter_dict(katana_profiles),
        },
        "ffuf": {
            "runs": len(ffuf_events),
            "total_candidates": ffuf_total,
            "latest_candidates": number_value(latest_ffuf_data.get("candidate_count")),
            "profiles": counter_dict(ffuf_profiles),
        },
        "passive": {
            "gau_runs": len(gau_events),
            "paramspider_runs": len(paramspider_events),
            "total_gau_urls": gau_total,
            "total_paramspider_urls": paramspider_total,
            "latest_gau_urls": number_value(latest_gau_data.get("raw_scoped_url_count", latest_gau_data.get("url_count"))),
            "latest_paramspider_urls": number_value(latest_paramspider_data.get("raw_scoped_url_count", latest_paramspider_data.get("url_count"))),
            "passive_urls": passive_url_count,
            "passive_seeds": passive_seed_count,
            "passive_param_names": passive_param_name_count,
            "passive_urls_file": str(passive_url_file),
            "passive_seeds_file": str(passive_seed_file),
            "passive_params_file": str(passive_params_file),
        },
        "extract": {
            "runs": len(extract_events),
            "latest_total_unique": number_value(latest_extract_data.get("total_unique"), -1),
            "latest_total_raw": number_value(latest_extract_data.get("total_raw"), -1),
            "max_total_unique": max(extract_unique_counts) if extract_unique_counts else 0,
            "latest_delta_added": number_value(latest_extract_data.get("delta_added"), -1),
            "latest_delta_removed": number_value(latest_extract_data.get("delta_removed"), -1),
            "latest_delta_changed": number_value(latest_extract_data.get("delta_changed"), -1),
        },
        "gate": {
            "runs": len(gate_events),
            "counts": counter_dict(gate_counts),
            "latest_passed": bool(latest_gate_data.get("passed")) if latest_gate else None,
            "latest_failure_count": number_value(latest_gate_data.get("failure_count"), 0),
        },
        "hints": hints,
    }



def brief_event(row: dict[str, object]) -> str:
    data = event_data(row)
    parts = []
    for key in (
        "exit_code", "total_unique", "delta_added", "candidate_count",
        "scoped_url_count", "url_count", "seed_count", "param_name_count",
        "raw_scoped_url_count", "recipes_added", "recipes_total", "recipe_id", "status", "status_code",
        "passed", "completed", "ok", "skipped", "errors",
        "http_2xx", "http_3xx", "http_4xx", "http_5xx",
    ):
        if key in data and data.get(key) not in ("", None):
            parts.append(f"{key}={data.get(key)}")
    endpoint = data.get("endpoint")
    if endpoint:
        parts.append(f"endpoint={endpoint}")
    suffix = " " + " ".join(parts) if parts else ""
    return f"{row.get('time', '')} {row.get('event', '')}{suffix}"



def render_flywheel(base: Path, summary: dict[str, object]) -> str:
    endpoint_tests = summary.get("endpoint_tests", {})
    if not isinstance(endpoint_tests, dict):
        endpoint_tests = {}
    status_counts = endpoint_tests.get("status_counts", {})
    if not isinstance(status_counts, dict):
        status_counts = {}

    katana_raw = summary.get("katana", {})
    ffuf_raw = summary.get("ffuf", {})
    passive_raw = summary.get("passive", {})
    recipes_raw = summary.get("recipes", {})
    flows_raw = summary.get("flows", {})
    extract_raw = summary.get("extract", {})
    gate_raw = summary.get("gate", {})
    audit_raw = summary.get("audit", {})
    audit = audit_raw if isinstance(audit_raw, dict) else {}
    katana = katana_raw if isinstance(katana_raw, dict) else {}
    ffuf = ffuf_raw if isinstance(ffuf_raw, dict) else {}
    passive = passive_raw if isinstance(passive_raw, dict) else {}
    recipes = recipes_raw if isinstance(recipes_raw, dict) else {}
    flows = flows_raw if isinstance(flows_raw, dict) else {}
    extract = extract_raw if isinstance(extract_raw, dict) else {}
    gate = gate_raw if isinstance(gate_raw, dict) else {}
    flow_status_counts = flows.get("status_counts", {})
    if not isinstance(flow_status_counts, dict):
        flow_status_counts = {}

    what_worked = []
    if audit.get("latest_status") == "ready":
        what_worked.append("- Latest target audit is ready.")
    if number_value(katana.get("total_scoped_urls")):
        what_worked.append(f"- Katana contributed {katana.get('total_scoped_urls')} scoped URLs across {katana.get('runs')} run(s).")
    if number_value(passive.get("passive_urls")):
        what_worked.append(
            f"- gau/ParamSpider contributed {passive.get('passive_urls')} passive URLs, "
            f"{passive.get('passive_seeds')} crawl seeds, and {passive.get('passive_param_names')} parameter names."
        )
    if number_value(ffuf.get("total_candidates")):
        what_worked.append(f"- ffuf produced {ffuf.get('total_candidates')} scoped candidates across {ffuf.get('runs')} run(s).")
    if number_value(recipes.get("records")):
        what_worked.append(f"- Normal request recipes available: {recipes.get('records')}.")
    if number_value(flows.get("records")):
        what_worked.append(f"- Flow records available: {flows.get('records')}.")
    if number_value(extract.get("max_total_unique")):
        what_worked.append(f"- Endpoint extraction reached {extract.get('max_total_unique')} unique endpoints.")
    if number_value(status_counts.get("confirmed")):
        what_worked.append(f"- Confirmed findings: {status_counts.get('confirmed')}.")
    if not what_worked:
        what_worked.append("- Not enough recorded signal yet.")

    weak_spots = []
    if audit.get("latest_status") == "blocked":
        weak_spots.append(f"- Latest target audit is blocked with {audit.get('latest_blockers', 0)} blocker(s).")
    elif audit.get("latest_status") == "ready_with_warnings":
        weak_spots.append(f"- Latest target audit has {audit.get('latest_warnings', 0)} warning(s).")
    if not number_value(endpoint_tests.get("records")) and number_value(extract.get("latest_total_unique"), -1) > 0:
        weak_spots.append("- Extracted endpoints have not been converted into logged endpoint tests.")
    if not number_value(recipes.get("records")) and number_value(extract.get("latest_total_unique"), -1) > 0:
        weak_spots.append("- Extracted endpoints do not yet have normal request recipes from HAR/Network.")
    if number_value(recipes.get("records")) and not number_value(flows.get("records")):
        weak_spots.append("- Normal request recipes exist but no business-flow verification has been recorded.")
    if number_value(status_counts.get("needs normal flow")) or number_value(flow_status_counts.get("needs normal flow")):
        weak_spots.append("- Some endpoint decisions are blocked by missing normal-flow understanding.")
    if number_value(status_counts.get("needs param source")) or number_value(flow_status_counts.get("needs param source")):
        weak_spots.append("- Some endpoint decisions lack parameter provenance.")
    if number_value(status_counts.get("needs more context")):
        weak_spots.append(f"- Needs more context: {status_counts.get('needs more context')} logged test(s).")
    if number_value(gate.get("latest_failure_count")):
        weak_spots.append(f"- Latest report gate has {gate.get('latest_failure_count')} failure(s).")
    if number_value(extract.get("latest_delta_added"), -1) == 0:
        weak_spots.append("- Latest extraction added no new endpoints; discovery inputs may be saturated.")
    if not weak_spots:
        weak_spots.append("- No clear weak spot from metrics yet.")

    lessons = []
    katana_profiles = katana.get("profiles", {})
    ffuf_profiles = ffuf.get("profiles", {})
    if isinstance(katana_profiles, dict) and katana_profiles:
        lessons.append("- Katana profiles used: " + ", ".join(f"{k}={v}" for k, v in katana_profiles.items()) + ".")
    if isinstance(ffuf_profiles, dict) and ffuf_profiles:
        lessons.append("- ffuf profiles used: " + ", ".join(f"{k}={v}" for k, v in ffuf_profiles.items()) + ".")
    if number_value(passive.get("passive_param_names")):
        lessons.append("- Passive parameter inventory is available in state/passive_params.json; use it before blind parameter fuzzing.")
    if number_value(recipes.get("records")):
        lessons.append("- Prefer recipe-list/recipe-run to replay a known-good request before testing variants.")
    if status_counts:
        lessons.append("- Endpoint test outcomes: " + ", ".join(f"{k}={v}" for k, v in status_counts.items()) + ".")
    if flow_status_counts:
        lessons.append("- Flow outcomes: " + ", ".join(f"{k}={v}" for k, v in flow_status_counts.items()) + ".")
    if not lessons:
        lessons.append("- Keep recording tool runs and endpoint-test outcomes so the flywheel has material to learn from.")

    hints = summary.get("hints", [])
    if not isinstance(hints, list):
        hints = []
    prompt_patches = [f"- {hint}" for hint in hints] or ["- No prompt patch suggested yet."]

    lines = [
        f"# Flywheel Notes: {base.name}",
        "",
        f"Generated: {utc_now()}",
        "",
        "This is passive learning material for the next soft loop. It does not enforce a state machine.",
        "",
        "## Metrics Snapshot",
        "",
        f"- Events: {summary.get('event_count', 0)}",
        f"- Last event: {summary.get('last_event_time') or '-'}",
        f"- Latest audit: status={audit.get('latest_status') or '-'} blockers={metric_display(audit.get('latest_blockers'))} warnings={metric_display(audit.get('latest_warnings'))}",
        f"- Latest extract: unique={metric_display(extract.get('latest_total_unique'))} raw={metric_display(extract.get('latest_total_raw'))} delta_added={metric_display(extract.get('latest_delta_added'))}",
        f"- Passive discovery: urls={metric_display(passive.get('passive_urls'))} seeds={metric_display(passive.get('passive_seeds'))} params={metric_display(passive.get('passive_param_names'))}",
        f"- Recipes: records={metric_display(recipes.get('records'))} runs={metric_display(recipes.get('runs'))}",
        f"- Flow records: {metric_display(flows.get('records'))}",
        f"- Endpoint tests: {endpoint_tests.get('records', 0)}",
        f"- Gate runs: {gate.get('runs', 0)}",
        "",
        "## What Worked",
        "",
        *what_worked,
        "",
        "## Weak Spots",
        "",
        *weak_spots,
        "",
        "## Reusable Lessons",
        "",
        *lessons,
        "",
        "## Soft Loop Hints",
        "",
        *prompt_patches,
        "",
    ]
    return "\n".join(lines)


def cmd_metrics(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    summary = summarize_target_metrics(base)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    events_by_type = summary.get("events_by_type", {})
    audit = summary.get("audit", {})
    endpoint_tests = summary.get("endpoint_tests", {})
    flows = summary.get("flows", {})
    recipes = summary.get("recipes", {})
    katana = summary.get("katana", {})
    ffuf = summary.get("ffuf", {})
    passive = summary.get("passive", {})
    extract = summary.get("extract", {})
    gate = summary.get("gate", {})

    print(f"Target: {base.name}")
    print(f"Metrics: {summary.get('event_count', 0)} events ({metrics_path(base)})")
    print(f"Last event: {summary.get('last_event_time') or '-'}")
    if isinstance(events_by_type, dict) and events_by_type:
        print("Events by type: " + ", ".join(f"{k}={v}" for k, v in events_by_type.items()))
    if isinstance(audit, dict) and audit.get("runs"):
        print(
            f"Audit: runs={audit.get('runs')} latest={audit.get('latest_status') or '-'} "
            f"blockers={audit.get('latest_blockers', 0)} warnings={audit.get('latest_warnings', 0)}"
        )
    if isinstance(extract, dict) and extract.get("runs"):
        latest_unique = extract.get("latest_total_unique")
        latest_raw = extract.get("latest_total_raw")
        print(f"Extract: runs={extract.get('runs')} latest={metric_display(latest_unique)} unique / {metric_display(latest_raw)} raw max={extract.get('max_total_unique')}")
        if latest_unique != -1:
            print(
                "Extract delta: "
                f"added={metric_display(extract.get('latest_delta_added'))} "
                f"removed={metric_display(extract.get('latest_delta_removed'))} "
                f"changed={metric_display(extract.get('latest_delta_changed'))}"
            )
    if isinstance(katana, dict):
        print(f"Katana: runs={katana.get('runs')} latest_scoped={katana.get('latest_scoped_urls')} total_scoped={katana.get('total_scoped_urls')}")
    if isinstance(passive, dict):
        print(
            "Passive URLs: "
            f"gau_runs={passive.get('gau_runs')} paramspider_runs={passive.get('paramspider_runs')} "
            f"urls={passive.get('passive_urls')} seeds={passive.get('passive_seeds')} params={passive.get('passive_param_names')}"
        )
    if isinstance(ffuf, dict):
        print(f"ffuf: runs={ffuf.get('runs')} latest_candidates={ffuf.get('latest_candidates')} total_candidates={ffuf.get('total_candidates')}")
    if isinstance(recipes, dict):
        print(
            f"Recipes: records={recipes.get('records')} runs={recipes.get('runs')} "
            f"latest_run={recipes.get('latest_run_status') or '-'} status={metric_display(recipes.get('latest_run_code'))}"
        )
    if isinstance(flows, dict):
        status_counts = flows.get("status_counts", {})
        status_text = ", ".join(f"{k}={v}" for k, v in status_counts.items()) if isinstance(status_counts, dict) else ""
        print(f"Flows: {flows.get('records', 0)} records" + (f" ({status_text})" if status_text else ""))
    if isinstance(endpoint_tests, dict):
        status_counts = endpoint_tests.get("status_counts", {})
        status_text = ", ".join(f"{k}={v}" for k, v in status_counts.items()) if isinstance(status_counts, dict) else ""
        print(f"Endpoint tests: {endpoint_tests.get('records', 0)} records" + (f" ({status_text})" if status_text else ""))
    if isinstance(gate, dict):
        gate_counts = gate.get("counts", {})
        gate_text = ", ".join(f"{k}={v}" for k, v in gate_counts.items()) if isinstance(gate_counts, dict) else ""
        print(f"Gates: {gate.get('runs', 0)} runs" + (f" ({gate_text})" if gate_text else ""))

    hints = summary.get("hints", [])
    if isinstance(hints, list) and hints:
        print("Soft loop hints:")
        for hint in hints:
            print(f"- {hint}")

    if args.limit and args.limit > 0:
        events = read_metric_events(base)
        recent = events[-args.limit:]
        if recent:
            print("Recent events:")
            for row in recent:
                print(f"- {brief_event(row)}")
    return 0


def cmd_flywheel(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    summary = summarize_target_metrics(base)
    text = render_flywheel(base, summary)
    if args.out == "-":
        print(text)
        return 0

    out = Path(args.out) if args.out else base / "state" / "flywheel.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"Flywheel updated: {out}")
    if args.print_report:
        print(text)
    return 0

