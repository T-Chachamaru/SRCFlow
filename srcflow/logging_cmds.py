"""srcflow.logging_cmds - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urljoin

from srcflow.constants import FLOW_STATUS_VALUES, TEST_STATUS_VALUES
from srcflow.har_import import find_recipe, recipe_method_path
from srcflow.io_helpers import append_jsonl, append_metric, endpoint_tests_path, flow_tests_path
from srcflow.scope import parse_scope, require_url_in_scope, scope_list, url_in_scope
from srcflow.utils import ensure_target_dirs, eprint, target_dir, utc_now

def cmd_log_test(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists() or not (base / "scope.md").exists():
        eprint(f"Target not found or missing scope.md: {base}")
        eprint(f"Run: python ai_src.py init-target {args.target} --wizard")
        return 2
    ensure_target_dirs(base)
    scope = parse_scope(base)
    endpoint = args.endpoint.strip()
    if not endpoint:
        eprint("Endpoint is required.")
        return 2

    effective_url = ""
    if endpoint.startswith(("http://", "https://")):
        effective_url = endpoint
    elif args.base_url:
        if not require_url_in_scope(base, scope, args.base_url, "base-url"):
            return 2
        effective_url = urljoin(args.base_url.rstrip("/") + "/", endpoint.lstrip("/"))
    else:
        seeds = scope_list(scope, "seeds")
        if len(seeds) == 1:
            candidate = urljoin(seeds[0].rstrip("/") + "/", endpoint.lstrip("/"))
            if url_in_scope(candidate, scope):
                effective_url = candidate
        if not effective_url:
            eprint(f"Relative endpoint requires --base-url to determine scope. Endpoint: {endpoint}")
            eprint(f"Provide --base-url with an in-scope URL, or use an absolute endpoint URL.")
            return 2

    if effective_url and not url_in_scope(effective_url, scope):
        eprint(f"Scope blocked: endpoint is outside targets/{base.name}/scope.md: {effective_url}")
        return 2

    record = {
        "time": utc_now(),
        "target": base.name,
        "endpoint": endpoint,
        "url": effective_url,
        "recipe_id": args.recipe_id,
        "flow": args.flow,
        "method": args.method.upper() if args.method else "",
        "status": TEST_STATUS_VALUES[args.status],
        "params": args.params,
        "function": args.function,
        "attack_surface": args.attack_surface,
        "auth_context": args.auth_context,
        "requests": args.requests,
        "expected": args.expected,
        "actual": args.actual,
        "evidence": args.evidence,
        "next": args.next,
        "notes": args.notes,
    }
    out = endpoint_tests_path(base)
    append_jsonl(out, record)
    append_metric(base, "endpoint_test", {
        "endpoint": endpoint,
        "method": record["method"],
        "status": record["status"],
        "function": args.function,
        "attack_surface": args.attack_surface,
    })
    print(f"Endpoint test logged: {out}")
    return 0



def cmd_log_flow(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists() or not (base / "scope.md").exists():
        eprint(f"Target not found or missing scope.md: {base}")
        eprint(f"Run: python ai_src.py init-target {args.target} --wizard")
        return 2
    ensure_target_dirs(base)
    recipe = None
    if args.recipe:
        recipe = find_recipe(base, args.recipe)
        if not recipe:
            eprint(f"Recipe not found or ambiguous: {args.recipe}")
            return 2
    record = {
        "time": utc_now(),
        "target": base.name,
        "flow": args.flow,
        "recipe_id": recipe.get("id") if recipe else args.recipe,
        "endpoint": args.endpoint or (recipe_method_path(recipe) if recipe else ""),
        "status": FLOW_STATUS_VALUES[args.status],
        "auth_context": args.auth_context,
        "preconditions": args.preconditions,
        "param_sources": args.param_sources,
        "success_indicators": args.success_indicators,
        "variant_plan": args.variant_plan,
        "actual": args.actual,
        "next": args.next,
        "notes": args.notes,
    }
    append_jsonl(flow_tests_path(base), record)
    append_metric(base, "flow_test", {
        "flow": args.flow,
        "recipe_id": record["recipe_id"],
        "status": record["status"],
        "endpoint": record["endpoint"],
    })
    print(f"Flow logged: {flow_tests_path(base)}")
    return 0



def cmd_checkpoint(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        eprint(f"Run: python ai_src.py init-target {args.target} --wizard")
        return 2
    ensure_target_dirs(base)
    checkpoint = base / "state" / "context_checkpoint.md"
    existing = checkpoint.read_text(encoding="utf-8", errors="ignore") if checkpoint.exists() else ""
    entry = [
        f"\n## {utc_now()}",
        "",
        "### Current Direction",
        args.direction or "TODO",
        "",
        "### Tested",
        args.tested or "TODO",
        "",
        "### Findings / Leads",
        args.findings or "TODO",
        "",
        "### Next",
        args.next or "TODO",
        "",
    ]
    checkpoint.write_text(existing + "\n".join(entry), encoding="utf-8")
    append_metric(base, "checkpoint", {
        "has_direction": bool(args.direction),
        "has_tested": bool(args.tested),
        "has_findings": bool(args.findings),
        "has_next": bool(args.next),
    })
    print(f"Checkpoint updated: {checkpoint}")
    return 0

