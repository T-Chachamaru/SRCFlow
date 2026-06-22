"""srcflow.recipes - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

from srcflow.auth import load_auth_profile_for_args
from srcflow.har_import import find_recipe, recipe_method_path
from srcflow.io_helpers import append_jsonl, append_metric, read_request_recipes, request_recipes_path
from srcflow.scope import parse_scope, require_url_in_scope
from srcflow.utils import eprint, target_dir, utc_now

def cmd_recipe_list(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    recipes = read_request_recipes(base)
    if args.json:
        print(json.dumps({"target": base.name, "count": len(recipes), "recipes": recipes}, ensure_ascii=False, indent=2))
        return 0
    print(f"Recipes: {len(recipes)} ({request_recipes_path(base)})")
    for recipe in recipes[:args.limit]:
        params = recipe.get("param_names", [])
        param_text = ",".join(params) if isinstance(params, list) else ""
        print(f"- {recipe.get('id')} {recipe_method_path(recipe)} status={recipe.get('observed_status', '-')}" + (f" params={param_text}" if param_text else ""))
        print(f"  {recipe.get('url')}")
    return 0



def cmd_recipe_run(args: argparse.Namespace) -> int:
    if requests is None:
        eprint("Python package missing: requests")
        return 2
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    scope = parse_scope(base)
    recipe = find_recipe(base, args.recipe)
    if not recipe:
        eprint(f"Recipe not found or ambiguous: {args.recipe}")
        return 2
    url = str(recipe.get("url", ""))
    if not require_url_in_scope(base, scope, url):
        return 2
    auth = load_auth_profile_for_args(base, args.auth_profile)
    if args.auth_profile and auth is None:
        return 2
    headers = dict(recipe.get("headers", {})) if isinstance(recipe.get("headers"), dict) else {}
    auth_headers = auth.get("headers", {}) if isinstance(auth, dict) and isinstance(auth.get("headers"), dict) else {}
    headers.update(auth_headers)
    method = (args.method or str(recipe.get("method", "GET"))).upper()
    body = args.data if args.data is not None else str(recipe.get("body", "") or "")
    timeout = args.timeout
    started = time.time()
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            data=body if body else None,
            timeout=timeout,
            allow_redirects=not args.no_redirects,
        )
        elapsed_ms = int((time.time() - started) * 1000)
        text_sample = response.text[: args.body_sample] if args.body_sample else ""
        result = {
            "time": utc_now(),
            "target": base.name,
            "recipe_id": recipe.get("id"),
            "method": method,
            "url": url,
            "auth_profile": args.auth_profile,
            "status": "ok",
            "status_code": response.status_code,
            "elapsed_ms": elapsed_ms,
            "content_type": response.headers.get("content-type", ""),
            "length": len(response.content),
            "body_sample": text_sample,
        }
    except Exception as exc:
        result = {
            "time": utc_now(),
            "target": base.name,
            "recipe_id": recipe.get("id"),
            "method": method,
            "url": url,
            "auth_profile": args.auth_profile,
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    out = Path(args.out) if args.out else base / "state" / "recipe_run_results.jsonl"
    append_jsonl(out, result)
    append_metric(base, "recipe_run", {
        "recipe_id": recipe.get("id"),
        "method": method,
        "status": result.get("status"),
        "status_code": result.get("status_code"),
        "auth_profile": args.auth_profile,
    })
    print(f"Recipe run: {result.get('status')} status={result.get('status_code', '-')}")
    print(f"Result: {out}")
    return 0 if result.get("status") == "ok" else 1

