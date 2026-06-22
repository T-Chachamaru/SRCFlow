"""srcflow.har_import - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from srcflow.constants import HOP_BY_HOP_HEADERS
from srcflow.io_helpers import append_jsonl, append_metric, read_request_recipes, request_recipes_path, write_json
from srcflow.scope import parse_scope, require_scope_ready, url_in_scope
from srcflow.utils import eprint, target_dir, utc_now

def query_keys_from_url(url: str) -> list[str]:
    parsed = urlparse(url)
    if not parsed.query:
        return []
    keys = []
    for part in parsed.query.split("&"):
        key = part.split("=", 1)[0]
        if key and key not in keys:
            keys.append(key)
    return keys



def body_keys_from_har(post_data: dict) -> list[str]:
    keys: list[str] = []
    for param in post_data.get("params", []) or []:
        name = param.get("name")
        if name and name not in keys:
            keys.append(name)
    text = post_data.get("text")
    if text:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return keys
        if isinstance(obj, dict):
            for key in obj:
                if key not in keys:
                    keys.append(key)
    return keys



def har_headers_to_dict(headers: list[dict[str, object]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in headers or []:
        name = str(item.get("name", "")).strip()
        value = str(item.get("value", "")).strip()
        if not name or name.lower() in HOP_BY_HOP_HEADERS:
            continue
        result[name] = value
    return result



def recipe_id(method: str, url: str, body: str) -> str:
    digest = hashlib.sha1(f"{method.upper()} {url}\n{body}".encode("utf-8", errors="ignore")).hexdigest()
    return digest[:12]



def recipe_from_har_entry(entry: dict[str, object], target: str) -> dict[str, object] | None:
    request = entry.get("request", {})
    response = entry.get("response", {})
    if not isinstance(request, dict):
        return None
    url = str(request.get("url", ""))
    if not url.startswith(("http://", "https://")):
        return None
    method = str(request.get("method", "GET")).upper()
    post_data = request.get("postData", {}) or {}
    if not isinstance(post_data, dict):
        post_data = {}
    body = str(post_data.get("text", "") or "")
    headers = har_headers_to_dict(request.get("headers", []) if isinstance(request.get("headers"), list) else [])
    query_keys = query_keys_from_url(url)
    body_keys = body_keys_from_har(post_data)
    parsed = urlparse(url)
    status = response.get("status") if isinstance(response, dict) else None
    mime = ""
    if isinstance(response, dict):
        content = response.get("content", {})
        if isinstance(content, dict):
            mime = str(content.get("mimeType", "") or "")
    return {
        "id": recipe_id(method, url, body),
        "time": utc_now(),
        "target": target,
        "source": "har",
        "method": method,
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "headers": headers,
        "body": body,
        "mime_type": mime,
        "observed_status": status,
        "query_keys": query_keys,
        "body_keys": body_keys,
        "param_names": sorted(set(query_keys + body_keys)),
        "normal_flow": {
            "baseline_status": status,
            "success_indicators": [],
            "required_preconditions": [],
            "resource_ids": [],
            "notes": "",
        },
    }



def append_unique_recipes(base: Path, recipes: list[dict[str, object]]) -> tuple[int, int]:
    path = request_recipes_path(base)
    existing = read_request_recipes(base)
    seen = {str(row.get("id", "")) for row in existing if row.get("id")}
    added = 0
    for recipe in recipes:
        rid = str(recipe.get("id", ""))
        if not rid or rid in seen:
            continue
        append_jsonl(path, recipe)
        seen.add(rid)
        added += 1
    return added, len(existing) + added



def recipe_method_path(recipe: dict[str, object]) -> str:
    method = str(recipe.get("method", "") or "GET").upper()
    path = str(recipe.get("path") or urlparse(str(recipe.get("url", ""))).path or "/")
    return f"{method} {path}"



def find_recipe(base: Path, value: str) -> dict[str, object] | None:
    recipes = read_request_recipes(base)
    for recipe in recipes:
        if str(recipe.get("id", "")) == value:
            return recipe
    matches = [
        recipe for recipe in recipes
        if value.lower() in str(recipe.get("url", "")).lower()
        or value.lower() in recipe_method_path(recipe).lower()
    ]
    if len(matches) == 1:
        return matches[0]
    return None



def cmd_import_har(args: argparse.Namespace) -> int:
    har_path = Path(args.har)
    if not har_path.exists():
        eprint(f"HAR file not found: {har_path}")
        return 2
    try:
        data = json.loads(har_path.read_text(encoding="utf-8-sig", errors="ignore"))
    except json.JSONDecodeError as exc:
        eprint(f"HAR file is not valid JSON: {exc}")
        return 2
    if not isinstance(data, dict):
        eprint("HAR file is not a valid JSON object")
        return 2
    entries = data.get("log", {}).get("entries", [])
    workspace_base = None
    workspace_scope: dict[str, object] | None = None
    if args.workspace_target:
        workspace_base = target_dir(args.workspace_target)
        if not workspace_base.exists():
            eprint(f"Target not found: {workspace_base}")
            return 2
        workspace_scope = parse_scope(workspace_base)
        if not require_scope_ready(workspace_base, workspace_scope):
            return 2
    if args.as_recipes and not workspace_base:
        eprint("Warning: --as-recipes requires --workspace-target; recipes will not be saved.")
    results = []
    recipes = []
    hosts: set[str] = set()
    prefixes: set[str] = set()
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        if not url.startswith(("http://", "https://")):
            continue
        parsed = urlparse(url)
        if args.target and args.target.lower() not in parsed.netloc.lower():
            continue
        if workspace_scope is not None and not url_in_scope(url, workspace_scope):
            continue
        path = parsed.path or "/"
        parts = [p for p in path.split("/") if p]
        if parts:
            prefixes.add("/" + parts[0] + "/")
        hosts.add(parsed.netloc)
        post_data = request.get("postData", {}) or {}
        record = {
            "method": request.get("method", ""),
            "url": url,
            "host": parsed.netloc,
            "path": path,
            "status": response.get("status"),
            "mimeType": response.get("content", {}).get("mimeType", ""),
            "query_keys": query_keys_from_url(url),
            "body_keys": body_keys_from_har(post_data),
        }
        results.append(record)
        if args.as_recipes and workspace_base:
            recipe = recipe_from_har_entry(entry, workspace_base.name)
            if recipe:
                recipes.append(recipe)

    export = {
        "har": str(har_path),
        "created_at": utc_now(),
        "workspace_target": workspace_base.name if workspace_base else "",
        "total": len(results),
        "hosts": sorted(hosts),
        "suggested_api_prefixes": sorted(prefixes),
        "requests": results,
    }
    if args.as_endpoints:
        url_source_count: dict[str, int] = {}
        path_info: dict[str, dict] = {}
        for record in results:
            endpoint = record["url"]
            url_source_count[endpoint] = url_source_count.get(endpoint, 0) + 1
            path = record["path"]
            if path and path != "/":
                if path not in path_info:
                    path_info[path] = {
                        "types": set(),
                        "query_keys": set(),
                        "body_keys": set(),
                        "method": record["method"],
                    }
                info = path_info[path]
                info["types"].add(f"HAR_{record['method'] or 'REQUEST'}")
                info["query_keys"].update(record["query_keys"])
                info["body_keys"].update(record["body_keys"])
        by_domain: dict[str, list[dict]] = {}
        relative: dict[str, dict] = {}
        seen_endpoints: set[str] = set()
        emitted_urls: set[str] = set()
        for record in results:
            endpoint = record["url"]
            if endpoint in emitted_urls:
                continue
            emitted_urls.add(endpoint)
            src_count = url_source_count[endpoint]
            by_domain.setdefault(record["host"], []).append({
                "endpoint": endpoint,
                "sources": src_count,
                "type": f"HAR_{record['method'] or 'REQUEST'}",
                "normalized": endpoint,
                "method": record["method"],
                "status": record["status"],
                "query_keys": record["query_keys"],
                "body_keys": record["body_keys"],
            })
            path = record["path"]
            if path and path != "/":
                info = path_info[path]
                relative[path] = {
                    "endpoint": path,
                    "sources": src_count,
                    "type": ",".join(sorted(info["types"])),
                    "normalized": path,
                    "method": info["method"],
                    "query_keys": sorted(info["query_keys"]),
                    "body_keys": sorted(info["body_keys"]),
                }
                seen_endpoints.add(path)
            else:
                seen_endpoints.add(endpoint)
        export = {
            "total_unique": len(seen_endpoints),
            "total_raw": len(results),
            "sites_dir": "",
            "target_keywords": [args.target] if args.target else [],
            "config": "",
            "workspace_target": workspace_base.name if workspace_base else "",
            "by_domain": by_domain,
            "relative": sorted(relative.values(), key=lambda item: item["endpoint"]),
            "special": [],
            "source": {
                "type": "har",
                "path": str(har_path),
                "hosts": sorted(hosts),
                "suggested_api_prefixes": sorted(prefixes),
            },
        }
    out = Path(args.out) if args.out else har_path.with_suffix(".endpoints.json")
    write_json(out, export)
    print(f"HAR requests: {len(results)}")
    print(f"Hosts: {', '.join(sorted(hosts)) or '-'}")
    print(f"Suggested prefixes: {', '.join(sorted(prefixes)) or '-'}")
    print(f"JSON: {out}")
    recipe_added = 0
    recipe_total = 0
    if args.as_recipes and workspace_base:
        recipe_added, recipe_total = append_unique_recipes(workspace_base, recipes)
        print(f"Recipes: added={recipe_added} total={recipe_total} -> {request_recipes_path(workspace_base)}")
    if workspace_base:
        append_metric(workspace_base, "import_har", {
            "har": str(har_path),
            "output": str(out),
            "total": len(results),
            "hosts": sorted(hosts),
            "as_endpoints": bool(args.as_endpoints),
            "as_recipes": bool(args.as_recipes),
            "recipes_added": recipe_added,
            "recipes_total": recipe_total,
        })
    return 0

