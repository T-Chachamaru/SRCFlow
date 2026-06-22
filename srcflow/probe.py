"""srcflow.probe - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None

from srcflow.auth import load_auth_profile_for_args
from srcflow.diff_endpoints import iter_exported_endpoints
from srcflow.io_helpers import append_metric, write_json
from srcflow.scope import delay_from_scope, parse_scope, require_scope_ready, require_url_in_scope, scope_list, url_in_scope
from srcflow.utils import counter_dict, ensure_target_dirs, eprint, target_dir, utc_now

def http_status_class(status_code: object) -> str:
    if not isinstance(status_code, int):
        return "unknown"
    if 100 <= status_code <= 599:
        return f"{status_code // 100}xx"
    return "unknown"



def cmd_probe(args: argparse.Namespace) -> int:
    if requests is None:
        eprint("Python package missing: requests")
        return 2

    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    if not require_scope_ready(base, scope):
        return 2
    if args.base_url and not require_url_in_scope(base, scope, args.base_url, "base-url"):
        return 2
    endpoints_file = Path(args.endpoints) if args.endpoints else base / "state" / "endpoints.json"
    if not endpoints_file.exists():
        eprint(f"Endpoints file not found: {endpoints_file}")
        return 2

    endpoints = iter_exported_endpoints(endpoints_file)
    if args.limit:
        endpoints = endpoints[:args.limit]

    auth = load_auth_profile_for_args(base, args.auth_profile)
    if args.auth_profile and auth is None:
        return 2
    headers = {"User-Agent": "AI-SRC-Agent/1.0 authorized-security-assessment"}
    auth_headers = auth.get("headers") if auth else {}
    if isinstance(auth_headers, dict):
        for key, value in auth_headers.items():
            if str(key).strip() and str(value).strip():
                headers[str(key).strip()] = str(value).strip()
    if args.authorization:
        headers["Authorization"] = args.authorization
    if args.cookie:
        headers["Cookie"] = args.cookie

    delay = delay_from_scope(args.delay, scope)
    results = []
    session = requests.Session()
    for endpoint in endpoints:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            url = endpoint
        elif args.base_url:
            url = urljoin(args.base_url.rstrip("/") + "/", endpoint.lstrip("/"))
        else:
            results.append({"endpoint": endpoint, "status": "skipped", "reason": "relative endpoint without --base-url"})
            continue

        record = {"endpoint": endpoint, "url": url, "method": args.method}
        if not url_in_scope(url, scope):
            record.update({"status": "skipped", "reason": "out-of-scope"})
            results.append(record)
            continue
        try:
            response = session.request(
                args.method,
                url,
                headers=headers,
                timeout=args.timeout,
                allow_redirects=False,
            )
            record.update({
                "status": "ok",
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "content_length": response.headers.get("Content-Length", ""),
                "location": response.headers.get("Location", ""),
                "auth_hint": response.status_code in {401, 403},
            })
        except requests.RequestException as exc:
            record.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"})
        results.append(record)
        if delay > 0:
            time.sleep(delay)

    ok = sum(1 for item in results if item.get("status") == "ok")
    skipped = sum(1 for item in results if item.get("status") == "skipped")
    errors = sum(1 for item in results if item.get("status") == "error")
    status_classes = Counter(
        http_status_class(item.get("status_code"))
        for item in results
        if item.get("status") == "ok"
    )
    status_codes = Counter(
        str(item.get("status_code"))
        for item in results
        if item.get("status") == "ok" and item.get("status_code") is not None
    )
    summary = {
        "completed": ok,
        "skipped": skipped,
        "errors": errors,
        "http_status_classes": counter_dict(status_classes),
        "http_status_codes": counter_dict(status_codes),
    }
    out = Path(args.out) if args.out else base / "state" / "probe_results.json"
    write_json(out, {
        "target": base.name,
        "created_at": utc_now(),
        "method": args.method,
        "headers": headers,
        "auth_profile": args.auth_profile,
        "endpoints_file": str(endpoints_file),
        "scope_domains": scope_list(scope, "domains"),
        "scope_ip_ranges": scope_list(scope, "ip_ranges"),
        "summary": summary,
        "results": results,
    })
    print(
        f"Probe complete: completed={ok} skipped={skipped} errors={errors} "
        f"2xx={status_classes.get('2xx', 0)} 3xx={status_classes.get('3xx', 0)} "
        f"4xx={status_classes.get('4xx', 0)} 5xx={status_classes.get('5xx', 0)}"
    )
    print(f"Output: {out}")
    append_metric(base, "probe", {
        "method": args.method,
        "endpoints_file": str(endpoints_file),
        "output": str(out),
        "ok": ok,
        "completed": ok,
        "skipped": skipped,
        "errors": errors,
        "http_status_classes": summary["http_status_classes"],
        "http_status_codes": summary["http_status_codes"],
        "http_2xx": status_classes.get("2xx", 0),
        "http_3xx": status_classes.get("3xx", 0),
        "http_4xx": status_classes.get("4xx", 0),
        "http_5xx": status_classes.get("5xx", 0),
        "limit": args.limit,
    })
    return 0 if errors == 0 else 1

