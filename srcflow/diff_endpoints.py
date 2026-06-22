"""srcflow.diff_endpoints - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from srcflow.io_helpers import write_json

def endpoint_records(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    records: dict[str, dict] = {}
    for domain, items in data.get("by_domain", {}).items():
        for item in items:
            endpoint = item.get("endpoint")
            if endpoint:
                record = dict(item)
                record["domain"] = domain
                records[endpoint] = record
    for item in data.get("relative", []):
        endpoint = item.get("endpoint")
        if endpoint:
            record = dict(item)
            record["domain"] = "__RELATIVE__"
            records[endpoint] = record
    return records



def cmd_diff_endpoints(args: argparse.Namespace) -> int:
    old_path = Path(args.old)
    new_path = Path(args.new)
    old = endpoint_records(old_path)
    new = endpoint_records(new_path)
    old_keys = set(old)
    new_keys = set(new)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    common = sorted(old_keys & new_keys)
    changed = [
        endpoint for endpoint in common
        if old[endpoint].get("type") != new[endpoint].get("type")
        or old[endpoint].get("sources") != new[endpoint].get("sources")
        or old[endpoint].get("domain") != new[endpoint].get("domain")
    ]

    result = {
        "old": str(old_path),
        "new": str(new_path),
        "old_count": len(old),
        "new_count": len(new),
        "added": [{"endpoint": e, **new[e]} for e in added],
        "removed": [{"endpoint": e, **old[e]} for e in removed],
        "changed": [{"endpoint": e, "old": old[e], "new": new[e]} for e in changed],
    }

    if args.out:
        write_json(Path(args.out), result)

    print(f"Old: {len(old)} endpoints")
    print(f"New: {len(new)} endpoints")
    print(f"Added: {len(added)} Removed: {len(removed)} Changed: {len(changed)}")
    if added:
        print("\nAdded:")
        for endpoint in added[:args.limit]:
            print(f"  + {endpoint}")
    if removed:
        print("\nRemoved:")
        for endpoint in removed[:args.limit]:
            print(f"  - {endpoint}")
    if changed:
        print("\nChanged:")
        for endpoint in changed[:args.limit]:
            print(f"  * {endpoint}")
    if args.out:
        print(f"\nJSON: {args.out}")
    return 0



def iter_exported_endpoints(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
    endpoints: list[str] = []
    for items in data.get("by_domain", {}).values():
        for item in items:
            endpoint = item.get("endpoint")
            if endpoint:
                endpoints.append(endpoint)
    for item in data.get("relative", []):
        endpoint = item.get("endpoint")
        if endpoint:
            endpoints.append(endpoint)
    return sorted(set(endpoints))

