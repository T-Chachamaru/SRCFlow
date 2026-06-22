"""srcflow.rank_js - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from srcflow.constants import JS_RANK_KEYWORDS
from srcflow.io_helpers import write_json
from srcflow.utils import eprint

def manifest_url_by_path(sites_dir: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    manifest = sites_dir / "manifest.jsonl"
    if not manifest.exists():
        return result
    for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        local_path = row.get("path") or row.get("file") or row.get("local_path")
        url = row.get("url", "")
        if local_path and url:
            result[str(Path(local_path))] = url
    return result



def cmd_rank_js(args: argparse.Namespace) -> int:
    sites_dir = Path(args.sites_dir)
    if not sites_dir.exists():
        eprint(f"sites dir not found: {sites_dir}")
        return 2
    url_map = manifest_url_by_path(sites_dir)
    rows = []
    for path in sites_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".js", ".html", ".htm"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        score = 0
        hits = {}
        for keyword, weight in JS_RANK_KEYWORDS.items():
            count = text.count(keyword)
            if count:
                hits[keyword] = count
                score += min(count, 10) * weight
        size = path.stat().st_size
        score += min(size // 50_000, 20)
        rows.append({
            "path": str(path),
            "size": size,
            "score": score,
            "hits": hits,
            "url": url_map.get(str(path), ""),
        })
    rows.sort(key=lambda item: (-item["score"], -item["size"], item["path"]))
    if args.out:
        write_json(Path(args.out), {"sites_dir": str(sites_dir), "files": rows})
    print(f"Ranked files: {len(rows)}")
    for item in rows[:args.limit]:
        print(f"{item['score']:4} {item['size']:8} {item['path']}")
        if item["hits"]:
            print("     " + ", ".join(f"{k}={v}" for k, v in sorted(item["hits"].items())))
    if args.out:
        print(f"JSON: {args.out}")
    return 0

