"""srcflow.passive - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from srcflow.constants import PASSIVE_STATIC_EXTENSIONS
from srcflow.exec_helpers import require_local_tool, run_capture, run_cmd
from srcflow.io_helpers import append_metric, write_json
from srcflow.scope import cap_int_by_scope, normalize_host, parse_scope, require_domain_in_scope, require_wrapper_allowed, scoped_urls_from_file, urls_from_line
from srcflow.utils import ensure_target_dirs, eprint, target_dir, utc_now

def passive_source_paths(base: Path) -> list[tuple[str, Path]]:
    return [
        ("gau", base / "state" / "gau_urls.txt"),
        ("paramspider", base / "state" / "paramspider_urls.txt"),
    ]



def passive_seed_candidates(urls: list[str]) -> list[str]:
    seeds: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        suffix = Path(parsed.path).suffix.lower()
        if suffix in PASSIVE_STATIC_EXTENSIONS:
            continue
        if url not in seeds:
            seeds.append(url)
    return seeds



def passive_param_summary(urls: list[str]) -> dict[str, object]:
    by_name: dict[str, dict[str, object]] = {}
    by_url = []
    for url in urls:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            continue
        names = []
        for key, value in pairs:
            if not key:
                continue
            names.append(key)
            item = by_name.setdefault(key, {"count": 0, "sample_values": [], "sample_urls": []})
            item["count"] = int(item.get("count", 0)) + 1
            values = item.setdefault("sample_values", [])
            if isinstance(values, list) and value and value not in values and len(values) < 5:
                values.append(value)
            sample_urls = item.setdefault("sample_urls", [])
            if isinstance(sample_urls, list) and url not in sample_urls and len(sample_urls) < 5:
                sample_urls.append(url)
        by_url.append({"url": url, "params": sorted(set(names))})
    return {
        "created_at": utc_now(),
        "total_urls_with_params": len(by_url),
        "total_param_names": len(by_name),
        "params": dict(sorted(by_name.items(), key=lambda item: (-int(item[1].get("count", 0)), item[0]))),
        "urls": by_url,
    }



def refresh_passive_state(base: Path, scope: dict[str, object]) -> dict[str, object]:
    all_urls: list[str] = []
    source_counts: dict[str, int] = {}
    for source, path in passive_source_paths(base):
        urls = scoped_urls_from_file(path, scope)
        source_counts[source] = len(urls)
        for url in urls:
            if url not in all_urls:
                all_urls.append(url)

    state_dir = base / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    passive_urls = state_dir / "passive_urls.txt"
    passive_seeds = state_dir / "passive_seeds.txt"
    passive_params = state_dir / "passive_params.json"

    seeds = passive_seed_candidates(all_urls)
    if all_urls:
        passive_urls.write_text("\n".join(all_urls) + "\n", encoding="utf-8")
    else:
        passive_urls.unlink(missing_ok=True)
    if seeds:
        passive_seeds.write_text("\n".join(seeds) + "\n", encoding="utf-8")
    else:
        passive_seeds.unlink(missing_ok=True)
    params = passive_param_summary(all_urls)
    write_json(passive_params, params)
    return {
        "url_count": len(all_urls),
        "seed_count": len(seeds),
        "param_name_count": params["total_param_names"],
        "urls_file": str(passive_urls) if all_urls else "",
        "seeds_file": str(passive_seeds) if seeds else "",
        "params_file": str(passive_params),
        "source_counts": source_counts,
    }



def cmd_gau_urls(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    if not require_wrapper_allowed(base, scope, "gau-urls"):
        return 2
    domain = normalize_host(args.domain)
    if not domain:
        eprint("Domain is required.")
        return 2
    if not require_domain_in_scope(base, scope, domain):
        return 2
    try:
        gau = require_local_tool("gau")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2

    out = Path(args.out) if args.out else base / "state" / "gau_urls.txt"
    threads = cap_int_by_scope(args.threads, scope, "max_threads", "gau threads")
    cmd = [gau, domain, "--o", str(out), "--threads", str(threads)]
    if args.blacklist:
        cmd.extend(["--blacklist", args.blacklist])
    if args.providers:
        cmd.extend(["--providers", args.providers])
    if args.from_date:
        cmd.extend(["--from", args.from_date])
    if args.to_date:
        cmd.extend(["--to", args.to_date])
    if args.fp:
        cmd.append("--fp")
    if args.subs:
        cmd.append("--subs")
    code = run_cmd(cmd, timeout=args.timeout)
    raw_scoped_count = len(scoped_urls_from_file(out, scope))
    summary = refresh_passive_state(base, scope)
    write_json(base / "state" / "last_gau.json", {
        "finished_at": utc_now(),
        "exit_code": code,
        "domain": domain,
        "source": str(out),
        "threads": threads,
        "timeout": args.timeout,
        "raw_scoped_url_count": raw_scoped_count,
        **summary,
    })
    append_metric(base, "gau", {
        "exit_code": code,
        "domain": domain,
        "source": str(out),
        "threads": threads,
        "timeout": args.timeout,
        "raw_scoped_url_count": raw_scoped_count,
        **summary,
    })
    print(f"Output: {out}")
    print(f"Passive URLs: {summary['url_count']} seeds={summary['seed_count']} params={summary['param_name_count']}")
    return code



def cmd_paramspider_urls(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    if not require_wrapper_allowed(base, scope, "paramspider-urls"):
        return 2
    domain = normalize_host(args.domain)
    if not domain:
        eprint("Domain is required.")
        return 2
    if not require_domain_in_scope(base, scope, domain):
        return 2
    try:
        paramspider = require_local_tool("paramspider")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2

    out = Path(args.out) if args.out else base / "state" / "paramspider_urls.txt"
    cmd = [paramspider, "-d", domain, "-s"]
    if args.placeholder:
        cmd.extend(["-p", args.placeholder])
    if args.proxy:
        cmd.extend(["--proxy", args.proxy])
    code, stdout = run_capture(cmd, cwd=base / "state", timeout=args.timeout)
    out.parent.mkdir(parents=True, exist_ok=True)
    urls = []
    for line in stdout.splitlines():
        for url in urls_from_line(line):
            if url not in urls:
                urls.append(url)
    out.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    raw_scoped_count = len(scoped_urls_from_file(out, scope))
    summary = refresh_passive_state(base, scope)
    write_json(base / "state" / "last_paramspider.json", {
        "finished_at": utc_now(),
        "exit_code": code,
        "domain": domain,
        "source": str(out),
        "timeout": args.timeout,
        "raw_url_count": len(urls),
        "raw_scoped_url_count": raw_scoped_count,
        **summary,
    })
    append_metric(base, "paramspider", {
        "exit_code": code,
        "domain": domain,
        "source": str(out),
        "timeout": args.timeout,
        "raw_url_count": len(urls),
        "raw_scoped_url_count": raw_scoped_count,
        **summary,
    })
    print(f"Output: {out}")
    print(f"Passive URLs: {summary['url_count']} seeds={summary['seed_count']} params={summary['param_name_count']}")
    return code

