"""srcflow.crawler - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from srcflow.auth import load_auth_profile_for_args
from srcflow.constants import ROOT
from srcflow.diff_endpoints import endpoint_records
from srcflow.exec_helpers import run_cmd
from srcflow.io_helpers import append_metric, write_json
from srcflow.scope import cap_int_by_scope, delay_from_scope, parse_scope, scope_list, snapshot_file, url_in_scope, write_scoped_seed_file
from srcflow.utils import display_command, ensure_target_dirs, eprint, load_config, read_lines_file, target_dir, utc_now

def cmd_crawl(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    scope_domains = scope_list(scope, "domains")
    cli_target_domains = list(args.target_kw or [])
    allowed_domains = scope_domains + cli_target_domains
    if not allowed_domains:
        eprint("No domains found. Add targets/<target>/domains.txt, scope.md, or pass --target-kw.")
        return 2

    try:
        _config_path, tool_config = load_config(args.config)
    except Exception as exc:
        eprint(f"Config invalid: {type(exc).__name__}: {exc}")
        return 1

    seeds_to_validate = list(args.seed or []) + scope_list(scope, "seeds")
    for seed in tool_config.get("extra_seeds", []) or []:
        seeds_to_validate.append(str(seed))
    for seed in seeds_to_validate:
        if not url_in_scope(seed, scope, cli_target_domains):
            eprint(f"Scope blocked: crawl seed is outside targets/{base.name}/scope.md: {seed}")
            return 2

    outdir = base / "raw" / "remote_sites"
    threads = cap_int_by_scope(args.threads, scope, "max_threads", "threads")
    delay = delay_from_scope(args.delay, scope)
    auth = load_auth_profile_for_args(base, args.auth_profile)
    if args.auth_profile and auth is None:
        return 2
    profile_cookie = str(auth.get("cookie") or "") if auth else ""
    profile_authorization = str(auth.get("authorization") or "") if auth else ""
    cookie = args.cookie or profile_cookie
    authorization = args.authorization or profile_authorization
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "download_remote_sites.py"),
        "--config",
        args.config,
        "--out",
        str(outdir),
        "--root",
        str(base),
        "--threads",
        str(threads),
        "--depth",
        str(args.depth),
        "--mode",
        args.mode,
        "--max-size",
        str(args.max_size),
        "--timeout",
        str(args.timeout),
    ]
    if delay > 0:
        cmd.extend(["--delay", f"{delay:.3f}"])
    if args.include_css:
        cmd.append("--include-css")
    if args.include_json:
        cmd.append("--include-json")
    if args.parse_json_links:
        cmd.append("--parse-json-links")
    if args.render:
        cmd.append("--render")
        cmd.extend(["--render-timeout", str(args.render_timeout)])
        cmd.extend(["--render-depth", str(args.render_depth)])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if authorization:
        cmd.extend(["--authorization", authorization])
    if args.max_urls:
        cmd.extend(["--max-urls", str(args.max_urls)])
    if args.batch_size:
        cmd.extend(["--batch-size", str(args.batch_size)])

    katana_seed_count = 0
    katana_seed_file = base / "state" / "katana_seeds.txt"
    if not args.no_katana_seeds:
        katana_source = base / "state" / "katana_urls.txt"
        if katana_source.exists():
            katana_seed_count = write_scoped_seed_file(katana_source, katana_seed_file, scope, cli_target_domains)
            if katana_seed_count == 0:
                katana_seed_file.unlink(missing_ok=True)
        elif katana_seed_file.exists():
            katana_seed_count = len(read_lines_file(katana_seed_file))

    passive_seed_count = 0
    passive_seed_file = base / "state" / "passive_seeds.txt"
    if not args.no_passive_seeds and passive_seed_file.exists():
        passive_seed_count = len(read_lines_file(passive_seed_file))

    combined_seed_file = base / "state" / "crawl_seeds.txt"
    combined_seeds: list[str] = []
    seed_files: list[Path] = []
    if not args.no_katana_seeds:
        seed_files.append(katana_seed_file)
    if not args.no_passive_seeds:
        seed_files.append(passive_seed_file)
    for seed_file in seed_files:
        for seed in read_lines_file(seed_file):
            if seed not in combined_seeds:
                combined_seeds.append(seed)
    if combined_seeds:
        combined_seed_file.write_text("\n".join(combined_seeds) + "\n", encoding="utf-8")
        cmd.extend(["--seed-file", str(combined_seed_file)])
    else:
        combined_seed_file.unlink(missing_ok=True)

    targets = cli_target_domains + scope_domains
    for domain in sorted(set(targets)):
        cmd.extend(["--target", domain])
    for seed in sorted(set(args.seed or [])):
        cmd.extend(["--seed", seed])
    for seed in scope_list(scope, "seeds"):
        cmd.extend(["--seed", seed])

    process_timeout = args.process_timeout if args.process_timeout > 0 else None
    code = run_cmd(cmd, timeout=process_timeout)
    crawl_state = {
        "finished_at": utc_now(),
        "exit_code": code,
        "outdir": str(outdir),
        "domains": scope_domains,
        "seeds": scope_list(scope, "seeds") + list(args.seed or []),
        "katana_seed_file": str(katana_seed_file) if katana_seed_count else "",
        "katana_seed_count": katana_seed_count,
        "passive_seed_file": str(passive_seed_file) if passive_seed_count else "",
        "passive_seed_count": passive_seed_count,
        "combined_seed_file": str(combined_seed_file) if combined_seeds else "",
        "combined_seed_count": len(combined_seeds),
        "config": args.config,
        "mode": args.mode,
        "depth": args.depth,
        "threads": threads,
        "delay": delay,
        "auth_profile": args.auth_profile,
        "auth_cookie": bool(cookie),
        "auth_authorization": bool(authorization),
        "process_timeout": args.process_timeout,
    }
    write_json(base / "state" / "last_crawl.json", crawl_state)
    append_metric(base, "crawl", {
        "exit_code": code,
        "domains_count": len(scope_domains),
        "seeds_count": len(crawl_state["seeds"]),
        "katana_seed_count": katana_seed_count,
        "passive_seed_count": passive_seed_count,
        "combined_seed_count": len(combined_seeds),
        "config": args.config,
        "mode": args.mode,
        "depth": args.depth,
        "threads": threads,
        "auth_profile": args.auth_profile,
        "auth_cookie": bool(cookie),
        "auth_authorization": bool(authorization),
        "process_timeout": args.process_timeout,
    })
    return code



def cmd_extract(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    sites_dir = Path(args.sites_dir) if args.sites_dir else base / "raw" / "remote_sites"
    out = Path(args.out) if args.out else base / "state" / "endpoints.json"
    previous_snapshot = snapshot_file(out, base / "state" / "snapshots", "endpoints-before")

    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "extract_remote_eps.py"),
        "--config",
        args.config,
        "--sites-dir",
        str(sites_dir),
        "--out",
        str(out),
    ]
    for domain in sorted(set(scope_list(scope, "domains") + list(args.target_kw or []))):
        cmd.extend(["--target", domain])
    if args.all_domains:
        cmd.append("--all-domains")
    if args.no_known:
        cmd.append("--no-known")

    code = run_cmd(cmd)
    if out.exists():
        export = json.loads(out.read_text(encoding="utf-8-sig", errors="ignore"))
        post_snapshot = snapshot_file(out, base / "state" / "snapshots", "endpoints-after")
        delta = {"delta_added": None, "delta_removed": None, "delta_changed": None}
        if previous_snapshot and post_snapshot:
            try:
                old_records = endpoint_records(previous_snapshot)
                new_records = endpoint_records(post_snapshot)
                old_keys = set(old_records)
                new_keys = set(new_records)
                changed = [
                    endpoint for endpoint in old_keys & new_keys
                    if old_records[endpoint].get("type") != new_records[endpoint].get("type")
                    or old_records[endpoint].get("sources") != new_records[endpoint].get("sources")
                    or old_records[endpoint].get("domain") != new_records[endpoint].get("domain")
                ]
                delta = {
                    "delta_added": len(new_keys - old_keys),
                    "delta_removed": len(old_keys - new_keys),
                    "delta_changed": len(changed),
                }
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                pass
        extract_state = {
            "finished_at": utc_now(),
            "exit_code": code,
            "endpoints_file": str(out),
            "previous_snapshot": str(previous_snapshot) if previous_snapshot else "",
            "current_snapshot": str(post_snapshot) if post_snapshot else "",
            "total_unique": export.get("total_unique"),
            "total_raw": export.get("total_raw"),
            "config": args.config,
            **delta,
        }
        write_json(base / "state" / "last_extract.json", extract_state)
        append_metric(base, "extract", {
            "exit_code": code,
            "endpoints_file": str(out),
            "total_unique": export.get("total_unique"),
            "total_raw": export.get("total_raw"),
            "config": args.config,
            **delta,
        })
        if previous_snapshot and post_snapshot:
            print(f"Previous endpoints snapshot: {previous_snapshot}")
            print(f"Current endpoints snapshot:  {post_snapshot}")
            print("Compare with: " + display_command([
                sys.executable,
                str(ROOT / "ai_src.py"),
                "diff-endpoints",
                previous_snapshot,
                post_snapshot,
            ]))
    else:
        append_metric(base, "extract", {
            "exit_code": code,
            "endpoints_file": str(out),
            "missing_output": True,
            "config": args.config,
        })
    return code

