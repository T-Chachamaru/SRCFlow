"""srcflow.wrappers - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from srcflow.auth import auth_header_lines, load_auth_profile_for_args, merge_header_lines
from srcflow.constants import FFUF_BLOCKED_PASSTHROUGH, FFUF_PROFILES, KATANA_BLOCKED_PASSTHROUGH, KATANA_PROFILES
from srcflow.exec_helpers import require_local_tool, run_cmd
from srcflow.io_helpers import append_metric, write_json
from srcflow.scope import cap_int_by_scope, cap_rate_by_scope, ffuf_candidate_summary, parse_scope, require_url_in_scope, require_wrapper_allowed, write_scoped_seed_file
from srcflow.utils import ensure_target_dirs, eprint, target_dir, utc_now

def normalize_passthrough(values: list[str]) -> list[str]:
    args = list(values or [])
    if args and args[0] == "--":
        args = args[1:]
    return args



def passthrough_has_flag(value: str, flag: str) -> bool:
    return value == flag or value.startswith(flag + "=")



def validate_passthrough(tool: str, values: list[str], blocked: set[str]) -> bool:
    for value in values:
        if not value.startswith("-"):
            continue
        for flag in blocked:
            if passthrough_has_flag(value, flag):
                eprint(f"{tool}: passthrough may not override safety/state flag `{flag}`")
                return False
    return True



def profile_args(profiles: dict[str, list[str]], name: str) -> list[str]:
    return list(profiles.get(name, []))



def cmd_katana_crawl(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    if not require_wrapper_allowed(base, scope, "katana-crawl"):
        return 2
    if not require_url_in_scope(base, scope, args.url):
        return 2
    passthrough = normalize_passthrough(args.tool_args)
    if not validate_passthrough("katana-crawl", passthrough, KATANA_BLOCKED_PASSTHROUGH):
        return 2
    try:
        katana = require_local_tool("katana")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2
    out = Path(args.out) if args.out else base / "state" / "katana_urls.txt"
    rate_limit = cap_rate_by_scope(args.rate_limit, scope, "katana rate-limit")
    concurrency = cap_int_by_scope(args.concurrency, scope, "max_threads", "katana concurrency")
    auth = load_auth_profile_for_args(base, args.auth_profile)
    if args.auth_profile and auth is None:
        return 2
    profile_headers = auth_header_lines(auth or {})
    cmd = [
        katana,
        "-u",
        args.url,
        "-d",
        str(args.depth),
        "-jc",
        "-silent",
        "-rl",
        str(rate_limit),
        "-c",
        str(concurrency),
        "-o",
        str(out),
    ]
    if args.headless:
        cmd.append("-headless")
    for header in profile_headers:
        cmd.extend(["-H", header])
    cmd.extend(profile_args(KATANA_PROFILES, args.profile))
    cmd.extend(passthrough)
    process_timeout = args.process_timeout if args.process_timeout > 0 else None
    code = run_cmd(cmd, timeout=process_timeout)
    print(f"Output: {out}")
    seed_file = base / "state" / "katana_seeds.txt"
    count = 0
    if out.exists():
        count = write_scoped_seed_file(out, seed_file, scope)
        if count:
            print(f"Scoped crawl seeds: {count} -> {seed_file}")
            print("Next crawl will include these seeds unless --no-katana-seeds is used.")
        else:
            seed_file.unlink(missing_ok=True)
            print("Scoped crawl seeds: 0")
    katana_state = {
        "finished_at": utc_now(),
        "exit_code": code,
        "url": args.url,
        "source": str(out),
        "seed_file": str(seed_file) if count else "",
        "scoped_url_count": count,
        "profile": args.profile,
        "passthrough": passthrough,
        "depth": args.depth,
        "rate_limit": rate_limit,
        "concurrency": concurrency,
        "process_timeout": args.process_timeout,
        "auth_profile": args.auth_profile,
        "auth_headers": len(profile_headers),
    }
    write_json(base / "state" / "last_katana.json", katana_state)
    append_metric(base, "katana", {
        "exit_code": code,
        "url": args.url,
        "source": str(out),
        "scoped_url_count": count,
        "profile": args.profile,
        "passthrough": passthrough,
        "depth": args.depth,
        "rate_limit": rate_limit,
        "concurrency": concurrency,
        "process_timeout": args.process_timeout,
        "auth_profile": args.auth_profile,
        "auth_headers": len(profile_headers),
    })
    return code



def cmd_ffuf_safe(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    if not require_wrapper_allowed(base, scope, "ffuf-safe"):
        return 2
    passthrough = normalize_passthrough(args.tool_args)
    if not validate_passthrough("ffuf-safe", passthrough, FFUF_BLOCKED_PASSTHROUGH):
        return 2
    fuzz_sources = [args.url, args.data or ""] + list(args.header or []) + passthrough
    if not any("FUZZ" in value for value in fuzz_sources):
        eprint("ffuf-safe requires FUZZ in the URL, a header, or the request body.")
        return 2
    if "FUZZ" in (urlparse(args.url).netloc or "").upper():
        eprint("ffuf-safe does not allow fuzzing the host; keep FUZZ in path, query, headers, or body.")
        return 2
    if not require_url_in_scope(base, scope, args.url):
        return 2
    try:
        ffuf = require_local_tool("ffuf")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2
    out = Path(args.out) if args.out else base / "state" / "ffuf-safe.json"
    rate = cap_rate_by_scope(args.rate, scope, "ffuf rate")
    threads = cap_int_by_scope(args.threads, scope, "max_threads", "ffuf threads")
    auth = load_auth_profile_for_args(base, args.auth_profile)
    if args.auth_profile and auth is None:
        return 2
    headers = merge_header_lines(auth_header_lines(auth or {}), list(args.header or []))
    cmd = [
        ffuf,
        "-u",
        args.url,
        "-w",
        args.wordlist,
        "-of",
        "json",
        "-o",
        str(out),
        "-rate",
        str(rate),
        "-t",
        str(threads),
        "-timeout",
        str(args.timeout),
        "-mc",
        args.match_codes,
    ]
    method = args.method.upper() if args.method else ("POST" if args.data else "")
    if method:
        cmd.extend(["-X", method])
    for header in headers:
        cmd.extend(["-H", header])
    if args.data:
        cmd.extend(["-d", args.data])
    if args.extensions:
        cmd.extend(["-e", args.extensions])
    if args.filter_size:
        cmd.extend(["-fs", args.filter_size])
    cmd.extend(profile_args(FFUF_PROFILES, args.profile))
    cmd.extend(passthrough)
    process_timeout = args.process_timeout if args.process_timeout > 0 else None
    code = run_cmd(cmd, timeout=process_timeout)
    print(f"Output: {out}")
    summary = ffuf_candidate_summary(out, scope)
    candidates_out = base / "state" / "ffuf_candidates.json"
    write_json(candidates_out, {
        "created_at": utc_now(),
        "source": str(out),
        "target": base.name,
        "profile": args.profile,
        "passthrough": passthrough,
        "candidate_count": summary["count"],
        "candidates": summary["candidates"],
        "auth_profile": args.auth_profile,
        "auth_headers": len(headers) - len(args.header or []),
        "process_timeout": args.process_timeout,
        "next": "Manually verify candidates through endpoint-testing before reporting.",
    })
    append_metric(base, "ffuf", {
        "exit_code": code,
        "url": args.url,
        "source": str(out),
        "candidate_count": summary["count"],
        "profile": args.profile,
        "passthrough": passthrough,
        "method": method or "GET",
        "rate": rate,
        "threads": threads,
        "auth_profile": args.auth_profile,
        "auth_headers": len(headers) - len(args.header or []),
        "process_timeout": args.process_timeout,
    })
    print(f"Candidates: {summary['count']} -> {candidates_out}")
    return code

