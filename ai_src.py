#!/usr/bin/env python3
"""AI SRC workspace orchestrator.

This script keeps the project runnable without hiding the underlying tools.
It creates target sandboxes, calls the existing crawler/extractor, keeps state
files in predictable places, and validates report quality gates.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
from copy import deepcopy

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

try:
    import requests
except ImportError:  # pragma: no cover - requests is present in this workspace
    requests = None


ROOT = Path(__file__).resolve().parent
TARGETS_DIR = ROOT / "targets"
REPORTS_DIR = ROOT / "reports"
TOOLS_DIR = ROOT / "tools"
CONFIG_DIR = ROOT / "config"


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = value.strip("-._")
    return value or "target"


def target_dir(name: str) -> Path:
    return TARGETS_DIR / slugify(name)


def ensure_target_dirs(base: Path) -> None:
    for child in ("findings", "state", "raw", "reports"):
        (base / child).mkdir(parents=True, exist_ok=True)


def read_lines_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    result: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        item = line.strip()
        if item and not item.startswith("#"):
            result.append(item)
    return result


def deep_merge(base: dict, override: dict) -> dict:
    result = deepcopy(base)
    for key, value in override.items():
        if key == "extends":
            continue
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        elif isinstance(value, list) and isinstance(result.get(key), list):
            merged = list(result[key])
            for item in value:
                if item not in merged:
                    merged.append(item)
            result[key] = merged
        else:
            result[key] = value
    return result


def resolve_config_path(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path
    named = CONFIG_DIR / value
    if named.exists():
        return named
    if not value.endswith(".json"):
        named = CONFIG_DIR / f"{value}.json"
        if named.exists():
            return named
    raise FileNotFoundError(f"config not found: {value}")


def load_config(value: str) -> tuple[Path, dict]:
    path = resolve_config_path(value)
    data = json.loads(path.read_text(encoding="utf-8"))
    parent = data.get("extends")
    if parent:
        parent_path, parent_data = load_config(str(path.parent / parent))
        data = deep_merge(parent_data, data)
        data["_extends_path"] = str(parent_path)
    data["_config_path"] = str(path)
    return path, data


def parse_scope(base: Path) -> dict[str, list[str]]:
    scope_path = base / "scope.md"
    data = {"domains": [], "seeds": []}
    if not scope_path.exists():
        return data

    active_section = ""
    for raw in scope_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = raw.strip()
        if stripped.startswith("## "):
            active_section = stripped[3:].strip().lower()
            continue
        if active_section != "in scope":
            continue
        line = stripped.lstrip("-").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            data["seeds"].append(line)
            host = urlparse(line).hostname
            if host:
                data["domains"].append(host)
        elif re.fullmatch(r"[A-Za-z0-9*_.-]+\.[A-Za-z]{2,}", line):
            data["domains"].append(line.lstrip("*."))

    for filename, key in (("domains.txt", "domains"), ("seeds.txt", "seeds")):
        for item in read_lines_file(base / filename):
            data[key].append(item)

    data["domains"] = sorted(set(d.lower() for d in data["domains"] if d))
    data["seeds"] = sorted(set(data["seeds"]))
    return data


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def snapshot_file(path: Path, snapshot_dir: Path, label: str) -> Path | None:
    if not path.exists():
        return None
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot = snapshot_dir / f"{label}-{stamp}{path.suffix or '.json'}"
    shutil.copyfile(path, snapshot)
    return snapshot


def run_cmd(cmd: list[str], cwd: Path = ROOT) -> int:
    print("+ " + " ".join(str(part) for part in cmd))
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.call(cmd, cwd=str(cwd), env=env)


def copy_template(template: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        shutil.copyfile(template, dest)


def render_scope(name: str, domains: list[str], seeds: list[str]) -> str:
    template = (TARGETS_DIR / "_template" / "scope.md").read_text(encoding="utf-8")
    domain_lines = "\n".join(f"  - {domain}" for domain in domains) or "  - TODO"
    seed_lines = "\n".join(f"  - {seed}" for seed in seeds) or "  - TODO"
    rendered = template.replace("- Target: TODO", f"- Target: {slugify(name)}")
    rendered = re.sub(r"- Domains:\n(?:  - .+\n)+", f"- Domains:\n{domain_lines}\n", rendered)
    rendered = re.sub(r"- Seed URLs:\n(?:  - .+\n)+", f"- Seed URLs:\n{seed_lines}\n", rendered)
    return rendered


def cmd_init_target(args: argparse.Namespace) -> int:
    base = target_dir(args.name)
    ensure_target_dirs(base)

    domains = sorted(set(args.domain or []))
    seeds = sorted(set(args.seed or []))
    scope_path = base / "scope.md"
    if not scope_path.exists():
        scope_path.write_text(render_scope(args.name, domains, seeds), encoding="utf-8")
    elif domains or seeds:
        existing = scope_path.read_text(encoding="utf-8", errors="ignore")
        if "- Target: TODO" in existing and "Authorization source: TODO" in existing:
            scope_path.write_text(render_scope(args.name, domains, seeds), encoding="utf-8")

    if domains:
        (base / "domains.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")
    if seeds:
        (base / "seeds.txt").write_text("\n".join(seeds) + "\n", encoding="utf-8")

    state = {
        "target": slugify(args.name),
        "created_at": utc_now(),
        "domains": domains,
        "seeds": seeds,
        "config": args.config,
        "notes": "Fill scope.md before active testing.",
    }
    write_json(base / "state" / "target.json", state)

    print(f"Target ready: {base}")
    print(f"Edit scope:   {base / 'scope.md'}")
    return 0


def cmd_crawl(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    scope = parse_scope(base)
    if not scope["domains"] and not args.target_kw:
        eprint("No domains found. Add targets/<target>/domains.txt, scope.md, or pass --target-kw.")
        return 2

    outdir = base / "raw" / "remote_sites"
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
        str(args.threads),
        "--depth",
        str(args.depth),
        "--mode",
        args.mode,
        "--max-size",
        str(args.max_size),
        "--timeout",
        str(args.timeout),
    ]
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
    if args.cookie:
        cmd.extend(["--cookie", args.cookie])
    if args.authorization:
        cmd.extend(["--authorization", args.authorization])
    if args.max_urls:
        cmd.extend(["--max-urls", str(args.max_urls)])
    if args.batch_size:
        cmd.extend(["--batch-size", str(args.batch_size)])

    targets = list(args.target_kw or []) + scope["domains"]
    for domain in sorted(set(targets)):
        cmd.extend(["--target", domain])
    for seed in sorted(set(args.seed or [])):
        cmd.extend(["--seed", seed])
    for seed in scope["seeds"]:
        cmd.extend(["--seed", seed])

    code = run_cmd(cmd)
    write_json(base / "state" / "last_crawl.json", {
        "finished_at": utc_now(),
        "exit_code": code,
        "outdir": str(outdir),
        "domains": scope["domains"],
        "seeds": scope["seeds"] + list(args.seed or []),
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
    for domain in sorted(set(scope["domains"] + list(args.target_kw or []))):
        cmd.extend(["--target", domain])
    if args.all_domains:
        cmd.append("--all-domains")
    if args.no_known:
        cmd.append("--no-known")

    code = run_cmd(cmd)
    if out.exists():
        export = json.loads(out.read_text(encoding="utf-8", errors="ignore"))
        post_snapshot = snapshot_file(out, base / "state" / "snapshots", "endpoints-after")
        write_json(base / "state" / "last_extract.json", {
            "finished_at": utc_now(),
            "exit_code": code,
            "endpoints_file": str(out),
            "previous_snapshot": str(previous_snapshot) if previous_snapshot else "",
            "current_snapshot": str(post_snapshot) if post_snapshot else "",
            "total_unique": export.get("total_unique"),
            "total_raw": export.get("total_raw"),
        })
        if previous_snapshot and post_snapshot:
            print(f"Previous endpoints snapshot: {previous_snapshot}")
            print(f"Current endpoints snapshot:  {post_snapshot}")
            print(f"Compare with: python ai_src.py diff-endpoints {previous_snapshot} {post_snapshot}")
    return code


GATE_PATTERNS = [
    ("poc", re.compile(r"\b(curl|python|httpie|powershell|GET |POST |PUT |DELETE )\b", re.I)),
    ("impact", re.compile(r"(Impact|\u5f71\u54cd|Confidentiality|Integrity|Availability|\u673a\u5bc6\u6027|\u5b8c\u6574\u6027|\u53ef\u7528\u6027)", re.I)),
    ("scope", re.compile(r"(Scope|\u6388\u6743|\u8303\u56f4|Target)", re.I)),
    ("false_positive_exclusion", re.compile(r"(CORS|\u5b89\u5168\u5934|\u7248\u672c\u53f7|Self-XSS|\u8bef\u62a5|\u6392\u9664)", re.I)),
    ("fix", re.compile(r"(\u4fee\u590d|Remediation|\u5efa\u8bae|Enforce|\u6821\u9a8c|\u6388\u6743)", re.I)),
]


def checked_gate_count(text: str) -> int:
    count = 0
    for line in text.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("- [x]") or stripped.startswith("* [x]"):
            count += 1
    return count


def cmd_gate(args: argparse.Namespace) -> int:
    report = Path(args.report)
    if not report.exists():
        eprint(f"Report not found: {report}")
        return 2
    text = report.read_text(encoding="utf-8", errors="ignore")

    failures: list[str] = []
    if checked_gate_count(text) < 7:
        failures.append("The seven report gates are not all checked as [x]")
    if "TODO" in text:
        failures.append("Report still contains TODO placeholders")
    if "https://example.com" in text or "Cookie: REDACTED" in text:
        failures.append("Report still contains template example values")
    for name, pattern in GATE_PATTERNS:
        if not pattern.search(text):
            failures.append(f"Missing required content: {name}")
    if re.search(r"Access-Control-Allow-Origin|X-Frame-Options|X-Content-Type-Options", text, re.I):
        if not re.search(r"(\u6570\u636e\u6cc4\u9732|\u8d8a\u6743|\u672a\u6388\u6743|\u6743\u9650\u63d0\u5347|RCE|\u547d\u4ee4\u6267\u884c|\u4e1a\u52a1\u903b\u8f91|\u654f\u611f)", text, re.I):
            failures.append("Report appears to describe only headers/configuration without proving real impact")

    if failures:
        print("Gate failed:")
        for item in failures:
            print(f"- {item}")
        return 1

    print("Gate passed.")
    return 0


def local_tool(name: str) -> str:
    local_exe = TOOLS_DIR / "bin" / f"{name}.exe"
    local_plain = TOOLS_DIR / "bin" / name
    if local_exe.exists():
        return str(local_exe)
    if local_plain.exists():
        return str(local_plain)
    return shutil.which(name) or ""


def require_local_tool(name: str) -> str:
    path = local_tool(name)
    if not path:
        raise FileNotFoundError(f"{name} not found. Run scripts/install_tools.ps1 first.")
    return path


def cmd_subdomains(args: argparse.Namespace) -> int:
    try:
        subfinder = require_local_tool("subfinder")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2
    base = target_dir(args.target)
    ensure_target_dirs(base)
    out = Path(args.out) if args.out else base / "state" / "subdomains.txt"
    cmd = [
        subfinder,
        "-d",
        args.domain,
        "-silent",
        "-o",
        str(out),
    ]
    if args.all:
        cmd.append("-all")
    code = run_cmd(cmd)
    print(f"Output: {out}")
    return code


def cmd_httpx_live(args: argparse.Namespace) -> int:
    try:
        httpx = require_local_tool("httpx")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2
    base = target_dir(args.target)
    ensure_target_dirs(base)
    inp = Path(args.input)
    out = Path(args.out) if args.out else base / "state" / "live_hosts.jsonl"
    cmd = [
        httpx,
        "-l",
        str(inp),
        "-json",
        "-silent",
        "-follow-host-redirects",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-rate-limit",
        str(args.rate_limit),
        "-retries",
        "0",
        "-timeout",
        str(args.timeout),
        "-o",
        str(out),
    ]
    code = run_cmd(cmd)
    print(f"Output: {out}")
    return code


def cmd_katana_crawl(args: argparse.Namespace) -> int:
    try:
        katana = require_local_tool("katana")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2
    base = target_dir(args.target)
    ensure_target_dirs(base)
    out = Path(args.out) if args.out else base / "state" / "katana_urls.txt"
    cmd = [
        katana,
        "-u",
        args.url,
        "-d",
        str(args.depth),
        "-jc",
        "-silent",
        "-rl",
        str(args.rate_limit),
        "-c",
        str(args.concurrency),
        "-o",
        str(out),
    ]
    if args.headless:
        cmd.append("-headless")
    code = run_cmd(cmd)
    print(f"Output: {out}")
    return code


def cmd_ffuf_safe(args: argparse.Namespace) -> int:
    try:
        ffuf = require_local_tool("ffuf")
    except FileNotFoundError as exc:
        eprint(str(exc))
        return 2
    base = target_dir(args.target)
    ensure_target_dirs(base)
    out = Path(args.out) if args.out else base / "state" / "ffuf-safe.json"
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
        str(args.rate),
        "-t",
        str(args.threads),
        "-timeout",
        str(args.timeout),
        "-mc",
        args.match_codes,
    ]
    if args.extensions:
        cmd.extend(["-e", args.extensions])
    if args.filter_size:
        cmd.extend(["-fs", args.filter_size])
    code = run_cmd(cmd)
    print(f"Output: {out}")
    return code


def cmd_nuclei_safe(args: argparse.Namespace) -> int:
    nuclei = local_tool("nuclei")
    if not nuclei:
        eprint("nuclei not found. Run scripts/install_tools.ps1 first.")
        return 2
    base = target_dir(args.target)
    ensure_target_dirs(base)
    out = Path(args.out) if args.out else base / "state" / "nuclei-safe.jsonl"
    cmd = [
        nuclei,
        "-u",
        args.url,
        "-jsonl",
        "-o",
        str(out),
        "-severity",
        args.severity,
        "-tags",
        args.tags,
        "-exclude-tags",
        args.exclude_tags,
        "-rate-limit",
        str(args.rate_limit),
        "-c",
        str(args.concurrency),
        "-retries",
        "0",
        "-timeout",
        str(args.timeout),
        "-disable-update-check",
        "-no-stdin",
    ]
    if args.templates:
        cmd.extend(["-t", args.templates])
    code = run_cmd(cmd)
    print(f"Output: {out}")
    return code


def count_files(path: Path, suffixes: tuple[str, ...]) -> int:
    if not path.exists():
        return 0
    return sum(1 for p in path.rglob("*") if p.is_file() and p.suffix.lower() in suffixes)


def cmd_status(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    scope = parse_scope(base)
    raw = base / "raw" / "remote_sites"
    endpoints = base / "state" / "endpoints.json"
    last_extract = base / "state" / "last_extract.json"

    print(f"Target: {base.name}")
    print(f"Path:   {base}")
    print(f"Domains ({len(scope['domains'])}): {', '.join(scope['domains']) or '-'}")
    print(f"Seeds   ({len(scope['seeds'])}): {', '.join(scope['seeds']) or '-'}")
    print(f"Raw files: HTML={count_files(raw, ('.html', '.htm'))} JS={count_files(raw, ('.js',))}")
    if endpoints.exists():
        data = json.loads(endpoints.read_text(encoding="utf-8", errors="ignore"))
        print(f"Endpoints: {data.get('total_unique')} unique / {data.get('total_raw')} raw")
        print(f"Endpoint file: {endpoints}")
    else:
        print("Endpoints: not extracted")
    if last_extract.exists():
        data = json.loads(last_extract.read_text(encoding="utf-8", errors="ignore"))
        if data.get("previous_snapshot"):
            print(f"Previous snapshot: {data.get('previous_snapshot')}")
        if data.get("current_snapshot"):
            print(f"Current snapshot:  {data.get('current_snapshot')}")
    for name in ("subdomains.txt", "live_hosts.jsonl", "katana_urls.txt", "probe_results.json", "nuclei-safe.jsonl", "ffuf-safe.json"):
        path = base / "state" / name
        if path.exists():
            print(f"State artifact: {path}")
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
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
    print(f"Checkpoint updated: {checkpoint}")
    return 0


def iter_exported_endpoints(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
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


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = {}
    for key, value in headers.items():
        if key.lower() in {"authorization", "cookie", "x-api-key"}:
            redacted[key] = "REDACTED"
        else:
            redacted[key] = value
    return redacted


def cmd_probe(args: argparse.Namespace) -> int:
    if requests is None:
        eprint("Python package missing: requests")
        return 2

    base = target_dir(args.target)
    ensure_target_dirs(base)
    endpoints_file = Path(args.endpoints) if args.endpoints else base / "state" / "endpoints.json"
    if not endpoints_file.exists():
        eprint(f"Endpoints file not found: {endpoints_file}")
        return 2

    endpoints = iter_exported_endpoints(endpoints_file)
    if args.limit:
        endpoints = endpoints[:args.limit]

    headers = {"User-Agent": "AI-SRC-Agent/1.0 authorized-security-assessment"}
    if args.authorization:
        headers["Authorization"] = args.authorization
    if args.cookie:
        headers["Cookie"] = args.cookie

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
        if args.delay > 0:
            time.sleep(args.delay)

    out = Path(args.out) if args.out else base / "state" / "probe_results.json"
    write_json(out, {
        "target": base.name,
        "created_at": utc_now(),
        "method": args.method,
        "headers": redact_headers(headers),
        "endpoints_file": str(endpoints_file),
        "results": results,
    })

    ok = sum(1 for item in results if item.get("status") == "ok")
    skipped = sum(1 for item in results if item.get("status") == "skipped")
    errors = sum(1 for item in results if item.get("status") == "error")
    print(f"Probe complete: ok={ok} skipped={skipped} errors={errors}")
    print(f"Output: {out}")
    return 0 if errors == 0 else 1


def cmd_tools(args: argparse.Namespace) -> int:
    tools = ["git", "go", "python", "httpx", "katana", "nuclei", "ffuf", "subfinder"]
    rows = []
    for tool in tools:
        local_exe = TOOLS_DIR / "bin" / f"{tool}.exe"
        local_plain = TOOLS_DIR / "bin" / tool
        if local_exe.exists():
            path = str(local_exe)
        elif local_plain.exists():
            path = str(local_plain)
        else:
            path = shutil.which(tool)
        rows.append({"tool": tool, "path": path or "", "installed": bool(path)})
    write_json(TOOLS_DIR / "tool_status.json", {"checked_at": utc_now(), "tools": rows})
    for row in rows:
        status = row["path"] if row["installed"] else "missing"
        print(f"{row['tool']}: {status}")
    print(f"Status JSON: {TOOLS_DIR / 'tool_status.json'}")
    return 0


def cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        path, config = load_config(args.config)
    except Exception as exc:
        print(f"Config invalid: {type(exc).__name__}: {exc}")
        return 1

    failures: list[str] = []
    warnings: list[str] = []
    list_fields = [
        "target_keywords", "extra_seeds", "skip_dirs", "third_party_domains",
        "skip_extensions", "api_prefixes", "api_path_regexes",
        "known_endpoints", "special_keywords", "garbage_substrings",
        "extract_patterns",
    ]
    for field in list_fields:
        if field in config and not isinstance(config[field], list):
            failures.append(f"`{field}` must be a list")

    for pattern in config.get("api_path_regexes", []):
        try:
            re.compile(pattern)
        except re.error as exc:
            failures.append(f"api_path_regex invalid: {pattern}: {exc}")

    for item in config.get("extract_patterns", []):
        if not isinstance(item, dict):
            failures.append(f"extract_patterns item must be object: {item!r}")
            continue
        name = item.get("name", "UNNAMED")
        pattern = item.get("pattern", "")
        if "?P<endpoint>" not in pattern:
            failures.append(f"extract pattern `{name}` missing (?P<endpoint>...)")
        try:
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            failures.append(f"extract pattern `{name}` invalid: {exc}")

    if not config.get("target_keywords"):
        warnings.append("target_keywords is empty; pass --target/--target-kw or fill target config")
    if not config.get("extra_seeds"):
        warnings.append("extra_seeds is empty; target must provide seeds via scope/seeds.txt/CLI")

    if failures:
        print(f"Config invalid: {path}")
        for item in failures:
            print(f"- {item}")
        return 1

    print(f"Config OK: {path}")
    if config.get("_extends_path"):
        print(f"Extends: {config['_extends_path']}")
    for item in warnings:
        print(f"Warning: {item}")
    print(f"extract_patterns={len(config.get('extract_patterns', []))} api_prefixes={len(config.get('api_prefixes', []))} known_endpoints={len(config.get('known_endpoints', []))}")
    return 0


def endpoint_records(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
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


def cmd_import_har(args: argparse.Namespace) -> int:
    har_path = Path(args.har)
    data = json.loads(har_path.read_text(encoding="utf-8", errors="ignore"))
    entries = data.get("log", {}).get("entries", [])
    results = []
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

    export = {
        "har": str(har_path),
        "created_at": utc_now(),
        "total": len(results),
        "hosts": sorted(hosts),
        "suggested_api_prefixes": sorted(prefixes),
        "requests": results,
    }
    if args.as_endpoints:
        by_domain: dict[str, list[dict]] = {}
        relative: dict[str, dict] = {}
        for record in results:
            endpoint = record["url"]
            by_domain.setdefault(record["host"], []).append({
                "endpoint": endpoint,
                "sources": 1,
                "type": f"HAR_{record['method'] or 'REQUEST'}",
                "normalized": endpoint,
                "method": record["method"],
                "status": record["status"],
                "query_keys": record["query_keys"],
                "body_keys": record["body_keys"],
            })
            path = record["path"]
            if path and path != "/":
                relative[path] = {
                    "endpoint": path,
                    "sources": 1,
                    "type": f"HAR_{record['method'] or 'REQUEST'}",
                    "normalized": path,
                    "method": record["method"],
                    "query_keys": record["query_keys"],
                    "body_keys": record["body_keys"],
                }
        export = {
            "total_unique": sum(len(items) for items in by_domain.values()) + len(relative),
            "total_raw": len(results),
            "sites_dir": "",
            "target_keywords": [args.target] if args.target else [],
            "config": "",
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
    return 0


JS_RANK_KEYWORDS = {
    "baseurl": 10,
    "baseURL": 10,
    "axios": 8,
    "fetch(": 8,
    "request(": 7,
    "api": 5,
    "graphql": 10,
    "swagger": 8,
    "openapi": 8,
    "router": 4,
    "userId": 6,
    "tenantId": 6,
    "orgId": 6,
    "token": 5,
    "authorization": 5,
}


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI SRC workspace CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init-target", help="create target sandbox")
    p.add_argument("name")
    p.add_argument("--domain", action="append", default=[])
    p.add_argument("--seed", action="append", default=[])
    p.add_argument("--config", default="default", help="config name or JSON path")
    p.set_defaults(func=cmd_init_target)

    p = sub.add_parser("crawl", help="crawl HTML/JS resources")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--mode", choices=["pages", "api", "full"], default="pages")
    p.add_argument("--config", default="default", help="config name or JSON path")
    p.add_argument("--target-kw", action="append", default=[])
    p.add_argument("--seed", action="append", default=[])
    p.add_argument("--include-css", action="store_true")
    p.add_argument("--include-json", action="store_true")
    p.add_argument("--parse-json-links", action="store_true")
    p.add_argument("--render", action="store_true")
    p.add_argument("--render-timeout", type=float, default=15.0)
    p.add_argument("--render-depth", type=int, default=0)
    p.add_argument("--cookie", default="")
    p.add_argument("--authorization", default="")
    p.add_argument("--max-size", type=float, default=5.0)
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--max-urls", type=int, default=0)
    p.add_argument("--batch-size", type=int, default=0)
    p.set_defaults(func=cmd_crawl)

    p = sub.add_parser("extract", help="extract endpoints from crawled files")
    p.add_argument("target")
    p.add_argument("--sites-dir")
    p.add_argument("--out")
    p.add_argument("--config", default="default", help="config name or JSON path")
    p.add_argument("--target-kw", action="append", default=[])
    p.add_argument("--all-domains", action="store_true")
    p.add_argument("--no-known", action="store_true")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("gate", help="validate report quality gates")
    p.add_argument("report")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("status", help="show target status")
    p.add_argument("target")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("checkpoint", help="append compressed loop state")
    p.add_argument("target")
    p.add_argument("--direction")
    p.add_argument("--tested")
    p.add_argument("--findings")
    p.add_argument("--next")
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("probe", help="low-risk status probe for extracted endpoints")
    p.add_argument("target")
    p.add_argument("--endpoints")
    p.add_argument("--base-url", help="base URL for relative endpoints")
    p.add_argument("--method", choices=["HEAD", "OPTIONS", "GET"], default="HEAD")
    p.add_argument("--authorization", default="")
    p.add_argument("--cookie", default="")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--delay", type=float, default=0.2)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--out")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("tools", help="check local tool availability")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("validate-config", help="validate config JSON and regexes")
    p.add_argument("config", help="config name or JSON path")
    p.set_defaults(func=cmd_validate_config)

    p = sub.add_parser("diff-endpoints", help="compare two endpoints JSON exports")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--out")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_diff_endpoints)

    p = sub.add_parser("import-har", help="extract API candidates from a browser HAR file")
    p.add_argument("har")
    p.add_argument("--target", help="filter by host keyword")
    p.add_argument("--out")
    p.add_argument("--as-endpoints", action="store_true", help="export in endpoints.json-compatible format")
    p.set_defaults(func=cmd_import_har)

    p = sub.add_parser("rank-js", help="rank crawled JS/HTML files for manual review")
    p.add_argument("sites_dir")
    p.add_argument("--out")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_rank_js)

    p = sub.add_parser("subdomains", help="run subfinder and save discovered subdomains")
    p.add_argument("target")
    p.add_argument("domain")
    p.add_argument("--out")
    p.add_argument("--all", action="store_true", help="enable subfinder -all")
    p.set_defaults(func=cmd_subdomains)

    p = sub.add_parser("httpx-live", help="run httpx against a host list with conservative defaults")
    p.add_argument("target")
    p.add_argument("input", help="host list, usually state/subdomains.txt")
    p.add_argument("--out")
    p.add_argument("--rate-limit", type=int, default=20)
    p.add_argument("--timeout", type=int, default=8)
    p.set_defaults(func=cmd_httpx_live)

    p = sub.add_parser("katana-crawl", help="run katana URL discovery with conservative defaults")
    p.add_argument("target")
    p.add_argument("url")
    p.add_argument("--out")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--rate-limit", type=int, default=5)
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--headless", action="store_true")
    p.set_defaults(func=cmd_katana_crawl)

    p = sub.add_parser("ffuf-safe", help="run ffuf with conservative low-rate defaults")
    p.add_argument("target")
    p.add_argument("url", help="URL containing FUZZ")
    p.add_argument("wordlist")
    p.add_argument("--out")
    p.add_argument("--rate", type=int, default=20)
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--match-codes", default="200,204,301,302,307,401,403")
    p.add_argument("--extensions", help="ffuf -e value, for example .js,.json")
    p.add_argument("--filter-size", help="ffuf -fs value")
    p.set_defaults(func=cmd_ffuf_safe)

    p = sub.add_parser("nuclei-safe", help="run nuclei with conservative low-risk defaults")
    p.add_argument("target")
    p.add_argument("url")
    p.add_argument("--out")
    p.add_argument("--templates", help="optional templates directory/file")
    p.add_argument("--severity", default="info,low,medium")
    p.add_argument("--tags", default="exposure,misconfig,tech,headers,cves")
    p.add_argument("--exclude-tags", default="fuzz,dast,bruteforce,intrusive,dos,headless")
    p.add_argument("--rate-limit", type=int, default=2)
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--timeout", type=int, default=8)
    p.set_defaults(func=cmd_nuclei_safe)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
