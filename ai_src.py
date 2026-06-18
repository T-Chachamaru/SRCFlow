#!/usr/bin/env python3
"""AI SRC workspace orchestrator.

This script keeps the project runnable without hiding the underlying tools.
It creates target sandboxes, calls the existing crawler/extractor, keeps state
files in predictable places, and validates report quality gates.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

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
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    parent = data.get("extends")
    if parent:
        parent_path, parent_data = load_config(str(path.parent / parent))
        data = deep_merge(parent_data, data)
        data["_extends_path"] = str(parent_path)
    data["_config_path"] = str(path)
    return path, data


SECRET_ARG_NAMES = {"--cookie", "--authorization", "-b"}
SECRET_HEADER_PREFIXES = ("authorization:", "cookie:", "x-api-key:")
KNOWN_WRAPPERS = {"ffuf-safe", "katana-crawl"}


def parse_first_number(value: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", value)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def parse_allowed_wrappers(value: str) -> list[str] | None:
    normalized = value.lower().strip()
    if not normalized or normalized in {"todo", "n/a", "na", "-"}:
        return None
    if re.search(r"\b(none|no wrappers|not allowed|disabled)\b", normalized):
        return []
    wrappers = sorted(wrapper for wrapper in KNOWN_WRAPPERS if wrapper in normalized)
    if wrappers:
        return wrappers
    return []


def parse_ip_network_value(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    if not candidate or candidate.lower() in {"todo", "n/a", "na", "-"}:
        return None
    if candidate.startswith(("http://", "https://")):
        candidate = urlparse(candidate).hostname or ""
    elif "/" in candidate and not re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", candidate):
        return None
    elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", candidate):
        candidate = candidate.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_network(candidate, strict=False))
    except ValueError:
        return None


def parse_ip_address_value(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = value.strip().strip("[]")
    if not candidate:
        return None
    if candidate.startswith(("http://", "https://")):
        candidate = urlparse(candidate).hostname or ""
    elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", candidate):
        candidate = candidate.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def ip_in_ranges(host: str, ranges: list[str]) -> bool:
    address = parse_ip_address_value(host)
    if address is None:
        return False
    for value in ranges:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def parse_scope(base: Path) -> dict[str, object]:
    scope_path = base / "scope.md"
    data: dict[str, object] = {
        "domains": [],
        "seeds": [],
        "ip_ranges": [],
        "out_domains": [],
        "out_ip_ranges": [],
        "max_threads": None,
        "max_request_rate": None,
        "allowed_wrappers": None,
    }
    if not scope_path.exists():
        return data

    active_section = ""
    for raw in scope_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = raw.strip()
        if stripped.startswith("## "):
            active_section = stripped[3:].strip().lower()
            continue
        line = stripped.lstrip("-").strip()
        if not line or line.startswith("#"):
            continue

        if active_section == "in scope":
            if line.startswith("http://") or line.startswith("https://"):
                cast_list = data["seeds"]
                if isinstance(cast_list, list):
                    cast_list.append(line)
                host = urlparse(line).hostname
                if host and isinstance(data["domains"], list):
                    data["domains"].append(host)
                network = parse_ip_network_value(line)
                if network and isinstance(data["ip_ranges"], list):
                    data["ip_ranges"].append(network)
            elif re.fullmatch(r"[A-Za-z0-9*_.:-]+\.[A-Za-z]{2,}", line):
                if isinstance(data["domains"], list):
                    data["domains"].append(line.lstrip("*."))
            else:
                network = parse_ip_network_value(line)
                if network and isinstance(data["ip_ranges"], list):
                    data["ip_ranges"].append(network)
            continue

        if active_section == "out of scope":
            candidate = line
            if candidate.startswith(("http://", "https://")):
                host = urlparse(candidate).hostname or ""
                candidate = host
            network = parse_ip_network_value(candidate)
            if network:
                if isinstance(data["out_ip_ranges"], list):
                    data["out_ip_ranges"].append(network)
                continue
            if re.fullmatch(r"[A-Za-z0-9*_.:-]+\.[A-Za-z]{2,}", candidate):
                if isinstance(data["out_domains"], list):
                    data["out_domains"].append(candidate.lstrip("*."))
            continue

        if active_section == "rate / safety limits":
            key, sep, value = line.partition(":")
            if not sep:
                continue
            normalized_key = key.lower().strip()
            value = value.strip()
            if normalized_key == "max threads":
                number = parse_first_number(value)
                if number is not None:
                    data["max_threads"] = max(1, int(number))
            elif normalized_key == "max request rate":
                number = parse_first_number(value)
                if number is not None:
                    data["max_request_rate"] = max(0.01, number)
            elif normalized_key == "allowed wrappers":
                data["allowed_wrappers"] = parse_allowed_wrappers(value)

    for filename, key in (("domains.txt", "domains"), ("seeds.txt", "seeds")):
        for item in read_lines_file(base / filename):
            values = data.get(key)
            if isinstance(values, list):
                values.append(item)

    for key in ("domains", "out_domains"):
        values = data.get(key)
        if isinstance(values, list):
            data[key] = sorted(set(str(d).lower().strip().lstrip("*.") for d in values if str(d).strip()))
    for key in ("ip_ranges", "out_ip_ranges"):
        values = data.get(key)
        if isinstance(values, list):
            data[key] = sorted(set(str(item).strip() for item in values if str(item).strip()))
    seeds = data.get("seeds")
    if isinstance(seeds, list):
        data["seeds"] = sorted(set(str(seed).strip() for seed in seeds if str(seed).strip()))
    return data


def scope_list(scope: dict[str, object], key: str) -> list[str]:
    values = scope.get(key, [])
    if not isinstance(values, list):
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def normalize_host(value: str) -> str:
    value = value.strip().strip("[]")
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        host = urlparse(value).hostname or ""
    else:
        candidate = value
        if "/" in candidate:
            candidate = urlparse("https://" + candidate).hostname or candidate
        host = candidate.split(":", 1)[0]
    return host.lower().strip(".").lstrip("*.")


def host_matches(host: str, domain: str) -> bool:
    host = normalize_host(host)
    domain = normalize_host(domain)
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def host_in_scope(host: str, scope: dict[str, object], extra_domains: list[str] | None = None) -> bool:
    raw_host = host
    host = normalize_host(host)
    if not host:
        return False
    if ip_in_ranges(raw_host, scope_list(scope, "out_ip_ranges")):
        return False
    if any(host_matches(host, domain) for domain in scope_list(scope, "out_domains")):
        return False
    allowed = scope_list(scope, "domains") + list(extra_domains or [])
    if allowed and any(host_matches(host, domain) for domain in allowed):
        return True
    return ip_in_ranges(raw_host, scope_list(scope, "ip_ranges"))


def url_host(value: str) -> str:
    return normalize_host(value)


def url_in_scope(value: str, scope: dict[str, object], extra_domains: list[str] | None = None) -> bool:
    return host_in_scope(url_host(value), scope, extra_domains)


def require_scope_ready(base: Path, scope: dict[str, object]) -> bool:
    if scope_list(scope, "domains") or scope_list(scope, "ip_ranges"):
        return True
    eprint(f"Scope blocked: no in-scope domains or IP ranges found for {base}. Fill scope.md or domains.txt first.")
    return False


def require_url_in_scope(base: Path, scope: dict[str, object], url: str, label: str = "url",
                         extra_domains: list[str] | None = None) -> bool:
    if not require_scope_ready(base, scope):
        return False
    if url_in_scope(url, scope, extra_domains):
        return True
    eprint(f"Scope blocked: {label} is outside targets/{base.name}/scope.md: {url}")
    return False


def require_wrapper_allowed(base: Path, scope: dict[str, object], wrapper: str) -> bool:
    allowed = scope.get("allowed_wrappers")
    if allowed is None:
        return True
    if isinstance(allowed, list) and wrapper in allowed:
        return True
    allowed_text = ", ".join(str(item) for item in allowed) if isinstance(allowed, list) and allowed else "none"
    eprint(f"Scope blocked: {wrapper} is not allowed by targets/{base.name}/scope.md (allowed: {allowed_text})")
    return False


def cap_int_by_scope(value: int, scope: dict[str, object], key: str, label: str) -> int:
    cap = scope.get(key)
    if isinstance(cap, int) and value > cap:
        print(f"Scope cap: {label} {value} -> {cap}")
        return cap
    return value


def cap_rate_by_scope(value: int, scope: dict[str, object], label: str) -> int:
    cap = scope.get("max_request_rate")
    if isinstance(cap, (int, float)):
        capped = max(1, int(cap))
        if value > capped:
            print(f"Scope cap: {label} {value} -> {capped}")
            return capped
    return value


def delay_from_scope(value: float, scope: dict[str, object]) -> float:
    rate = scope.get("max_request_rate")
    if isinstance(rate, (int, float)) and rate > 0:
        scoped_delay = 1.0 / float(rate)
        if value < scoped_delay:
            print(f"Scope cap: crawl delay {value:.3f}s -> {scoped_delay:.3f}s")
            return scoped_delay
    return value


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def append_jsonl(path: Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def metrics_path(base: Path) -> Path:
    return base / "state" / "metrics.jsonl"


def endpoint_tests_path(base: Path) -> Path:
    return base / "state" / "endpoint_tests.jsonl"


def append_metric(base: Path, event: str, data: dict[str, object]) -> None:
    try:
        append_jsonl(metrics_path(base), {
            "time": utc_now(),
            "target": base.name,
            "event": event,
            "data": data,
        })
    except (OSError, TypeError, ValueError):
        return


def read_metric_events(base: Path) -> list[dict[str, object]]:
    return read_jsonl(metrics_path(base))


def read_endpoint_tests(base: Path) -> list[dict[str, object]]:
    return read_jsonl(endpoint_tests_path(base))


def latest_event(events: list[dict[str, object]], name: str) -> dict[str, object] | None:
    for row in reversed(events):
        if row.get("event") == name:
            return row
    return None


def event_data(row: dict[str, object] | None) -> dict[str, object]:
    if not row:
        return {}
    data = row.get("data", {})
    return data if isinstance(data, dict) else {}


def number_value(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def metric_display(value: object) -> str:
    if value in (None, "", -1):
        return "-"
    return str(value)


LINE_URL_RE = re.compile(r"https?://[^\s\"'`<>)\]]+", re.I)


def urls_from_line(line: str) -> list[str]:
    value = line.strip()
    if not value:
        return []
    if value.startswith("{"):
        try:
            obj = json.loads(value)
        except json.JSONDecodeError:
            obj = {}
        for key in ("url", "matched", "request", "input"):
            candidate = obj.get(key)
            if isinstance(candidate, str) and candidate.startswith(("http://", "https://")):
                return [candidate]
    return [match.group(0).rstrip(".,;") for match in LINE_URL_RE.finditer(value)]


def scoped_urls_from_file(path: Path, scope: dict[str, object],
                          extra_domains: list[str] | None = None) -> list[str]:
    if not path.exists():
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        for url in urls_from_line(line):
            if not url_in_scope(url, scope, extra_domains):
                continue
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
    return urls


def write_scoped_seed_file(source: Path, dest: Path, scope: dict[str, object],
                           extra_domains: list[str] | None = None) -> int:
    urls = scoped_urls_from_file(source, scope, extra_domains)
    if not urls:
        return 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return len(urls)


def ffuf_candidate_summary(path: Path, scope: dict[str, object]) -> dict[str, object]:
    if not path.exists():
        return {"count": 0, "candidates": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
    except json.JSONDecodeError:
        return {"count": 0, "candidates": []}
    candidates = []
    for item in data.get("results", []) or []:
        url = str(item.get("url", ""))
        if url and not url_in_scope(url, scope):
            continue
        candidates.append({
            "url": url,
            "status": item.get("status"),
            "length": item.get("length"),
            "words": item.get("words"),
            "lines": item.get("lines"),
            "content_type": item.get("content-type") or item.get("content_type", ""),
            "redirect": item.get("redirectlocation", ""),
            "input": item.get("input", {}),
        })
    return {
        "count": len(candidates),
        "candidates": candidates,
    }


def snapshot_file(path: Path, snapshot_dir: Path, label: str) -> Path | None:
    if not path.exists():
        return None
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot = snapshot_dir / f"{label}-{stamp}{path.suffix or '.json'}"
    shutil.copyfile(path, snapshot)
    return snapshot


def redact_cmd(cmd: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for part in cmd:
        text = str(part)
        lower = text.lower()
        if redact_next:
            redacted.append("REDACTED")
            redact_next = False
            continue
        if lower in SECRET_ARG_NAMES:
            redacted.append(text)
            redact_next = True
            continue
        if any(lower.startswith(prefix) for prefix in SECRET_HEADER_PREFIXES):
            name = text.split(":", 1)[0]
            redacted.append(f"{name}: REDACTED")
            continue
        text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer REDACTED", text)
        redacted.append(text)
    return redacted


def run_cmd(cmd: list[str], cwd: Path = ROOT) -> int:
    print("+ " + subprocess.list2cmdline(redact_cmd(cmd)))
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.call(cmd, cwd=str(cwd), env=env)


def counter_dict(values: Counter) -> dict[str, int]:
    return {str(key): int(values[key]) for key in sorted(values)}


def row_time(row: dict[str, object] | None) -> str:
    return str(row.get("time", "")) if row else ""


def summarize_target_metrics(base: Path) -> dict[str, object]:
    events = read_metric_events(base)
    event_counts = Counter(str(row.get("event", "")) for row in events if row.get("event"))

    endpoint_tests = read_endpoint_tests(base)
    if endpoint_tests:
        test_rows = endpoint_tests
    else:
        test_rows = [
            event_data(row)
            for row in events
            if row.get("event") == "endpoint_test"
        ]
    test_status_counts = Counter(
        str(row.get("status", "")).strip()
        for row in test_rows
        if str(row.get("status", "")).strip()
    )

    katana_events = [row for row in events if row.get("event") == "katana"]
    ffuf_events = [row for row in events if row.get("event") == "ffuf"]
    extract_events = [row for row in events if row.get("event") == "extract"]
    gate_events = [row for row in events if row.get("event") == "gate"]

    latest_katana = latest_event(events, "katana")
    latest_ffuf = latest_event(events, "ffuf")
    latest_extract = latest_event(events, "extract")
    latest_crawl = latest_event(events, "crawl")
    latest_endpoint_test = latest_event(events, "endpoint_test")
    latest_gate = latest_event(events, "gate")

    katana_total = sum(number_value(event_data(row).get("scoped_url_count")) for row in katana_events)
    ffuf_total = sum(number_value(event_data(row).get("candidate_count")) for row in ffuf_events)
    extract_unique_counts = [
        number_value(event_data(row).get("total_unique"), -1)
        for row in extract_events
        if event_data(row).get("total_unique") is not None
    ]
    extract_unique_counts = [value for value in extract_unique_counts if value >= 0]

    gate_counts = Counter(
        "passed" if event_data(row).get("passed") else "failed"
        for row in gate_events
    )
    katana_profiles = Counter(
        str(event_data(row).get("profile") or "default")
        for row in katana_events
    )
    ffuf_profiles = Counter(
        str(event_data(row).get("profile") or "default")
        for row in ffuf_events
    )

    latest_extract_data = event_data(latest_extract)
    latest_katana_data = event_data(latest_katana)
    latest_ffuf_data = event_data(latest_ffuf)
    latest_gate_data = event_data(latest_gate)
    endpoint_test_time = (
        str(endpoint_tests[-1].get("time", ""))
        if endpoint_tests else row_time(latest_endpoint_test)
    )

    hints: list[str] = []
    if number_value(latest_katana_data.get("scoped_url_count")) > 0 and row_time(latest_katana) > row_time(latest_crawl):
        hints.append("Katana produced scoped seeds after the last crawl; consider recrawling before another extraction pass.")
    if number_value(latest_ffuf_data.get("candidate_count")) > 0 and row_time(latest_ffuf) > endpoint_test_time:
        hints.append("ffuf produced candidates after the last logged endpoint test; review and manually verify them before reporting.")
    if len(extract_unique_counts) >= 2 and extract_unique_counts[-1] == extract_unique_counts[-2]:
        hints.append("Endpoint totals are flat across the last two extracts; prefer Network review, high-value JS review, or config refinement over repeating the same extraction.")
    if number_value(latest_extract_data.get("total_unique")) > 0 and not test_rows:
        hints.append("Endpoints exist but no endpoint tests are logged; start endpoint-family verification and record results with log-test.")
    if test_status_counts.get("needs more context", 0) > test_status_counts.get("confirmed", 0) + test_status_counts.get("rejected", 0):
        hints.append("Many tests need more context; revisit parameter sources, related endpoints, and browser Network traces.")
    if latest_gate and not latest_gate_data.get("passed"):
        hints.append("The latest report gate failed; fix gate failures before treating a finding as reportable.")
    if not hints:
        hints.append("No strong metric signal yet; continue with the current soft loop and log meaningful results.")

    return {
        "target": base.name,
        "metrics_file": str(metrics_path(base)),
        "endpoint_tests_file": str(endpoint_tests_path(base)),
        "event_count": len(events),
        "last_event_time": str(events[-1].get("time", "")) if events else "",
        "events_by_type": counter_dict(event_counts),
        "endpoint_tests": {
            "records": len(endpoint_tests),
            "status_counts": counter_dict(test_status_counts),
        },
        "katana": {
            "runs": len(katana_events),
            "total_scoped_urls": katana_total,
            "latest_scoped_urls": number_value(latest_katana_data.get("scoped_url_count")),
            "profiles": counter_dict(katana_profiles),
        },
        "ffuf": {
            "runs": len(ffuf_events),
            "total_candidates": ffuf_total,
            "latest_candidates": number_value(latest_ffuf_data.get("candidate_count")),
            "profiles": counter_dict(ffuf_profiles),
        },
        "extract": {
            "runs": len(extract_events),
            "latest_total_unique": number_value(latest_extract_data.get("total_unique"), -1),
            "latest_total_raw": number_value(latest_extract_data.get("total_raw"), -1),
            "max_total_unique": max(extract_unique_counts) if extract_unique_counts else 0,
            "latest_delta_added": number_value(latest_extract_data.get("delta_added"), -1),
            "latest_delta_removed": number_value(latest_extract_data.get("delta_removed"), -1),
            "latest_delta_changed": number_value(latest_extract_data.get("delta_changed"), -1),
        },
        "gate": {
            "runs": len(gate_events),
            "counts": counter_dict(gate_counts),
            "latest_passed": bool(latest_gate_data.get("passed")) if latest_gate else None,
            "latest_failure_count": number_value(latest_gate_data.get("failure_count"), 0),
        },
        "hints": hints,
    }


def brief_event(row: dict[str, object]) -> str:
    data = event_data(row)
    parts = []
    for key in (
        "exit_code", "total_unique", "delta_added", "candidate_count",
        "scoped_url_count", "status", "passed", "completed", "ok", "skipped", "errors",
        "http_2xx", "http_3xx", "http_4xx", "http_5xx",
    ):
        if key in data and data.get(key) not in ("", None):
            parts.append(f"{key}={data.get(key)}")
    endpoint = data.get("endpoint")
    if endpoint:
        parts.append(f"endpoint={endpoint}")
    suffix = " " + " ".join(parts) if parts else ""
    return f"{row.get('time', '')} {row.get('event', '')}{suffix}"


def render_flywheel(base: Path, summary: dict[str, object]) -> str:
    endpoint_tests = summary.get("endpoint_tests", {})
    if not isinstance(endpoint_tests, dict):
        endpoint_tests = {}
    status_counts = endpoint_tests.get("status_counts", {})
    if not isinstance(status_counts, dict):
        status_counts = {}

    katana_raw = summary.get("katana", {})
    ffuf_raw = summary.get("ffuf", {})
    extract_raw = summary.get("extract", {})
    gate_raw = summary.get("gate", {})
    katana = katana_raw if isinstance(katana_raw, dict) else {}
    ffuf = ffuf_raw if isinstance(ffuf_raw, dict) else {}
    extract = extract_raw if isinstance(extract_raw, dict) else {}
    gate = gate_raw if isinstance(gate_raw, dict) else {}

    what_worked = []
    if number_value(katana.get("total_scoped_urls")):
        what_worked.append(f"- Katana contributed {katana.get('total_scoped_urls')} scoped URLs across {katana.get('runs')} run(s).")
    if number_value(ffuf.get("total_candidates")):
        what_worked.append(f"- ffuf produced {ffuf.get('total_candidates')} scoped candidates across {ffuf.get('runs')} run(s).")
    if number_value(extract.get("max_total_unique")):
        what_worked.append(f"- Endpoint extraction reached {extract.get('max_total_unique')} unique endpoints.")
    if number_value(status_counts.get("confirmed")):
        what_worked.append(f"- Confirmed findings: {status_counts.get('confirmed')}.")
    if not what_worked:
        what_worked.append("- Not enough recorded signal yet.")

    weak_spots = []
    if not number_value(endpoint_tests.get("records")) and number_value(extract.get("latest_total_unique"), -1) > 0:
        weak_spots.append("- Extracted endpoints have not been converted into logged endpoint tests.")
    if number_value(status_counts.get("needs more context")):
        weak_spots.append(f"- Needs more context: {status_counts.get('needs more context')} logged test(s).")
    if number_value(gate.get("latest_failure_count")):
        weak_spots.append(f"- Latest report gate has {gate.get('latest_failure_count')} failure(s).")
    if number_value(extract.get("latest_delta_added"), -1) == 0:
        weak_spots.append("- Latest extraction added no new endpoints; discovery inputs may be saturated.")
    if not weak_spots:
        weak_spots.append("- No clear weak spot from metrics yet.")

    lessons = []
    katana_profiles = katana.get("profiles", {})
    ffuf_profiles = ffuf.get("profiles", {})
    if isinstance(katana_profiles, dict) and katana_profiles:
        lessons.append("- Katana profiles used: " + ", ".join(f"{k}={v}" for k, v in katana_profiles.items()) + ".")
    if isinstance(ffuf_profiles, dict) and ffuf_profiles:
        lessons.append("- ffuf profiles used: " + ", ".join(f"{k}={v}" for k, v in ffuf_profiles.items()) + ".")
    if status_counts:
        lessons.append("- Endpoint test outcomes: " + ", ".join(f"{k}={v}" for k, v in status_counts.items()) + ".")
    if not lessons:
        lessons.append("- Keep recording tool runs and endpoint-test outcomes so the flywheel has material to learn from.")

    hints = summary.get("hints", [])
    if not isinstance(hints, list):
        hints = []
    prompt_patches = [f"- {hint}" for hint in hints] or ["- No prompt patch suggested yet."]

    lines = [
        f"# Flywheel Notes: {base.name}",
        "",
        f"Generated: {utc_now()}",
        "",
        "This is passive learning material for the next soft loop. It does not enforce a state machine.",
        "",
        "## Metrics Snapshot",
        "",
        f"- Events: {summary.get('event_count', 0)}",
        f"- Last event: {summary.get('last_event_time') or '-'}",
        f"- Latest extract: unique={metric_display(extract.get('latest_total_unique'))} raw={metric_display(extract.get('latest_total_raw'))} delta_added={metric_display(extract.get('latest_delta_added'))}",
        f"- Endpoint tests: {endpoint_tests.get('records', 0)}",
        f"- Gate runs: {gate.get('runs', 0)}",
        "",
        "## What Worked",
        "",
        *what_worked,
        "",
        "## Weak Spots",
        "",
        *weak_spots,
        "",
        "## Reusable Lessons",
        "",
        *lessons,
        "",
        "## Soft Loop Hints",
        "",
        *prompt_patches,
        "",
    ]
    return "\n".join(lines)


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
    append_metric(base, "init_target", {
        "domains_count": len(domains),
        "seeds_count": len(seeds),
        "config": args.config,
    })

    print(f"Target ready: {base}")
    print(f"Edit scope:   {base / 'scope.md'}")
    return 0


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
    if args.cookie:
        cmd.extend(["--cookie", args.cookie])
    if args.authorization:
        cmd.extend(["--authorization", args.authorization])
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
        if katana_seed_count:
            cmd.extend(["--seed-file", str(katana_seed_file)])

    targets = cli_target_domains + scope_domains
    for domain in sorted(set(targets)):
        cmd.extend(["--target", domain])
    for seed in sorted(set(args.seed or [])):
        cmd.extend(["--seed", seed])
    for seed in scope_list(scope, "seeds"):
        cmd.extend(["--seed", seed])

    code = run_cmd(cmd)
    crawl_state = {
        "finished_at": utc_now(),
        "exit_code": code,
        "outdir": str(outdir),
        "domains": scope_domains,
        "seeds": scope_list(scope, "seeds") + list(args.seed or []),
        "katana_seed_file": str(katana_seed_file) if katana_seed_count else "",
        "katana_seed_count": katana_seed_count,
        "config": args.config,
        "mode": args.mode,
        "depth": args.depth,
        "threads": threads,
        "delay": delay,
    }
    write_json(base / "state" / "last_crawl.json", crawl_state)
    append_metric(base, "crawl", {
        "exit_code": code,
        "domains_count": len(scope_domains),
        "seeds_count": len(crawl_state["seeds"]),
        "katana_seed_count": katana_seed_count,
        "config": args.config,
        "mode": args.mode,
        "depth": args.depth,
        "threads": threads,
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
            print(f"Compare with: python ai_src.py diff-endpoints {previous_snapshot} {post_snapshot}")
    else:
        append_metric(base, "extract", {
            "exit_code": code,
            "endpoints_file": str(out),
            "missing_output": True,
            "config": args.config,
        })
    return code


GATE_PATTERNS = [
    ("poc", re.compile(r"\b(curl|python|httpie|powershell|GET |POST |PUT |DELETE )\b", re.I)),
    ("impact", re.compile(r"(Impact|\u5f71\u54cd|Confidentiality|Integrity|Availability|\u673a\u5bc6\u6027|\u5b8c\u6574\u6027|\u53ef\u7528\u6027)", re.I)),
    ("scope", re.compile(r"(Scope|\u6388\u6743|\u8303\u56f4|Target)", re.I)),
    ("false_positive_exclusion", re.compile(r"(CORS|\u5b89\u5168\u5934|\u7248\u672c\u53f7|Self-XSS|\u8bef\u62a5|\u6392\u9664)", re.I)),
    ("fix", re.compile(r"(\u4fee\u590d|Remediation|\u5efa\u8bae|Enforce|\u6821\u9a8c|\u6388\u6743)", re.I)),
]

BANNED_TITLE_PATTERNS = [
    ("CORS-only finding", re.compile(r"\bCORS\b|Access-Control-Allow-Origin|\u8de8\u57df", re.I)),
    ("missing security headers", re.compile(r"security headers?|\u5b89\u5168\u5934|X-Frame-Options|X-Content-Type-Options|HSTS|CSP", re.I)),
    ("version disclosure", re.compile(r"version disclosure|\u7248\u672c(?:\u53f7)?(?:\u6cc4\u9732|\u66b4\u9732)|banner", re.I)),
    ("Self-XSS", re.compile(r"Self[- ]?XSS|\u81ea\u6211XSS", re.I)),
]

POC_PATTERN = re.compile(
    r"(curl\s+[^ \n\r]*\s*['\"]?https?://|"
    r"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?:https?://|/)[^\s]+|"
    r"Invoke-WebRequest\s+|http\s+(?:GET|POST|PUT|DELETE|PATCH)\s+|python\s+\S+\.py)",
    re.I,
)

REPORT_URL_RE = re.compile(r"https?://[^\s\"'`<>)\]]+", re.I)
PLACEHOLDER_VALUES = {"", "-", "TODO", "N/A", "NA", "NONE", "\u65e0", "\u4e0d\u9002\u7528"}


def checked_gate_count(text: str) -> int:
    count = 0
    for line in text.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("- [x]") or stripped.startswith("* [x]"):
            count += 1
    return count


def cjk_count(text: str) -> int:
    return len(re.findall(r"[\u4e00-\u9fff]", text))


def first_heading(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
    return ""


def field_value(text: str, labels: list[str]) -> str:
    for line in text.splitlines():
        stripped = line.strip().lstrip("-*").strip()
        for label in labels:
            pattern = rf"^{re.escape(label)}\s*[:\uff1a]\s*(.*)$"
            match = re.match(pattern, stripped, re.I)
            if not match:
                continue
            value = match.group(1).strip()
            if value.upper() not in PLACEHOLDER_VALUES:
                return value
    return ""


def extract_report_urls(text: str) -> list[str]:
    urls = []
    for match in REPORT_URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;")
        if url not in urls:
            urls.append(url)
    return urls


def infer_target_from_report(report: Path) -> str:
    try:
        parts = list(report.resolve().parts)
    except OSError:
        parts = list(report.parts)
    lowered = [part.lower() for part in parts]
    if "targets" in lowered:
        idx = lowered.index("targets")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def cmd_gate(args: argparse.Namespace) -> int:
    report = Path(args.report)
    if not report.exists():
        eprint(f"Report not found: {report}")
        return 2
    text = report.read_text(encoding="utf-8", errors="ignore")

    failures: list[str] = []
    title = first_heading(text)
    if cjk_count(text) < 80:
        failures.append("Final reports must be written mostly in Chinese")
    if checked_gate_count(text) < 7:
        failures.append("The seven report gates are not all checked as [x]")
    if "TODO" in text:
        failures.append("Report still contains TODO placeholders")
    if "https://example.com" in text:
        failures.append("Report still contains template example values")
    if not POC_PATTERN.search(text):
        failures.append("Missing concrete reproducible PoC command or HTTP request")
    for name, pattern in BANNED_TITLE_PATTERNS:
        if title and pattern.search(title):
            failures.append(f"Report title matches a do-not-report class: {name}")
    for name, pattern in GATE_PATTERNS:
        if not pattern.search(text):
            failures.append(f"Missing required content: {name}")
    required_fields = [
        ("Target", ["Target", "\u76ee\u6807"]),
        ("Scope", ["Scope", "\u6388\u6743\u8303\u56f4", "\u8303\u56f4"]),
        ("Test time", ["Test time", "\u6d4b\u8bd5\u65f6\u95f4"]),
        ("Verified IDs / parameters", ["Verified IDs / parameters", "Verified IDs", "\u5df2\u9a8c\u8bc1 ID", "\u5df2\u9a8c\u8bc1\u53c2\u6570"]),
        ("Cross-interface parameter migration", ["Cross-interface parameter migration attempted", "\u8de8\u63a5\u53e3\u53c2\u6570\u79fb\u690d"]),
        ("False-positive exclusion", ["Not CORS / security header / version disclosure / Self-XSS", "\u8bef\u62a5\u6392\u9664"]),
    ]
    for label, labels in required_fields:
        if not field_value(text, labels):
            failures.append(f"Missing non-placeholder field value: {label}")
    for label, labels in [
        ("Confidentiality", ["Confidentiality", "\u673a\u5bc6\u6027"]),
        ("Integrity", ["Integrity", "\u5b8c\u6574\u6027"]),
        ("Availability", ["Availability", "\u53ef\u7528\u6027"]),
    ]:
        if not field_value(text, labels):
            failures.append(f"Missing concrete CIA impact field: {label}")

    target_name = args.target or infer_target_from_report(report)
    if not target_name:
        failures.append("Target is required for scope validation; pass --target or store the report under targets/<target>/reports")
    else:
        base = target_dir(target_name)
        if not base.exists():
            failures.append(f"Target for scope validation does not exist: {base}")
        else:
            scope = parse_scope(base)
            urls = extract_report_urls(text)
            if not urls:
                failures.append("Report contains no absolute URL to validate against scope")
            elif not any(url_in_scope(url, scope) for url in urls):
                failures.append(f"No report URL is inside targets/{base.name}/scope.md")
    if re.search(r"Access-Control-Allow-Origin|X-Frame-Options|X-Content-Type-Options", text, re.I):
        if not re.search(r"(\u6570\u636e\u6cc4\u9732|\u8d8a\u6743|\u672a\u6388\u6743|\u6743\u9650\u63d0\u5347|RCE|\u547d\u4ee4\u6267\u884c|\u4e1a\u52a1\u903b\u8f91|\u654f\u611f)", text, re.I):
            failures.append("Report appears to describe only headers/configuration without proving real impact")

    metric_base = target_dir(target_name) if target_name and target_dir(target_name).exists() else None
    if failures:
        if metric_base:
            append_metric(metric_base, "gate", {
                "report": str(report),
                "passed": False,
                "failure_count": len(failures),
                "failures": failures,
            })
        print("Gate failed:")
        for item in failures:
            print(f"- {item}")
        return 1

    if metric_base:
        append_metric(metric_base, "gate", {
            "report": str(report),
            "passed": True,
            "failure_count": 0,
            "failures": [],
        })
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


KATANA_PROFILES = {
    "default": [],
    "routes": ["-pc"],
    "forms": ["-fx"],
    "headless-xhr": ["-headless", "-xhr"],
}

FFUF_PROFILES = {
    "default": [],
    "paths": ["-ac"],
    "params": ["-ac"],
    "recursive": ["-ac", "-recursion", "-recursion-depth", "1"],
}

KATANA_BLOCKED_PASSTHROUGH = {
    "-u", "-list", "-o", "-output", "-rl", "-rate-limit", "-c", "-concurrency",
    "-ns", "-no-scope", "-do", "-display-out-scope", "-cs", "-crawl-scope",
    "-cos", "-crawl-out-scope", "-fs", "-field-scope", "-config", "-resume",
}

FFUF_BLOCKED_PASSTHROUGH = {
    "-u", "-o", "-of", "-od", "-rate", "-t",
    "-request", "-request-proto", "-input-cmd", "-input-shell", "-config",
}


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
    cmd.extend(profile_args(KATANA_PROFILES, args.profile))
    cmd.extend(passthrough)
    code = run_cmd(cmd)
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
    redacted_passthrough = redact_cmd(passthrough)
    katana_state = {
        "finished_at": utc_now(),
        "exit_code": code,
        "url": args.url,
        "source": str(out),
        "seed_file": str(seed_file) if count else "",
        "scoped_url_count": count,
        "profile": args.profile,
        "passthrough": redacted_passthrough,
        "depth": args.depth,
        "rate_limit": rate_limit,
        "concurrency": concurrency,
    }
    write_json(base / "state" / "last_katana.json", katana_state)
    append_metric(base, "katana", {
        "exit_code": code,
        "url": args.url,
        "source": str(out),
        "scoped_url_count": count,
        "profile": args.profile,
        "passthrough": redacted_passthrough,
        "depth": args.depth,
        "rate_limit": rate_limit,
        "concurrency": concurrency,
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
    for header in args.header or []:
        cmd.extend(["-H", header])
    if args.data:
        cmd.extend(["-d", args.data])
    if args.extensions:
        cmd.extend(["-e", args.extensions])
    if args.filter_size:
        cmd.extend(["-fs", args.filter_size])
    cmd.extend(profile_args(FFUF_PROFILES, args.profile))
    cmd.extend(passthrough)
    code = run_cmd(cmd)
    print(f"Output: {out}")
    summary = ffuf_candidate_summary(out, scope)
    candidates_out = base / "state" / "ffuf_candidates.json"
    redacted_passthrough = redact_cmd(passthrough)
    write_json(candidates_out, {
        "created_at": utc_now(),
        "source": str(out),
        "target": base.name,
        "profile": args.profile,
        "passthrough": redacted_passthrough,
        "candidate_count": summary["count"],
        "candidates": summary["candidates"],
        "next": "Manually verify candidates through endpoint-testing before reporting.",
    })
    append_metric(base, "ffuf", {
        "exit_code": code,
        "url": args.url,
        "source": str(out),
        "candidate_count": summary["count"],
        "profile": args.profile,
        "passthrough": redacted_passthrough,
        "method": method or "GET",
        "rate": rate,
        "threads": threads,
    })
    print(f"Candidates: {summary['count']} -> {candidates_out}")
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
    test_log = base / "state" / "endpoint_tests.jsonl"
    domains = scope_list(scope, "domains")
    ip_ranges = scope_list(scope, "ip_ranges")
    allowed_wrappers = scope.get("allowed_wrappers")
    seeds = scope_list(scope, "seeds")

    print(f"Target: {base.name}")
    print(f"Path:   {base}")
    print(f"Domains ({len(domains)}): {', '.join(domains) or '-'}")
    print(f"IP ranges ({len(ip_ranges)}): {', '.join(ip_ranges) or '-'}")
    print(f"Seeds   ({len(seeds)}): {', '.join(seeds) or '-'}")
    if isinstance(allowed_wrappers, list):
        print(f"Allowed wrappers: {', '.join(allowed_wrappers) or 'none'}")
    if scope.get("max_threads"):
        print(f"Max threads: {scope.get('max_threads')}")
    if scope.get("max_request_rate"):
        print(f"Max request rate: {scope.get('max_request_rate')} req/s")
    print(f"Raw files: HTML={count_files(raw, ('.html', '.htm'))} JS={count_files(raw, ('.js',))}")
    if endpoints.exists():
        data = json.loads(endpoints.read_text(encoding="utf-8-sig", errors="ignore"))
        print(f"Endpoints: {data.get('total_unique')} unique / {data.get('total_raw')} raw")
        print(f"Endpoint file: {endpoints}")
    else:
        print("Endpoints: not extracted")
    if last_extract.exists():
        data = json.loads(last_extract.read_text(encoding="utf-8-sig", errors="ignore"))
        if data.get("previous_snapshot"):
            print(f"Previous snapshot: {data.get('previous_snapshot')}")
        if data.get("current_snapshot"):
            print(f"Current snapshot:  {data.get('current_snapshot')}")
    for name in (
        "katana_urls.txt",
        "katana_seeds.txt",
        "last_katana.json",
        "probe_results.json",
        "ffuf-safe.json",
        "ffuf_candidates.json",
    ):
        path = base / "state" / name
        if path.exists():
            print(f"State artifact: {path}")
    if test_log.exists():
        count = sum(1 for line in test_log.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())
        print(f"Endpoint tests: {count} records ({test_log})")
    metric_log = metrics_path(base)
    if metric_log.exists():
        events = read_metric_events(base)
        print(f"Metrics: {len(events)} events ({metric_log})")
    flywheel = base / "state" / "flywheel.md"
    if flywheel.exists():
        print(f"Flywheel: {flywheel}")
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    summary = summarize_target_metrics(base)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    events_by_type = summary.get("events_by_type", {})
    endpoint_tests = summary.get("endpoint_tests", {})
    katana = summary.get("katana", {})
    ffuf = summary.get("ffuf", {})
    extract = summary.get("extract", {})
    gate = summary.get("gate", {})

    print(f"Target: {base.name}")
    print(f"Metrics: {summary.get('event_count', 0)} events ({metrics_path(base)})")
    print(f"Last event: {summary.get('last_event_time') or '-'}")
    if isinstance(events_by_type, dict) and events_by_type:
        print("Events by type: " + ", ".join(f"{k}={v}" for k, v in events_by_type.items()))
    if isinstance(extract, dict):
        latest_unique = extract.get("latest_total_unique")
        latest_raw = extract.get("latest_total_raw")
        if latest_unique != -1:
            print(f"Extract: runs={extract.get('runs')} latest={latest_unique} unique / {latest_raw} raw max={extract.get('max_total_unique')}")
            print(
                "Extract delta: "
                f"added={metric_display(extract.get('latest_delta_added'))} "
                f"removed={metric_display(extract.get('latest_delta_removed'))} "
                f"changed={metric_display(extract.get('latest_delta_changed'))}"
            )
    if isinstance(katana, dict):
        print(f"Katana: runs={katana.get('runs')} latest_scoped={katana.get('latest_scoped_urls')} total_scoped={katana.get('total_scoped_urls')}")
    if isinstance(ffuf, dict):
        print(f"ffuf: runs={ffuf.get('runs')} latest_candidates={ffuf.get('latest_candidates')} total_candidates={ffuf.get('total_candidates')}")
    if isinstance(endpoint_tests, dict):
        status_counts = endpoint_tests.get("status_counts", {})
        status_text = ", ".join(f"{k}={v}" for k, v in status_counts.items()) if isinstance(status_counts, dict) else ""
        print(f"Endpoint tests: {endpoint_tests.get('records', 0)} records" + (f" ({status_text})" if status_text else ""))
    if isinstance(gate, dict):
        gate_counts = gate.get("counts", {})
        gate_text = ", ".join(f"{k}={v}" for k, v in gate_counts.items()) if isinstance(gate_counts, dict) else ""
        print(f"Gates: {gate.get('runs', 0)} runs" + (f" ({gate_text})" if gate_text else ""))

    hints = summary.get("hints", [])
    if isinstance(hints, list) and hints:
        print("Soft loop hints:")
        for hint in hints:
            print(f"- {hint}")

    if args.limit:
        events = read_metric_events(base)
        recent = events[-args.limit:]
        if recent:
            print("Recent events:")
            for row in recent:
                print(f"- {brief_event(row)}")
    return 0


def cmd_flywheel(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    if not base.exists():
        eprint(f"Target not found: {base}")
        return 2
    summary = summarize_target_metrics(base)
    text = render_flywheel(base, summary)
    if args.out == "-":
        print(text)
        return 0

    out = Path(args.out) if args.out else base / "state" / "flywheel.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"Flywheel updated: {out}")
    if args.print_report:
        print(text)
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
    append_metric(base, "checkpoint", {
        "has_direction": bool(args.direction),
        "has_tested": bool(args.tested),
        "has_findings": bool(args.findings),
        "has_next": bool(args.next),
    })
    print(f"Checkpoint updated: {checkpoint}")
    return 0


TEST_STATUS_VALUES = {
    "confirmed": "confirmed",
    "rejected": "rejected",
    "needs-account": "needs account",
    "needs-more-context": "needs more context",
    "out-of-scope": "out of scope",
}


def cmd_log_test(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
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

    if effective_url and not url_in_scope(effective_url, scope):
        eprint(f"Scope blocked: endpoint is outside targets/{base.name}/scope.md: {effective_url}")
        return 2

    record = {
        "time": utc_now(),
        "target": base.name,
        "endpoint": endpoint,
        "url": effective_url,
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


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = {}
    for key, value in headers.items():
        if key.lower() in {"authorization", "cookie", "x-api-key"}:
            redacted[key] = "REDACTED"
        else:
            redacted[key] = value
    return redacted


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

    headers = {"User-Agent": "AI-SRC-Agent/1.0 authorized-security-assessment"}
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
        "headers": redact_headers(headers),
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


def cmd_tools(args: argparse.Namespace) -> int:
    tools = ["katana", "ffuf"]
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
    data = json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
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
    data = json.loads(har_path.read_text(encoding="utf-8-sig", errors="ignore"))
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
    if workspace_base:
        append_metric(workspace_base, "import_har", {
            "har": str(har_path),
            "output": str(out),
            "total": len(results),
            "hosts": sorted(hosts),
            "as_endpoints": bool(args.as_endpoints),
        })
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
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--no-katana-seeds", action="store_true", help="do not include state/katana_seeds.txt in crawl")
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

    p = sub.add_parser("gate", help="validate report quality gates and target scope")
    p.add_argument("report")
    p.add_argument("--target", help="target name for scope validation; required unless inferred from targets/<target>/reports")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("status", help="show target status")
    p.add_argument("target")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("metrics", help="summarize passive target metrics")
    p.add_argument("target")
    p.add_argument("--json", action="store_true", help="print machine-readable summary")
    p.add_argument("--limit", type=int, default=10, help="recent metric events to print; 0 disables")
    p.set_defaults(func=cmd_metrics)

    p = sub.add_parser("flywheel", help="write passive learning notes from metrics")
    p.add_argument("target")
    p.add_argument("--out", help="output markdown path; use - to print only")
    p.add_argument("--print", dest="print_report", action="store_true", help="also print the generated markdown")
    p.set_defaults(func=cmd_flywheel)

    p = sub.add_parser("checkpoint", help="append compressed loop state")
    p.add_argument("target")
    p.add_argument("--direction")
    p.add_argument("--tested")
    p.add_argument("--findings")
    p.add_argument("--next")
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("log-test", help="append one structured endpoint test record")
    p.add_argument("target")
    p.add_argument("endpoint")
    p.add_argument("--base-url")
    p.add_argument("--method", default="")
    p.add_argument("--status", choices=sorted(TEST_STATUS_VALUES), required=True)
    p.add_argument("--params", default="")
    p.add_argument("--function", default="")
    p.add_argument("--attack-surface", default="")
    p.add_argument("--auth-context", default="")
    p.add_argument("--requests", default="")
    p.add_argument("--expected", default="")
    p.add_argument("--actual", default="")
    p.add_argument("--evidence", default="")
    p.add_argument("--next", default="")
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_log_test)

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
    p.add_argument("--workspace-target", help="target name; filters requests through targets/<target>/scope.md")
    p.add_argument("--out")
    p.add_argument("--as-endpoints", action="store_true", help="export in endpoints.json-compatible format")
    p.set_defaults(func=cmd_import_har)

    p = sub.add_parser("rank-js", help="rank crawled JS/HTML files for manual review")
    p.add_argument("sites_dir")
    p.add_argument("--out")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_rank_js)

    p = sub.add_parser(
        "katana-crawl",
        help="run katana URL discovery with conservative defaults",
        epilog="Native katana args may be appended after --; safety/state flags such as -u, -o, -rl, -c and scope overrides are blocked.",
    )
    p.add_argument("target")
    p.add_argument("url")
    p.add_argument("--out")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--rate-limit", type=int, default=5)
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--headless", action="store_true")
    p.add_argument("--profile", choices=sorted(KATANA_PROFILES), default="default", help="small preset of native katana args")
    p.set_defaults(func=cmd_katana_crawl, allow_passthrough=True)

    p = sub.add_parser(
        "ffuf-safe",
        help="run ffuf with conservative low-rate defaults",
        epilog="Native ffuf args may be appended after --; safety/state flags such as -u, -o, -of, -rate and -t are blocked.",
    )
    p.add_argument("target")
    p.add_argument("url", help="target URL; FUZZ may be here, in --header, or in --data")
    p.add_argument("wordlist")
    p.add_argument("--out")
    p.add_argument("--rate", type=int, default=20)
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--method", default="", help="optional HTTP method; defaults to POST when --data is used")
    p.add_argument("--header", action="append", default=[], help="ffuf -H header; may contain FUZZ")
    p.add_argument("--data", default="", help="ffuf -d request body; may contain FUZZ")
    p.add_argument("--match-codes", default="200,204,301,302,307,401,403")
    p.add_argument("--extensions", help="ffuf -e value, for example .js,.json")
    p.add_argument("--filter-size", help="ffuf -fs value")
    p.add_argument("--profile", choices=sorted(FFUF_PROFILES), default="default", help="small preset of native ffuf args")
    p.set_defaults(func=cmd_ffuf_safe, allow_passthrough=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)
    if getattr(args, "allow_passthrough", False):
        args.tool_args = unknown
    elif unknown:
        parser.error("unrecognized arguments: " + " ".join(unknown))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
