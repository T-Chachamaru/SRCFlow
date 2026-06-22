"""srcflow.scope - extracted from ai_src.py"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from srcflow.constants import CONFIG_DIR, KNOWN_WRAPPERS, LINE_URL_RE
from srcflow.io_helpers import read_json_file
from srcflow.utils import eprint, number_value, parse_first_number, read_lines_file

def parse_allowed_wrappers(value: str) -> list[str] | None:
    normalized = value.lower().strip()
    if not normalized or normalized in {"todo", "n/a", "na", "-"}:
        return None
    if re.search(r"\b(none|no wrappers|not allowed|disabled)\b", normalized):
        return []
    if normalized in {"all", "both", "*", "any"}:
        return sorted(KNOWN_WRAPPERS)
    wrappers = sorted(wrapper for wrapper in KNOWN_WRAPPERS if wrapper in normalized)
    if wrappers:
        return wrappers
    return None



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
        line = stripped.lstrip("-*+").strip()
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
    value = value.strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        host = urlparse(value).hostname or ""
    else:
        candidate = value
        if "/" in candidate:
            candidate = urlparse("https://" + candidate).hostname or candidate
        if candidate.startswith("["):
            bracket_end = candidate.find("]")
            host = candidate[1:bracket_end] if bracket_end > 0 else candidate
        elif candidate.count(":") >= 2:
            host = candidate
        else:
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
        if 0 < cap < 1.0:
            eprint(f"Warning: scope max_request_rate={cap} is fractional; {label} capped to {capped} (integer rate limit, delay-based limiting may be needed for exact rate)")
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
        if not url or not url_in_scope(url, scope):
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



def require_domain_in_scope(base: Path, scope: dict[str, object], domain: str) -> bool:
    if not require_scope_ready(base, scope):
        return False
    if host_in_scope(domain, scope):
        return True
    eprint(f"Scope blocked: domain is outside targets/{base.name}/scope.md: {domain}")
    return False



def raw_scope_field(text: str, label: str) -> str:
    pattern = rf"^- {re.escape(label)}:\s*(.*)$"
    match = re.search(pattern, text, flags=re.M)
    return match.group(1).strip() if match else ""



def missing_setup_value(value: str) -> bool:
    clean = value.strip()
    if not clean:
        return True
    lowered = clean.lower()
    return (
        lowered in {"todo", "tbd", "n/a", "na", "none", "-"}
        or re.match(r"^todo(\s*[-:].*|\s*$)", lowered) is not None
        or clean in {"无", "不适用"}
    )



def target_state_config(base: Path) -> str:
    raw = read_json_file(base / "state" / "target.json", {})
    if isinstance(raw, dict):
        value = str(raw.get("config") or "").strip()
        if value:
            return value
    target_config = CONFIG_DIR / f"{base.name}.json"
    if target_config.exists():
        return base.name
    return "default"



def endpoint_export_count(path: Path) -> tuple[int, int]:
    if not path.exists():
        return 0, 0
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return 0, 0
    if not isinstance(data, dict):
        return 0, 0
    return number_value(data.get("total_unique"), 0), number_value(data.get("total_raw"), 0)

