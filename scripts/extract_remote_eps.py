#!/usr/bin/env python3
"""Config-driven API endpoint extractor.

No single regex set can fully recover endpoints from obfuscated front-end code.
This script is intentionally a repeatable extraction pass: run it, compare the
result with manual JS/HTML review and browser Network observations, update the
config regexes, then run it again.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DEFAULT_CONFIG = CONFIG_DIR / "default.json"
DEFAULT_SITES_DIR = "remote_sites"
DEFAULT_OUT = "remote_sites_endpoints.json"


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


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_config_path(value: str | None) -> Path:
    if not value:
        return DEFAULT_CONFIG
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


def load_config(path: Path) -> dict:
    data = load_json(path)
    parent = data.get("extends")
    if parent:
        parent_path = (path.parent / parent).resolve()
        data = deep_merge(load_config(parent_path), data)
    return data


def split_values(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item and item not in result:
                result.append(item)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract API endpoints from HTML/JS/manifest/links")
    parser.add_argument("--sites-dir", "-i", default=DEFAULT_SITES_DIR,
                        help=f"Crawler output directory, default {DEFAULT_SITES_DIR}")
    parser.add_argument("--out", "-o", default=DEFAULT_OUT,
                        help=f"JSON output path, default {DEFAULT_OUT}")
    parser.add_argument("--config", "-c", default=str(DEFAULT_CONFIG),
                        help="Rule config JSON; pass config/default.json or a config name")
    parser.add_argument("--target", action="append", default=[],
                        help="Target domain keyword, repeatable; comma-separated values are allowed")
    parser.add_argument("--regex", action="append", default=[],
                        help="Temporarily add an extraction regex; must include named group (?P<endpoint>...)")
    parser.add_argument("--api-prefix", action="append", default=[],
                        help="Temporarily add an API path prefix")
    parser.add_argument("--known-endpoint", action="append", default=[],
                        help="Temporarily add a known probe endpoint")
    parser.add_argument("--all-domains", action="store_true",
                        help="Export all domains without target keyword filtering")
    parser.add_argument("--no-known", action="store_true",
                        help="Do not append known_endpoints")
    parser.add_argument("--max-file-bytes", type=int, default=2_000_000,
                        help="Maximum bytes to read per file")
    return parser


def compile_regexes(patterns: list[dict]) -> list[dict]:
    compiled = []
    for item in patterns:
        pattern = item.get("pattern", "")
        if "?P<endpoint>" not in pattern:
            raise ValueError(f"extract pattern must include (?P<endpoint>...): {item.get('name', pattern)}")
        compiled.append({
            "name": item.get("name", "CUSTOM"),
            "kind": item.get("kind", "relative"),
            "confidence": item.get("confidence", "custom"),
            "regex": re.compile(pattern.encode("utf-8"), re.IGNORECASE | re.DOTALL),
        })
    return compiled


def clean_endpoint(value: str) -> str:
    value = value.strip().strip("\"'`")
    value = value.rstrip(",;:" + chr(92) + ")]} ")
    value = re.sub(r"\$\{[^}]+\}", "{param}", value)
    value = re.sub(r"\s+", "", value)
    return value


def any_suffix(value: str, suffixes: list[str]) -> bool:
    lower = value.lower()
    return any(lower.endswith(s.lower()) for s in suffixes)


def path_matches_api(path: str, config: dict) -> bool:
    lower = path.lower()
    if any(keyword.lower() in lower for keyword in config.get("special_keywords", [])):
        return True
    if any_suffix(path, config.get("skip_extensions", [])):
        return False
    for prefix in config.get("api_prefixes", []):
        p = prefix.lower()
        if lower.startswith(p) or f"/{p.lstrip('/')}" in lower:
            return True
    for pattern in config.get("api_path_regexes", []):
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False


def is_api_url(endpoint: str, config: dict) -> bool:
    try:
        parsed = urlparse(endpoint)
        path = parsed.path or "/"
        if any_suffix(path, config.get("skip_extensions", [])):
            if not any(keyword.lower() in endpoint.lower() for keyword in config.get("special_keywords", [])):
                return False
        return path_matches_api(path, config)
    except Exception:
        return False


def should_keep(endpoint: str, kind: str, config: dict) -> bool:
    if not (2 <= len(endpoint) <= 600):
        return False
    if endpoint.count("'") > 3 or endpoint.count('"') > 3:
        return False
    if any(g and g in endpoint for g in config.get("garbage_substrings", [])):
        return False
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return is_api_url(endpoint, config)
    if endpoint.startswith("/"):
        if kind == "high":
            return not any_suffix(endpoint, config.get("skip_extensions", []))
        return path_matches_api(endpoint, config)
    return False


def normalize_endpoint(endpoint: str) -> str:
    endpoint = re.sub(r"/\d{6,}", "/{id}", endpoint)
    endpoint = re.sub(r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "/{uuid}", endpoint, flags=re.I)
    endpoint = re.sub(r"/[a-f0-9]{16,}", "/{hex}", endpoint, flags=re.I)
    return endpoint


def endpoint_domain(endpoint: str) -> str:
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return urlparse(endpoint).netloc.split(":")[0]
    if endpoint.startswith("/"):
        return "__RELATIVE__"
    return "__OTHER__"


def domain_allowed(domain: str, target_keywords: list[str], all_domains: bool) -> bool:
    if all_domains:
        return True
    if domain == "__RELATIVE__":
        return True
    return any(keyword.lower() in domain.lower() for keyword in target_keywords)


def add_endpoint(store: dict, endpoint: str, source: str, typ: str) -> None:
    store[endpoint]["sources"].add(source)
    store[endpoint]["types"].add(typ)


def extract_from_files(sites_dir: Path, config: dict, patterns: list[dict], max_file_bytes: int) -> tuple[dict, int]:
    all_eps = defaultdict(lambda: {"sources": set(), "types": set()})
    file_count = 0
    skip_dirs = set(config.get("third_party_domains", [])) | set(config.get("skip_dirs", []))

    for root, dirs, files in os.walk(sites_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (".js", ".html", ".htm"):
                continue
            path = Path(root) / fname
            try:
                size = path.stat().st_size
                if size < 20:
                    continue
                content = path.read_bytes()[:max_file_bytes]
            except OSError:
                continue
            file_count += 1

            for item in patterns:
                for match in item["regex"].finditer(content):
                    raw = match.group("endpoint")
                    endpoint = clean_endpoint(raw.decode("utf-8", errors="replace"))
                    keep_kind = "high" if item["confidence"] == "high" else item["kind"]
                    if not should_keep(endpoint, keep_kind, config):
                        continue
                    add_endpoint(all_eps, endpoint, str(path)[:160], item["name"])

    return all_eps, file_count


def extract_manifest_links(sites_dir: Path, config: dict, all_eps: dict) -> tuple[int, int]:
    manifest_count = 0
    links_count = 0
    manifest_path = sites_dir / "manifest.jsonl"
    if manifest_path.exists():
        for line in manifest_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = record.get("url", "")
            if not should_keep(url, "absolute", config):
                continue
            add_endpoint(all_eps, url, "manifest", "MANIFEST")
            manifest_count += 1
            path = urlparse(url).path
            if path and path != "/" and path_matches_api(path, config):
                add_endpoint(all_eps, path, "manifest-rel", "MANIFEST")

    links_path = sites_dir / "links.jsonl"
    if links_path.exists():
        for line in links_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = record.get("discovered_url", "")
            if not should_keep(url, "absolute", config):
                continue
            if url not in all_eps:
                add_endpoint(all_eps, url, "links", "LINKS")
                links_count += 1
    return manifest_count, links_count


def build_groups(normalized: dict) -> dict:
    by_domain = defaultdict(list)
    for norm, info in normalized.items():
        endpoint = sorted(info["origins"], key=len)[0]
        types = ",".join(sorted(info["types"]))
        by_domain[endpoint_domain(endpoint)].append((endpoint, len(info["sources"]), types, norm))
    return by_domain


def print_summary(by_domain: dict, target_keywords: list[str], all_domains: bool, config: dict,
                  total_unique: int, total_raw: int, file_count: int, sites_dir: Path) -> None:
    print(f"API endpoints: {total_unique} unique after normalization (raw: {total_raw})")
    print(f"  Sources: JS/HTML files={file_count} + manifest + links.jsonl")
    print(f"  Input dir: {sites_dir}")
    print()

    category_rules = [
        ("High Confidence", lambda e: any(tag in e[2] for tag in ("AXIOS", "FETCH", "HTTP_ANNOTATION", "MANIFEST"))),
        ("Configured Prefix", lambda e: path_matches_api(urlparse(e[0]).path if e[0].startswith("http") else e[0], config)),
        ("Other", lambda e: True),
    ]

    for domain in sorted(by_domain):
        if not domain_allowed(domain, target_keywords, all_domains):
            continue
        endpoints = sorted(by_domain[domain], key=lambda x: (-x[1], x[0]))
        print(f"## [{domain}] ({len(endpoints)} endpoints)")
        remaining = endpoints
        for label, predicate in category_rules:
            bucket = [item for item in remaining if predicate(item)]
            if not bucket:
                continue
            print(f"\n  --- {label} ({len(bucket)}) ---")
            for endpoint, count, typ, _norm in bucket:
                print(f"  {endpoint}  [{typ}; {count} src]")
            bucket_set = {item[0] for item in bucket}
            remaining = [item for item in remaining if item[0] not in bucket_set]
        print()

    specials = []
    keywords = [k.lower() for k in config.get("special_keywords", [])]
    for endpoints in by_domain.values():
        for endpoint, count, typ, _norm in endpoints:
            if any(keyword in endpoint.lower() for keyword in keywords):
                specials.append((endpoint, count, typ))
    print("=" * 60)
    print("Special endpoints:")
    if specials:
        for endpoint, count, typ in sorted(specials):
            print(f"  {endpoint}  [{typ}; {count} src]")
        print(f"  Total: {len(specials)}")
    else:
        print("  (none)")


def export_json(out: Path, by_domain: dict, normalized: dict, target_keywords: list[str],
                all_domains: bool, config: dict, sites_dir: Path) -> None:
    export = {
        "total_unique": len(normalized),
        "total_raw": sum(len(info["origins"]) for info in normalized.values()),
        "sites_dir": str(sites_dir),
        "target_keywords": target_keywords,
        "config": config.get("_config_path", ""),
        "by_domain": {},
        "relative": [],
        "special": [],
    }

    for domain, endpoints in sorted(by_domain.items()):
        if not domain_allowed(domain, target_keywords, all_domains):
            continue
        items = [
            {"endpoint": endpoint, "sources": count, "type": typ, "normalized": norm}
            for endpoint, count, typ, norm in sorted(endpoints, key=lambda x: (-x[1], x[0]))
        ]
        if domain == "__RELATIVE__":
            export["relative"] = items
        else:
            export["by_domain"][domain] = items

    keywords = [k.lower() for k in config.get("special_keywords", [])]
    for endpoints in by_domain.values():
        for endpoint, count, typ, norm in endpoints:
            if any(keyword in endpoint.lower() for keyword in keywords):
                export["special"].append({
                    "endpoint": endpoint,
                    "sources": count,
                    "type": typ,
                    "normalized": norm,
                })

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(export, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nJSON → {out}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = resolve_config_path(args.config)
    config = load_config(config_path)
    config["_config_path"] = str(config_path)

    target_keywords = split_values(args.target) or list(config.get("target_keywords", []))
    if "__RELATIVE__" not in target_keywords:
        target_keywords.append("__RELATIVE__")
    config["api_prefixes"] = list(config.get("api_prefixes", [])) + split_values(args.api_prefix)

    patterns = list(config.get("extract_patterns", []))
    for idx, regex in enumerate(args.regex, 1):
        patterns.append({
            "name": f"CLI_REGEX_{idx}",
            "pattern": regex,
            "kind": "relative",
            "confidence": "custom",
        })
    compiled_patterns = compile_regexes(patterns)

    sites_dir = Path(args.sites_dir)
    all_eps, file_count = extract_from_files(sites_dir, config, compiled_patterns, args.max_file_bytes)
    extract_manifest_links(sites_dir, config, all_eps)

    if not args.no_known:
        for endpoint in list(config.get("known_endpoints", [])) + split_values(args.known_endpoint):
            if endpoint not in all_eps:
                add_endpoint(all_eps, endpoint, "known", "KNOWN")

    normalized = defaultdict(lambda: {"origins": set(), "sources": set(), "types": set()})
    for endpoint, info in all_eps.items():
        norm = normalize_endpoint(endpoint)
        normalized[norm]["origins"].add(endpoint)
        normalized[norm]["sources"].update(info["sources"])
        normalized[norm]["types"].update(info["types"])

    by_domain = build_groups(normalized)
    total_raw = len(all_eps)
    print_summary(by_domain, target_keywords, args.all_domains, config,
                  len(normalized), total_raw, file_count, sites_dir)
    export_json(Path(args.out), by_domain, normalized, target_keywords,
                args.all_domains, config, sites_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
