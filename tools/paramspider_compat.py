#!/usr/bin/env python3
"""Small ParamSpider-compatible fallback used when upstream install fails.

The official ParamSpider project is preferred. This fallback implements the
CLI surface SRCFlow needs: mine parameterized URLs from Web Archive, replace
parameter values with a placeholder, optionally stream results, and write an
output file.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

try:
    import requests
except ImportError:
    requests = None


DEFAULT_EXCLUDED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json", ".css", ".js",
    ".webp", ".woff", ".woff2", ".eot", ".ttf", ".otf", ".mp4", ".txt",
}


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = value.replace("https://", "").replace("http://", "")
    return value.strip("/")


def extension_blocked(url: str, extensions: set[str]) -> bool:
    suffix = Path(urlparse(url).path).suffix.lower()
    return bool(suffix and suffix in extensions)


def clean_url(url: str, placeholder: str, extensions: set[str]) -> str:
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc or not parsed.query:
        return ""
    if extension_blocked(url, extensions):
        return ""
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return ""
    replaced = {key: placeholder for key in params if key}
    if not replaced:
        return ""
    return parsed._replace(query=urlencode(replaced, doseq=True)).geturl()


def fetch_wayback_urls(domain: str, proxy: str = "") -> list[str]:
    if requests is None:
        raise RuntimeError("Python package missing: requests")
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original&page=/"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    response = requests.get(url, proxies=proxies, timeout=45)
    response.raise_for_status()
    return response.text.split()


def mine_domain(domain: str, args: argparse.Namespace, extensions: set[str]) -> list[str]:
    raw_urls = fetch_wayback_urls(domain, args.proxy or "")
    cleaned: set[str] = set()
    for url in raw_urls:
        item = clean_url(url, args.placeholder, extensions)
        if item:
            cleaned.add(item)
    return sorted(cleaned)


def write_results(domain: str, urls: list[str], output: str) -> Path:
    if output:
        path = Path(output)
    else:
        results_dir = Path("results")
        results_dir.mkdir(parents=True, exist_ok=True)
        path = results_dir / f"{domain}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    return path


def parse_extensions(value: str) -> set[str]:
    if not value:
        return set(DEFAULT_EXCLUDED_EXTENSIONS)
    result = set(DEFAULT_EXCLUDED_EXTENSIONS)
    for item in value.split(","):
        item = item.strip().lower()
        if not item:
            continue
        result.add(item if item.startswith(".") else f".{item}")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mining URLs from Web Archives for parameters")
    parser.add_argument("-d", "--domain", help="Domain name to fetch related URLs for.")
    parser.add_argument("-l", "--list", help="File containing domain names.")
    parser.add_argument("-s", "--stream", action="store_true", help="Stream URLs to stdout.")
    parser.add_argument("--proxy", default="", help="Proxy URL for web requests.")
    parser.add_argument("-p", "--placeholder", default="FUZZ", help="Placeholder for parameter values.")
    parser.add_argument("--exclude", default="", help="Comma-separated extensions to exclude in addition to defaults.")
    parser.add_argument("--output", default="", help="Output file. With --list this is ignored.")
    parser.add_argument("--quiet", action="store_true", help="Suppress informational stderr output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.domain and not args.list:
        parser.error("Please provide either -d/--domain or -l/--list.")
    if args.domain and args.list:
        parser.error("Please provide either -d/--domain or -l/--list, not both.")

    if args.list:
        domains = []
        for line in Path(args.list).read_text(encoding="utf-8", errors="ignore").splitlines():
            domain = normalize_domain(line)
            if domain and domain not in domains:
                domains.append(domain)
    else:
        domains = [normalize_domain(args.domain)]

    extensions = parse_extensions(args.exclude)
    exit_code = 0
    for domain in domains:
        if not domain:
            continue
        try:
            urls = mine_domain(domain, args, extensions)
        except Exception as exc:
            print(f"[paramspider-compat] {domain}: {type(exc).__name__}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        output = "" if args.list else args.output
        path = write_results(domain, urls, output)
        if not args.quiet:
            print(f"[paramspider-compat] {domain}: {len(urls)} URLs -> {path}", file=sys.stderr)
        if args.stream:
            for url in urls:
                print(url)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
