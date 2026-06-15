#!/usr/bin/env python3
"""
Recursively crawl HTML / JS / SPA entry resources for target domains.

v2 improvements:
- Resume support: frontier.jsonl stores the pending queue.
- parsed_hashes uses (hash, host) to avoid losing relative links.
- Playwright cookies are injected per seed origin; Authorization uses extra HTTP headers.
- Long-lived thread pool and per-thread HTTP session reuse.
- Response header prefiltering by Content-Length and Content-Type.
- Heavy regexes run only when signals are present.
- sitemap.xml and robots.txt seed discovery.
- SPA route patterns: router.push / linkTo / hash routes.
- Layered crawl modes: pages | api | full.
- links.jsonl records link provenance.
- Failure statistics are grouped by reason.
"""
from __future__ import annotations

import argparse
import hashlib
import html as html_mod
import json
import os
import queue
import random
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urldefrag, urljoin, urlparse, urlunparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from xml.etree import ElementTree

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

try:
    from curl_cffi import requests as curl_requests
except ImportError:
    curl_requests = None

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT_DIR / "config"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "default.json"

DEFAULT_TARGET_KW = set()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", ".claude",
    ".playwright-mcp", "__pycache__", "node_modules",
    "aspose-words-src", "aspose_classes", "dump", "remote_sites",
}

DEFAULT_EXTRA_SEEDS: list[str] = []

TRACKING_QUERY_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "spm", "from",
}

# ── Regex patterns (compiled once) ──────────────────────────────

URL_RE = re.compile(
    rb"https?://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}"
    rb"(?::[0-9]{1,5})?(?:/[^\s\"'<>,;)\]\[{}\\]*)?",
    re.IGNORECASE,
)

ABS_URL_RE = re.compile(
    r"""(?P<url>https?://[a-z0-9.-]+\.[a-z]{2,}(?::[0-9]{1,5})?[^\s"'<>)]{0,500})""",
    re.IGNORECASE,
)

JS_CALL_RE = re.compile(
    r"""(?:fetch|import|require|axios\.(?:get|post|put|delete|patch|request))\s*\(\s*["'](?P<url>[^"'\s<>]{2,500})["']""",
    re.IGNORECASE,
)

JS_IMPORT_RE = re.compile(
    r"""(?:from\s+|import\s*)["'](?P<url>(?:\./|\.\./|/|https?://|//)[^"'\s<>]{2,500})["']""",
    re.IGNORECASE,
)

JS_OBJECT_URL_RE = re.compile(
    r"""(?:url|baseURL|href|src|path|api)\s*:\s*["'](?P<url>(?:\./|\.\./|/|https?://|//)[^"'\s<>]{2,500})["']""",
    re.IGNORECASE,
)

JS_NAVIGATION_RE = re.compile(
    r"""(?:location(?:\.href)?|window\.location(?:\.href)?|document\.location(?:\.href)?)\s*=\s*["'](?P<assign>[^"']{1,500})["']|(?:location\.replace|location\.assign|window\.open)\s*\(\s*["'](?P<call>[^"']{1,500})["']""",
    re.IGNORECASE,
)

REQUIRE_ARRAY_RE = re.compile(
    r"""(?:require|define)\s*\(\s*\[(?P<deps>[^\]]{1,5000})\]""",
    re.IGNORECASE | re.DOTALL,
)

REQUIRE_CONFIG_PATHS_RE = re.compile(
    r"""(?:requirejs|require)\.config\s*\(\s*\{(?P<body>.{1,12000})\}\s*\)""",
    re.IGNORECASE | re.DOTALL,
)

JS_STRING_RE = re.compile(r"""["'](?P<value>[^"']+)["']""")

JS_TEMPLATE_URL_RE = re.compile(
    r"""`(?P<url>(?:/|https?://|//)[^`]{0,500}\$\{[^}]+\}[^`]{0,500})`""",
    re.IGNORECASE,
)

QUOTED_PATH_RE = re.compile(
    r"""["'](?P<url>(?:\./|\.\./|/)[a-zA-Z0-9._~!$&'()*+,;=:@%/-]{2,500})["']""")

CSS_URL_RE = re.compile(
    r"""(?:url\(|@import\s+)(?:\s*)["']?(?P<url>[^"')\s<>]{2,500})["']?""",
    re.IGNORECASE,
)

DATA_MAIN_RE = re.compile(
    r"""data-main\s*=\s*["'](?P<url>[^"']{2,500})["']""", re.IGNORECASE)

WEBPACK_CSS_CHUNK_RE = re.compile(
    r"""["']css/["']\s*\+\s*e\s*\+\s*["']-["']\s*\+\s*\{(?P<hashes>[^}]+)\}\[e\]\s*\+\s*["']\.css["']""",
    re.DOTALL,
)

WEBPACK_JS_CHUNK_RE = re.compile(
    r"""["']js/["']\s*\+\s*\(\s*\{(?P<names>[^}]+)\}\[e\]\s*\|\|\s*e\s*\)\s*\+\s*["']-["']\s*\+\s*\{(?P<hashes>[^}]+)\}\[e\]\s*\+\s*["']\.js["']""",
    re.DOTALL,
)

WEBPACK_MAP_ENTRY_RE = re.compile(r"""(?P<id>\d+)\s*:\s*["'](?P<value>[^"']+)["']""")

# New: SPA route patterns
SPA_ROUTER_PUSH_RE = re.compile(
    r"""(?:router|navigateTo|redirectTo|switchTab|reLaunch|navigateBack|uni\.navigateTo)\s*\(\s*["'](?P<path>[^"']{2,300})["']""",
    re.IGNORECASE,
)

SPA_LINK_TO_RE = re.compile(
    r"""(?:linkTo|push|replace|go|navigate)\s*\(\s*(?:\{[^}]*path\s*:\s*)?["'](?P<path>[^"']{2,300})["']""",
    re.IGNORECASE,
)

SPA_HASH_ROUTE_RE = re.compile(
    r"""(?:href|to)\s*=\s*["']#(?P<hash>[^"'\s]{2,200})["']""", re.IGNORECASE)

SITEMAP_LOC_RE = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.IGNORECASE)

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".wav", ".mp4", ".m4v", ".webm", ".ogg", ".mov", ".avi", ".flv",
    ".zip", ".rar", ".exe", ".dmg", ".apk", ".ipa", ".jar", ".tar", ".gz", ".bz2", ".7z",
    ".map", ".less", ".scss", ".sass",
}

# Content-Types we don't want to download
SKIP_CONTENT_TYPES = {
    "image/", "video/", "audio/", "font/",
    "application/zip", "application/x-rar", "application/x-tar",
    "application/gzip", "application/x-7z", "application/x-gzip",
    "application/octet-stream",
}

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


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


def resolve_config_path(value: str | None) -> Optional[Path]:
    if not value:
        return DEFAULT_CONFIG_PATH if DEFAULT_CONFIG_PATH.exists() else None
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


def load_tool_config(value: str | None) -> dict:
    path = resolve_config_path(value)
    if not path:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    parent = data.get("extends")
    if parent:
        data = deep_merge(load_tool_config(str((path.parent / parent).resolve())), data)
    data["_config_path"] = str(path)
    return data


def split_config_values(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        for item in str(value).split(","):
            item = item.strip()
            if item and item not in result:
                result.append(item)
    return result


# ── Data classes ─────────────────────────────────────────────────

@dataclass
class CrawlerConfig:
    threads: int = 10
    max_depth: int = 0
    outdir: Path = Path("remote_sites")
    root: Path = Path(".")
    max_size: int = 5 * 1024 * 1024
    timeout: float = 20.0
    retries: int = 2
    retry_backoff: float = 1.0
    delay: float = 0.0
    batch_size: int = 0
    max_urls: int = 0
    target_kw: set[str] = field(default_factory=lambda: set(DEFAULT_TARGET_KW))
    skip_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_SKIP_DIRS))
    include_css: bool = False
    include_json: bool = False
    parse_json_links: bool = False
    retry_failed: bool = False
    resume_parse_existing: bool = True
    no_extra_seeds: bool = False
    render: bool = False
    render_timeout: float = 15.0
    render_depth: int = 0  # 0=initial seeds only, N=max rerender rounds
    verbose: bool = False
    cookies: str = ""
    authorization: str = ""
    mode: str = "pages"  # pages | api | full
    extra_seeds: list[str] = field(default_factory=list)

    @property
    def manifest_path(self) -> Path:
        return self.outdir / "manifest.jsonl"

    @property
    def frontier_path(self) -> Path:
        return self.outdir / "frontier.jsonl"

    @property
    def failed_path(self) -> Path:
        return self.outdir / "failed_urls.txt"

    @property
    def links_path(self) -> Path:
        return self.outdir / "links.jsonl"

    @property
    def effective_batch_size(self) -> int:
        if self.batch_size > 0:
            return self.batch_size
        return max(1, self.threads * 5)


@dataclass
class FetchResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes


@dataclass
class CrawlResult:
    url: str
    depth: int
    source_url: str
    status: str
    discovered: set[str] = field(default_factory=set)
    http_status: Optional[int] = None
    content_type: str = ""
    kind: str = ""
    byte_count: int = 0
    content_hash: str = ""
    path: str = ""
    error: str = ""
    elapsed: float = 0.0
    attempts: int = 1

    @property
    def failed(self) -> bool:
        return self.status in {"fail", "too_large", "too_small", "not_target"}


# ── Utility functions ────────────────────────────────────────────

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_candidate_url(raw: str) -> str:
    value = html_mod.unescape(raw.strip())
    value = value.replace("\\/", "/")
    value = value.strip(" \t\r\n\"'`<>")
    value = value.rstrip(".,;:)]}")
    return value


def normalize_url(raw: str, base_url: str = "", strip_tracking: bool = True) -> Optional[str]:
    if not raw:
        return None
    value = clean_candidate_url(raw)
    if not value or value.startswith("#"):
        return None
    lowered = value.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "about:", "chrome:")):
        return None
    if "{{" in value or "}}" in value or "${" in value or "<%" in value:
        return None
    if any(ch.isspace() for ch in value):
        return None
    if value.startswith("//"):
        value = "https:" + value
    elif base_url:
        value = urljoin(base_url, value)
    value, _ = urldefrag(value)
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return None
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    port = parsed.port
    netloc = hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    path = parsed.path or "/"
    query = parsed.query
    if strip_tracking and query:
        kept = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True)
                if k.lower() not in TRACKING_QUERY_KEYS]
        query = urlencode(kept, doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def is_target_domain(url: str, target_kw: Iterable[str] = DEFAULT_TARGET_KW) -> bool:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return False
        parts = host.split(".")
        for raw_kw in target_kw:
            kw = raw_kw.lower().strip(".")
            if not kw:
                continue
            if "." in kw:
                if host == kw or host.endswith("." + kw):
                    return True
            elif kw in parts:
                return True
        return False
    except Exception:
        return False


def is_test_env(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return any(kw in host for kw in ("test-env", "test-integ", "dev-integ"))
    except Exception:
        return False


def should_skip_by_extension(url: str, config: CrawlerConfig) -> bool:
    path = urlparse(url).path.lower()
    suffix = Path(path).suffix
    if suffix == ".css":
        return not config.include_css
    if suffix == ".json":
        return not config.include_json
    return suffix in STATIC_EXTENSIONS


def guess_extension(url: str, content_type: str, kind: str) -> str:
    path_suffix = Path(urlparse(url).path.lower()).suffix
    if path_suffix in {".html", ".htm", ".js", ".mjs", ".css", ".json", ".txt"}:
        return ".html" if path_suffix == ".htm" else path_suffix
    ct = content_type.lower()
    if kind == "html" or "html" in ct:
        return ".html"
    if kind == "js" or "javascript" in ct or "ecmascript" in ct:
        return ".js"
    if kind == "css" or "css" in ct:
        return ".css"
    if kind == "json" or "json" in ct:
        return ".json"
    return ".txt"


def sanitize_filename(value: str, max_len: int = 110) -> str:
    value = value.replace("/", "_").replace("\\", "_").strip("._ ")
    value = re.sub(r'[<>:"|?*\x00-\x1f]', "_", value)
    value = re.sub(r"_+", "_", value)
    if not value:
        value = "index"
    return value[:max_len].rstrip("._ ") or "index"


def safe_path(url: str, content_type: str, kind: str, config: CrawlerConfig) -> Path:
    parsed = urlparse(url)
    host = parsed.netloc.lower().replace(":", "_")
    domain_dir = config.outdir / sanitize_filename(host, max_len=160)
    raw_path = parsed.path.strip("/") or "index"
    suffix = guess_extension(url, content_type, kind)
    stem = sanitize_filename(raw_path, max_len=110)
    if stem.lower().endswith(suffix):
        stem = stem[:-len(suffix)]
    url_hash = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    filename = f"{stem}__{url_hash}{suffix}"
    path = domain_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    resolved_out = config.outdir.resolve()
    resolved_path = path.resolve()
    if resolved_out not in resolved_path.parents and resolved_path != resolved_out:
        raise ValueError(f"Unsafe output path: {resolved_path}")
    return path


def parse_charset(content_type: str) -> Optional[str]:
    match = re.search(r"charset\s*=\s*([^\s;]+)", content_type, re.IGNORECASE)
    if match:
        return match.group(1).strip("\"'")
    return None


def decode_text(content: bytes, content_type: str) -> str:
    candidates: list[str] = []
    charset = parse_charset(content_type)
    if charset:
        candidates.append(charset)
    candidates.extend(["utf-8-sig", "utf-8", "gb18030", "big5", "latin-1"])
    tried: set[str] = set()
    for encoding in candidates:
        normalized = encoding.lower()
        if normalized in tried:
            continue
        tried.add(normalized)
        try:
            return content.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return content.decode("utf-8", errors="replace")


def detect_kind(url: str, content_type: str, text: str, config: CrawlerConfig) -> str:
    ct = content_type.lower()
    path = urlparse(url).path.lower()
    head = text[:500].lstrip().lower()
    if "html" in ct or head.startswith("<!doctype") or head.startswith("<html") or "<html" in head[:200]:
        return "html"
    if "javascript" in ct or "ecmascript" in ct or path.endswith((".js", ".mjs")):
        return "js"
    if ("css" in ct or path.endswith(".css")) and config.include_css:
        return "css"
    if ("json" in ct or path.endswith(".json")) and config.include_json:
        return "json"
    if ct.startswith("text/"):
        js_signals = ("function ", "=>", "const ", "let ", "var ", "import ", "export ",
                       "__webpack_require__")
        if any(signal in text[:3000] for signal in js_signals):
            return "js"
    return "other"


# ── Link extraction ──────────────────────────────────────────────

class LinkHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: set[str] = set()
        self.base_href: str = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_map = {name.lower(): value for name, value in attrs if value}
        if tag.lower() == "base" and attr_map.get("href") and not self.base_href:
            self.base_href = attr_map["href"] or ""
        for key in ("href", "src", "action", "data-url", "data-api", "data-href",
                     "data-main", "data-src", "data-original", "poster"):
            value = attr_map.get(key)
            if value:
                self.links.add(value)
        srcset = attr_map.get("srcset")
        if srcset:
            for item in srcset.split(","):
                candidate = item.strip().split(" ")[0]
                if candidate:
                    self.links.add(candidate)
        content_attr = attr_map.get("content")
        if tag.lower() == "meta" and content_attr and "url=" in content_attr.lower():
            _, _, target = content_attr.partition("=")
            if target:
                self.links.add(target.strip())


def require_module_to_url(module_id: str) -> Optional[str]:
    module_id = clean_candidate_url(module_id)
    if not module_id:
        return None
    if module_id in {"require", "exports", "module"}:
        return None
    if "!" in module_id:
        module_id = module_id.rsplit("!", 1)[-1]
    if re.search(r"\.(?:js|css|html|json)(?:[?#].*)?$", module_id, re.IGNORECASE):
        return module_id
    if re.search(r"\.(?:png|jpe?g|gif|webp|svg|ico|mp4|mp3|woff2?|ttf|eot)(?:[?#].*)?$",
                 module_id, re.IGNORECASE):
        return module_id
    return module_id + ".js"


def extract_requirejs_links(text: str) -> set[str]:
    links: set[str] = set()
    for match in REQUIRE_ARRAY_RE.finditer(text):
        deps = match.group("deps")
        for string_match in JS_STRING_RE.finditer(deps):
            candidate = require_module_to_url(string_match.group("value"))
            if candidate:
                links.add(candidate)
    for match in REQUIRE_CONFIG_PATHS_RE.finditer(text):
        body = match.group("body")
        paths_match = re.search(r"""paths\s*:\s*\{(?P<paths>.{1,8000})\}""",
                                body, re.IGNORECASE | re.DOTALL)
        if paths_match:
            for value in re.findall(r"""["'][\w./-]+["']\s*:\s*["']([^"']+)["']""",
                                    paths_match.group("paths")):
                candidate = require_module_to_url(value)
                if candidate:
                    links.add(candidate)
    return links


def parse_webpack_map_entries(raw: str) -> dict[str, str]:
    return {match.group("id"): match.group("value")
            for match in WEBPACK_MAP_ENTRY_RE.finditer(raw)}


def extract_webpack_runtime_links(text: str) -> set[str]:
    links: set[str] = set()
    for match in WEBPACK_CSS_CHUNK_RE.finditer(text):
        for chunk_id, chunk_hash in parse_webpack_map_entries(match.group("hashes")).items():
            links.add(f"/css/{chunk_id}-{chunk_hash}.css")
    for match in WEBPACK_JS_CHUNK_RE.finditer(text):
        names = parse_webpack_map_entries(match.group("names"))
        hashes = parse_webpack_map_entries(match.group("hashes"))
        for chunk_id, chunk_hash in hashes.items():
            chunk_name = names.get(chunk_id, chunk_id)
            links.add(f"/js/{chunk_name}-{chunk_hash}.js")
    return links


def template_url_to_stub(template_url: str) -> Optional[str]:
    prefix = template_url.split("${", 1)[0]
    prefix = prefix.rstrip(" ?&/#")
    if not prefix or prefix in {"http:", "https:"}:
        return None
    if not prefix.startswith(("/", "http://", "https://", "//")):
        return None
    if " " in prefix:
        prefix = prefix.split(" ", 1)[0]
    if len(prefix) < 2:
        return None
    return prefix


# Lightweight signals for triggering heavy regexes
def _has_requirejs_signal(text: str) -> bool:
    return bool(re.search(r'(?:requirejs|require)\.config\s*\(|(?:require|define)\s*\(\s*\[',
                          text[:5000], re.IGNORECASE))


def _has_webpack_signal(text: str) -> bool:
    return bool(re.search(r'webpackJsonp|\.e\s*=\s*function|["\']css/["\']\s*\+\s*e',
                         text[:5000]))


def _has_template_signal(text: str) -> bool:
    return "${" in text[:10000]


def _has_data_main_signal(text: str) -> bool:
    return "data-main" in text[:5000]


def _has_spa_signal(text: str) -> bool:
    head = text[:10000]
    return bool(re.search(r'(?:router|navigateTo|redirectTo|linkTo)\s*\(', head))


def extract_links(text: str, base_url: str, kind: str = "html") -> set[str]:
    """Extract links from HTML/JS/CSS content. Heavy regexes only run when signals present."""
    candidates: set[str] = set()
    effective_base = base_url

    if kind == "html":
        parser = LinkHTMLParser()
        try:
            parser.feed(text)
            candidates.update(parser.links)
            if parser.base_href:
                normalized_base = normalize_url(parser.base_href, base_url=base_url)
                if normalized_base:
                    effective_base = normalized_base
        except Exception:
            pass
        # Signal-triggered: only run if data-main attribute present
        if _has_data_main_signal(text):
            for match in DATA_MAIN_RE.finditer(text):
                candidates.add(match.group("url"))

    # Light regexes (always run — cheap)
    for regex in (ABS_URL_RE, JS_CALL_RE, JS_IMPORT_RE, JS_OBJECT_URL_RE, QUOTED_PATH_RE):
        for match in regex.finditer(text):
            candidates.add(match.group("url"))

    for match in JS_NAVIGATION_RE.finditer(text):
        candidates.add(match.group("assign") or match.group("call") or "")

    # Signal-triggered heavy regexes
    if _has_template_signal(text):
        for match in JS_TEMPLATE_URL_RE.finditer(text):
            stub = template_url_to_stub(match.group("url"))
            if stub:
                candidates.add(stub)

    if _has_requirejs_signal(text):
        candidates.update(extract_requirejs_links(text))

    if _has_webpack_signal(text):
        candidates.update(extract_webpack_runtime_links(text))

    # New: SPA route patterns (signal-triggered)
    if _has_spa_signal(text):
        for regex in (SPA_ROUTER_PUSH_RE, SPA_LINK_TO_RE):
            for match in regex.finditer(text):
                route = match.group("path")
                if route and not route.startswith(("http:", "https:", "//")):
                    candidates.add(route)
        for match in SPA_HASH_ROUTE_RE.finditer(text):
            candidates.add("#" + match.group("hash"))

    if kind == "css":
        for match in CSS_URL_RE.finditer(text):
            candidates.add(match.group("url"))

    resolved: set[str] = set()
    for candidate in candidates:
        normalized = normalize_url(candidate, base_url=effective_base)
        if normalized:
            resolved.add(normalized)
        if effective_base != base_url and clean_candidate_url(candidate).startswith("/"):
            original_base_normalized = normalize_url(candidate, base_url=base_url)
            if original_base_normalized:
                resolved.add(original_base_normalized)
    return resolved


# ── HTTP client ───────────────────────────────────────────────────

# Per-thread HTTP sessions for connection reuse
_tls = threading.local()

def _get_session():
    if curl_requests is None:
        return None
    if not hasattr(_tls, 'session'):
        _tls.session = curl_requests.Session()
        _tls.session.headers.update({"User-Agent": USER_AGENT})
    return _tls.session


def http_get(url: str, timeout: float, headers: dict[str, str],
             max_size: int = 0, stream: bool = False) -> FetchResponse:
    """HTTP GET with optional streaming and size limit."""
    if curl_requests is not None:
        session = _get_session()
        resp = session.get(url, impersonate="chrome120", timeout=timeout,
                          headers=headers, stream=stream)
        if stream and max_size > 0:
            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192):
                chunks.append(chunk)
                total += len(chunk)
                if total > max_size:
                    resp.close()
                    return FetchResponse(
                        status_code=resp.status_code,
                        headers={str(k): str(v) for k, v in resp.headers.items()},
                        content=b"".join(chunks)[:max_size + 1],
                    )
            content = b"".join(chunks)
        else:
            content = resp.content
        return FetchResponse(
            status_code=resp.status_code,
            headers={str(k): str(v) for k, v in resp.headers.items()},
            content=content,
        )

    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return FetchResponse(
                status_code=response.getcode(),
                headers={str(k): str(v) for k, v in response.headers.items()},
                content=response.read(),
            )
    except HTTPError as exc:
        return FetchResponse(
            status_code=exc.code,
            headers={str(k): str(v) for k, v in exc.headers.items()},
            content=exc.read(),
        )


def should_skip_by_headers(content_type: str, content_length: str, max_size: int) -> tuple[bool, str]:
    """Quick pre-filter: check if we can skip without downloading body."""
    ct_lower = content_type.lower()

    # Check Content-Type
    for skip_ct in SKIP_CONTENT_TYPES:
        if ct_lower.startswith(skip_ct):
            return True, f"skip_by_ct:{ct_lower}"

    # Check Content-Length
    if content_length:
        try:
            cl = int(content_length)
            if cl < 20:
                return True, "too_small_by_cl"
            if cl > max_size:
                return True, "too_large_by_cl"
        except ValueError:
            pass

    return False, ""


# ── Sitemap / robots.txt discovery ────────────────────────────────

def fetch_robots_sitemaps(domain_root: str, timeout: float) -> list[str]:
    """Fetch robots.txt and extract Sitemap URLs."""
    robots_url = domain_root.rstrip("/") + "/robots.txt"
    try:
        resp = http_get(robots_url, timeout=timeout,
                       headers={"User-Agent": USER_AGENT}, max_size=500_000)
        if resp.status_code == 200:
            sitemaps = re.findall(r'^Sitemap:\s*(\S+)', resp.content.decode('utf-8', errors='ignore'),
                                  re.IGNORECASE | re.MULTILINE)
            return sitemaps
    except Exception:
        pass
    return []


def parse_sitemap_urls(sitemap_url: str, timeout: float) -> set[str]:
    """Fetch sitemap XML and extract <loc> URLs."""
    urls: set[str] = set()
    try:
        resp = http_get(sitemap_url, timeout=timeout,
                       headers={"User-Agent": USER_AGENT}, max_size=5_000_000)
        if resp.status_code != 200:
            return urls
        text = resp.content.decode('utf-8', errors='ignore')
        urls.update(SITEMAP_LOC_RE.findall(text))
        # Handle sitemap index (nested sitemaps)
        if '<sitemapindex' in text.lower():
            for nested in SITEMAP_LOC_RE.findall(text):
                urls.update(parse_sitemap_urls(nested, timeout))
    except Exception:
        pass
    return urls


def discover_sitemap_seeds(domain_roots: list[str], timeout: float) -> set[str]:
    """Discover HTML/JS seeds from robots.txt + sitemap.xml."""
    seeds: set[str] = set()
    for root in domain_roots:
        sitemaps = fetch_robots_sitemaps(root, timeout)
        # Also try default sitemap location
        default_sitemap = root.rstrip("/") + "/sitemap.xml"
        all_sitemaps = set(sitemaps)
        all_sitemaps.add(default_sitemap)
        for sitemap_url in all_sitemaps:
            urls = parse_sitemap_urls(sitemap_url, timeout)
            # Only keep HTML/no-extension pages (not images, PDFs, etc.)
            for url in urls:
                path = urlparse(url).path.lower()
                if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
                    continue
                seeds.add(url)
    return seeds


# ── Main crawler class ────────────────────────────────────────────

class RemoteSiteCrawler:
    def __init__(self, config: CrawlerConfig) -> None:
        self.config = config
        self.config.outdir.mkdir(parents=True, exist_ok=True)

        self.pending: dict[str, tuple[int, str]] = {}
        self.known_urls: set[str] = set()
        self.content_hashes: set[str] = set()
        # Fix: use (hash, host) to avoid missing relative links from same content on different hosts
        self.parsed_keys: set[tuple[str, str]] = set()
        self.stats: Counter[str] = Counter()
        self.fail_stats: Counter[str] = Counter()  # categorized failure stats
        self.failed_results: list[CrawlResult] = []
        self.links_file: Optional[object] = None  # links.jsonl file handle
        self.lock = threading.Lock()

        # Long-lived thread pool (created once, reused across batches)
        self._executor: Optional[ThreadPoolExecutor] = None
        self._render_queue: list[str] = []  # SPA pages found during crawl for later rendering

    def log(self, message: str) -> None:
        print(message, flush=True)

    # ── URL management ──────────────────────────────────────────

    def add_url(self, raw_url: str, depth: int = 0, source_url: str = "",
                reason: str = "") -> bool:
        url = normalize_url(raw_url)
        if not url:
            return False
        if not is_target_domain(url, self.config.target_kw):
            return False
        if is_test_env(url) or should_skip_by_extension(url, self.config):
            return False
        if self.config.max_depth > 0 and depth > self.config.max_depth:
            return False
        if self.config.max_urls > 0 and len(self.known_urls) >= self.config.max_urls:
            return False
        if url in self.known_urls:
            return False

        self.known_urls.add(url)
        self.pending[url] = (depth, source_url)

        # Log discovered link
        if self.links_file is not None:
            entry = {"source_url": source_url, "discovered_url": url,
                     "reason": reason, "depth": depth}
            self.links_file.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return True

    # ── Persistence ──────────────────────────────────────────────

    def save_frontier(self) -> None:
        """Save pending queue to frontier.jsonl for crash recovery."""
        if not self.pending:
            return
        with open(self.config.frontier_path, "w", encoding="utf-8") as f:
            for url, (depth, source) in self.pending.items():
                f.write(json.dumps({"url": url, "depth": depth, "source_url": source},
                                   ensure_ascii=False) + "\n")

    def load_frontier(self) -> int:
        """Load pending queue from frontier.jsonl."""
        fp = self.config.frontier_path
        if not fp.exists():
            return 0
        loaded = 0
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if self.add_url(rec["url"], depth=rec.get("depth", 0),
                                    source_url=rec.get("source_url", "frontier"),
                                    reason="frontier-resume"):
                        loaded += 1
                except (json.JSONDecodeError, KeyError):
                    continue
        # Remove after loading so we don't double-load on next run if clean exit
        fp.unlink(missing_ok=True)
        return loaded

    def load_manifest(self) -> int:
        manifest = self.config.manifest_path
        if not manifest.exists():
            return 0

        loaded = 0
        retry_candidates: list[tuple[str, int, str]] = []
        parse_candidates: list[tuple[str, int, Path]] = []
        with manifest.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                url = record.get("url")
                status = record.get("status")
                depth = int(record.get("depth", 0) or 0)
                if url and self.config.retry_failed and status in {"fail", "too_large",
                                                                     "too_small"}:
                    retry_candidates.append((url, depth,
                                             record.get("source_url", "manifest-retry")))
                elif url:
                    self.known_urls.add(url)
                if record.get("hash"):
                    self.content_hashes.add(record["hash"])
                    # Reconstruct parsed_keys from host in URL
                    try:
                        host = urlparse(url).hostname or ""
                        self.parsed_keys.add((record["hash"], host))
                    except Exception:
                        pass
                if status:
                    self.stats[f"previous_{status}"] += 1
                loaded += 1

                if (self.config.resume_parse_existing and status in {"ok", "dup"}
                        and record.get("path") and url):
                    path = Path(record["path"])
                    if path.exists():
                        parse_candidates.append((url, depth, path))

        retried = 0
        for url, depth, source_url in retry_candidates:
            if self.add_url(url, depth=depth, source_url=source_url,
                           reason="manifest-retry"):
                retried += 1

        added = 0
        for url, depth, path in parse_candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            suffix = path.suffix.lower()
            if suffix == ".json" and not self.config.parse_json_links:
                continue
            if suffix == ".css" and not self.config.include_css:
                continue
            kind = "html" if suffix == ".html" else ("css" if suffix == ".css"
                       else "json" if suffix == ".json" else "js")
            for link in extract_links(text, url, kind=kind):
                if self.add_url(link, depth + 1, source_url=url, reason="resume-parse"):
                    added += 1

        if retried:
            self.log(f"  Resume: rescheduled {retried} failed URLs")
        if added:
            self.log(f"  Resume: requeued {added} follow-up URLs from saved files")
        return loaded

    def load_existing_hashes_without_manifest(self) -> int:
        if self.config.manifest_path.exists():
            return 0
        existing = 0
        for path in self.config.outdir.rglob("*"):
            if not path.is_file() or path.name in {"failed_urls.txt", "frontier.jsonl",
                                                     "links.jsonl"}:
                continue
            try:
                content = path.read_bytes()
            except OSError:
                continue
            h = hashlib.sha256(content).hexdigest()
            self.content_hashes.add(h)
            # Build parsed_key from directory name (domain)
            try:
                domain = path.relative_to(self.config.outdir).parts[0]
                self.parsed_keys.add((h, domain))
            except Exception:
                pass
            existing += 1
        return existing

    def append_manifest(self, result: CrawlResult) -> None:
        record = {
            "time": utc_now(),
            "url": result.url,
            "source_url": result.source_url,
            "depth": result.depth,
            "status": result.status,
            "http_status": result.http_status,
            "content_type": result.content_type,
            "kind": result.kind,
            "bytes": result.byte_count,
            "hash": result.content_hash,
            "path": result.path,
            "discovered": len(result.discovered),
            "error": result.error,
            "elapsed": round(result.elapsed, 3),
            "attempts": result.attempts,
        }
        with self.config.manifest_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def write_failed_urls(self) -> None:
        if not self.failed_results:
            if self.config.failed_path.exists():
                self.config.failed_path.unlink()
            return
        with self.config.failed_path.open("w", encoding="utf-8") as fh:
            fh.write("# url\thttp_status\terror_type\terror_detail\n")
            for result in self.failed_results:
                reason = result.error or result.status
                error_type = result.error.split(":")[0] if ":" in result.error else result.error
                fh.write(f"{result.url}\t{result.http_status or ''}\t{error_type}\t{reason}\n")

    def print_failure_summary(self) -> None:
        """Print aggregated failure statistics."""
        if not self.fail_stats:
            return
        self.log("\n  Failure reasons:")
        for reason, count in self.fail_stats.most_common(20):
            self.log(f"    {reason}: {count}")

    # ── Seed discovery ───────────────────────────────────────────

    def scan_local_seed_urls(self) -> int:
        found = 0
        root = self.config.root
        outdir_name = self.config.outdir.name
        skip_dirs = set(self.config.skip_dirs)
        skip_dirs.add(outdir_name)
        for current_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                path = Path(current_root) / fname
                try:
                    content = path.read_bytes()[:2_000_000]
                except OSError:
                    continue
                for match in URL_RE.finditer(content):
                    raw = match.group(0).decode("utf-8", errors="replace")
                    if self.add_url(raw, depth=0, source_url=str(path),
                                    reason="local-scan"):
                        found += 1
        return found

    def add_domain_roots(self) -> int:
        roots = set()
        for url in list(self.pending):
            parsed = urlparse(url)
            roots.add(f"{parsed.scheme}://{parsed.netloc}/")
        added = 0
        for root_url in sorted(roots):
            if self.add_url(root_url, depth=0, source_url="domain-root",
                           reason="domain-root"):
                added += 1
        return added

    def add_extra_seeds(self) -> int:
        if self.config.no_extra_seeds:
            return 0
        added = 0
        for url in self.config.extra_seeds:
            if self.add_url(url, depth=0, source_url="default-extra",
                           reason="extra-seed"):
                added += 1
        return added

    def add_sitemap_seeds(self) -> int:
        """Discover seeds from robots.txt and sitemap.xml."""
        roots = set()
        for url in list(self.pending):
            parsed = urlparse(url)
            roots.add(f"{parsed.scheme}://{parsed.netloc}/")
        seeds = discover_sitemap_seeds(list(roots), self.config.timeout)
        added = 0
        for seed in seeds:
            if self.add_url(seed, depth=0, source_url="sitemap", reason="sitemap"):
                added += 1
        if added:
            self.log(f"  sitemap/robots discovered: {added} seeds")
        return added

    def add_seed_file(self, seed_file: Path) -> int:
        added = 0
        try:
            lines = seed_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            self.log(f"[!] Failed to read seed file {seed_file}: {exc}")
            return 0
        for line in lines:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if self.add_url(value, depth=0, source_url=str(seed_file),
                           reason="seed-file"):
                added += 1
        return added

    # ── Playwright rendering ─────────────────────────────────────

    @staticmethod
    def _is_likely_html(url: str) -> bool:
        """Return whether a URL is likely an HTML/SPA page worth Playwright rendering."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        api_patterns = (
            '/v1/', '/v2/', '/v3/', '/v4/', '/v5/',
            '/api/', '/rest/', '/graphql',
            'service/', 'service/v',
            'jeecg-boot', 'actuator', 'druid',
            'webadapt', 'appadapt', 'adaptservice',
            'streamservice', 'storeservice',
        )
        for p in api_patterns:
            if p in url.lower():
                return False
        static_exts = (
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svg',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.css', '.less', '.scss',
            '.js', '.mjs', '.map',
            '.mp3', '.mp4', '.webm', '.ogg', '.wav', '.avi', '.mov', '.flv',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.json', '.xml',
        )
        if any(path.endswith(ext) for ext in static_exts):
            return False
        if '/download/' in url.lower():
            return False
        if path.endswith(('.html', '.htm')):
            return True
        last_seg = path.rstrip('/').split('/')[-1]
        if '.' not in last_seg:
            return True
        if parsed.query and '.' not in last_seg:
            return True
        return False

    def _render_urls(self, seeds: list[str], label: str = "") -> int:
        """Render a list of URLs with Playwright and collect network requests."""
        if not self.config.render:
            return 0
        seed_list = [s for s in seeds if self._is_likely_html(s)]
        skipped = len(seeds) - len(seed_list)
        if not seed_list:
            return 0

        label_str = f" ({label})" if label else ""
        self.log(f"  Playwright rendering {len(seed_list)} pages{label_str}"
                 f" (skipped {skipped} non-HTML URLs)...")

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.log("[!] --render requires playwright; skipped.")
            return 0

        collected: set[str] = set()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            total = len(seed_list)
            for idx, seed in enumerate(seed_list):
                # Create context with proper cookie domain
                parsed = urlparse(seed)
                origin = f"{parsed.scheme}://{parsed.netloc}"
                context = browser.new_context(
                    user_agent=USER_AGENT,
                    ignore_https_errors=True,
                )
                # Fix: inject cookies with correct origin
                if self.config.cookies:
                    pw_cookies = []
                    for c in self.config.cookies.split(";"):
                        c = c.strip()
                        if "=" in c:
                            name, val = c.split("=", 1)
                            pw_cookies.append({
                                "name": name.strip(),
                                "value": val.strip(),
                                "domain": parsed.hostname or "",
                                "path": "/",
                            })
                    if pw_cookies:
                        context.add_cookies(pw_cookies)

                # Fix: Authorization via extra_http_headers (not per-route)
                if self.config.authorization:
                    context.set_extra_http_headers({
                        "Authorization": self.config.authorization,
                    })

                page = context.new_page()
                page.on("request", lambda request: collected.add(request.url))
                page.on("response", lambda response: collected.add(response.url))

                start = time.monotonic()
                try:
                    page.goto(seed, wait_until="networkidle",
                             timeout=int(self.config.render_timeout * 1000))
                    elapsed = time.monotonic() - start
                    self.log(f"    [{idx+1}/{total}] OK {seed[:80]} "
                             f"({elapsed:.1f}s, {len(collected)} URLs)")
                except Exception as exc:
                    elapsed = time.monotonic() - start
                    self.log(f"    [{idx+1}/{total}] FAIL {seed[:80]} "
                             f"({elapsed:.1f}s) {type(exc).__name__}")
                finally:
                    page.close()
                    context.close()
            browser.close()

        added = 0
        for url in collected:
            if self.add_url(url, depth=1, source_url="playwright", reason="playwright"):
                added += 1
        return added

    def collect_rendered_urls(self, seeds: Iterable[str]) -> int:
        return self._render_urls(list(seeds), label="initial seeds")

    # ── Download & process ───────────────────────────────────────

    def fetch_with_retries(self, url: str) -> tuple[Optional[FetchResponse], int, str, float]:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": ("text/html,application/xhtml+xml,application/javascript,"
                       "text/javascript,text/css,application/json,*/*"),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        if self.config.cookies:
            headers["Cookie"] = self.config.cookies
        if self.config.authorization:
            headers["Authorization"] = self.config.authorization

        attempts = max(1, self.config.retries + 1)
        last_error = ""
        started = time.monotonic()

        for attempt in range(1, attempts + 1):
            if self.config.delay > 0:
                time.sleep(self.config.delay)
            try:
                response = http_get(url, timeout=self.config.timeout, headers=headers)
                if response.status_code not in RETRYABLE_STATUS or attempt == attempts:
                    return response, attempt, "", time.monotonic() - started
                last_error = f"HTTP {response.status_code}"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt == attempts:
                    return None, attempt, last_error, time.monotonic() - started
            sleep_for = self.config.retry_backoff * (2 ** (attempt - 1))
            if sleep_for > 0:
                time.sleep(sleep_for + random.uniform(0, sleep_for * 0.1))

        return None, attempts, last_error, time.monotonic() - started

    def download(self, url: str, depth: int, source_url: str) -> CrawlResult:
        response, attempts, error, elapsed = self.fetch_with_retries(url)
        result = CrawlResult(url=url, depth=depth, source_url=source_url,
                            status="fail", attempts=attempts, elapsed=elapsed)

        if response is None:
            result.error = error or "request failed"
            return result

        result.http_status = response.status_code
        result.content_type = response.headers.get("Content-Type",
                            response.headers.get("content-type", ""))
        result.byte_count = len(response.content)

        if response.status_code != 200:
            result.error = f"HTTP {response.status_code}"
            return result

        # Header pre-filter: skip before text decode if possible
        content_length_hdr = response.headers.get("Content-Length",
                             response.headers.get("content-length", ""))

        if result.byte_count < 20:
            result.status = "too_small"
            result.error = f"content too small: {result.byte_count} bytes"
            return result

        if result.byte_count > self.config.max_size:
            result.status = "too_large"
            result.error = f"content too large: {result.byte_count} bytes"
            return result

        text = decode_text(response.content, result.content_type)
        kind = detect_kind(url, result.content_type, text, self.config)
        result.kind = kind

        # Mode-based filtering
        if kind == "other":
            result.status = "not_target"
            return result

        if self.config.mode == "pages":
            if kind not in ("html", "js", "css"):
                result.status = "not_target"
                return result
        elif self.config.mode == "api":
            # API mode: skip HTML pages, keep JSON/JS (which may contain API defs)
            if kind == "html":
                result.status = "not_target"
                return result

        result.content_hash = hashlib.sha256(response.content).hexdigest()

        # Fix: parsed_keys uses (hash, host) to avoid missing relative links
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
        parse_key = (result.content_hash, host)

        duplicate = False
        already_parsed = False
        with self.lock:
            if result.content_hash in self.content_hashes:
                duplicate = True
                already_parsed = parse_key in self.parsed_keys
            else:
                self.content_hashes.add(result.content_hash)

        # Extract links (skip if already parsed from same host)
        if (kind != "json" or self.config.parse_json_links) and not already_parsed:
            result.discovered = extract_links(text, url, kind=kind)
            with self.lock:
                self.parsed_keys.add(parse_key)

        if duplicate:
            result.status = "dup"
            return result

        path = safe_path(url, result.content_type, kind, self.config)
        path.write_text(text, encoding="utf-8", errors="ignore")
        result.path = str(path.resolve())
        result.status = "ok"
        return result

    # ── BFS crawl ─────────────────────────────────────────────────

    def take_batch(self) -> dict[str, tuple[int, str]]:
        batch: dict[str, tuple[int, str]] = {}
        for url in list(self.pending):
            depth, source = self.pending.pop(url)
            if self.config.max_depth > 0 and depth > self.config.max_depth:
                self.stats["depth_skipped"] += 1
                continue
            batch[url] = (depth, source)
            if len(batch) >= self.config.effective_batch_size:
                break
        return batch

    def process_result(self, result: CrawlResult) -> int:
        self.stats[result.status] += 1
        self.append_manifest(result)

        if result.failed:
            self.failed_results.append(result)
            # Categorized failure tracking
            if result.error:
                if result.error.startswith("HTTP "):
                    self.fail_stats[f"HTTP {result.http_status}"] += 1
                elif ":" in result.error:
                    self.fail_stats[result.error.split(":")[0]] += 1
                else:
                    self.fail_stats[result.error] += 1
            else:
                self.fail_stats[result.status] += 1

        added = 0
        for link in result.discovered:
            reason = f"extracted-from-{result.kind}"
            if self.add_url(link, depth=result.depth + 1, source_url=result.url,
                           reason=reason):
                added += 1
        return added

    def crawl(self) -> None:
        round_num = 0
        total_found = 0
        render_round = 0

        # Create long-lived executor (reused across batches)
        self._executor = ThreadPoolExecutor(max_workers=self.config.threads)

        try:
            while self.pending:
                batch = self.take_batch()
                if not batch:
                    break

                round_num += 1
                depths = [depth for depth, _ in batch.values()]
                self.log(
                    f"\n  Round {round_num}: {len(batch)} URLs "
                    f"(depth={min(depths)}-{max(depths)}, queue={len(self.pending)}) "
                    f"OK={self.stats['ok']} DUP={self.stats['dup']} FAIL={self.stats['fail']}"
                )

                round_new = 0
                futures = {
                    self._executor.submit(self.download, url, depth, source): url
                    for url, (depth, source) in batch.items()
                }
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = CrawlResult(url=url, depth=batch[url][0],
                                            source_url=batch[url][1], status="fail")
                        result.error = f"worker error: {type(exc).__name__}: {exc}"
                    round_new += self.process_result(result)

                    # Save frontier every 10 completed URLs for crash recovery
                    if round_new % 10 == 0 and self.pending:
                        self.save_frontier()

                total_found += round_new
                self.log(f"    -> added {round_new} URLs, cumulative discoveries {total_found}")

                # Render-depth: queue newly found SPA pages for rendering
                if (self.config.render and self.config.render_depth > 0
                        and render_round < self.config.render_depth):
                    new_spa = [url for url in self.pending
                              if self._is_likely_html(url)
                              and url not in self._render_queue]
                    if new_spa:
                        self._render_queue.extend(new_spa)
                        render_count = self._render_urls(
                            new_spa, label=f"SPA render round {render_round+1}")
                        render_round += 1
                        if render_count:
                            self.log(f"    render captured: {render_count} new URLs")

        finally:
            if self._executor:
                self._executor.shutdown(wait=True)

        # Clean frontier on clean exit
        if self.config.frontier_path.exists():
            self.config.frontier_path.unlink(missing_ok=True)

        self.write_failed_urls()
        self.print_summary(round_num, total_found)

    def print_summary(self, round_num: int, total_found: int) -> None:
        self.log("\n" + "=" * 60)
        self.log(f"Crawl complete: {round_num} rounds")
        self.log(f"  OK downloads:       {self.stats['ok']}")
        self.log(f"  Duplicate content:  {self.stats['dup']}")
        self.log(f"  Non-target type:    {self.stats['not_target']}")
        fail_total = (self.stats['fail'] + self.stats['too_large']
                     + self.stats['too_small'])
        self.log(f"  Failures:           {fail_total}")
        self.log(f"  Depth skipped:      {self.stats['depth_skipped']}")
        self.log(f"  New URLs:           {total_found}")

        self.print_failure_summary()

        total_files = 0
        domain_stats: defaultdict[str, Counter[str]] = defaultdict(Counter)
        for path in self.config.outdir.rglob("*"):
            if not path.is_file() or path.name in {"manifest.jsonl", "failed_urls.txt",
                                                     "frontier.jsonl", "links.jsonl"}:
                continue
            total_files += 1
            try:
                domain = path.relative_to(self.config.outdir).parts[0]
            except ValueError:
                domain = ""
            suffix = path.suffix.lower().lstrip(".") or "txt"
            domain_stats[domain][suffix] += 1

        self.log(f"  Output dir:         {self.config.outdir}")
        self.log(f"  manifest:     {self.config.manifest_path}")
        if self.failed_results:
            self.log(f"  Failure list:       {self.config.failed_path}")
        self.log(f"  Total files:        {total_files}")

        if domain_stats:
            self.log("\n  Stats by domain:")
            for domain in sorted(domain_stats):
                pieces = [f"{count} {suffix.upper()}"
                         for suffix, count in sorted(domain_stats[domain].items())]
                self.log(f"    {domain}: " + " + ".join(pieces))


# ── CLI ────────────────────────────────────────────────────────────

def parse_target_keywords(values: list[str]) -> set[str]:
    if not values:
        return set(DEFAULT_TARGET_KW)
    result: set[str] = set()
    for value in values:
        for item in value.split(","):
            item = item.strip().lower()
            if item:
                result.add(item)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recursive crawler v2 - download HTML/JS/SPA resources for target domains")
    parser.add_argument("--config", "-c", default=str(DEFAULT_CONFIG_PATH),
                        help="Rule config JSON; pass config/default.json or a config name")
    parser.add_argument("--threads", "-t", type=int, default=10, help="Thread count, default 10")
    parser.add_argument("--depth", "-d", type=int, default=0, help="Maximum recursion depth, 0 means unlimited")
    parser.add_argument("--out", "-o", default="remote_sites", help="Output directory")
    parser.add_argument("--root", default=".", help="Root directory for local seed URL scanning")
    parser.add_argument("--max-size", type=float, default=5.0, help="Maximum MB per response")
    parser.add_argument("--timeout", type=float, default=20.0, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=2, help="Retry count for failures")
    parser.add_argument("--retry-backoff", type=float, default=1.0, help="Retry backoff base seconds")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay before each request in seconds")
    parser.add_argument("--batch-size", type=int, default=0, help="Maximum URLs per batch")
    parser.add_argument("--max-urls", type=int, default=0, help="Maximum scheduled URLs, 0 means unlimited")
    parser.add_argument("--target", action="append", default=[], help="Target domain keyword, repeatable")
    parser.add_argument("--seed", action="append", default=[], help="Extra seed URL, repeatable")
    parser.add_argument("--seed-file", help="Extra seed URL file, one per line")
    parser.add_argument("--skip-dir", action="append", default=[], help="Directory name to skip, repeatable")
    parser.add_argument("--include-css", action="store_true", help="Download and parse CSS")
    parser.add_argument("--include-json", action="store_true", help="Save JSON responses")
    parser.add_argument("--parse-json-links", action="store_true", help="Extract URLs from JSON")
    parser.add_argument("--retry-failed", action="store_true", help="Retry failed URLs from manifest")
    parser.add_argument("--no-resume-parse", action="store_true", help="Do not resume links from saved files")
    parser.add_argument("--no-extra-seeds", action="store_true", help="Do not add configured extra seeds")
    parser.add_argument("--no-sitemap", action="store_true", help="Do not discover sitemap/robots seeds")
    parser.add_argument("--render", action="store_true", help="Render SPA pages with Playwright")
    parser.add_argument("--render-timeout", type=float, default=15.0, help="Playwright timeout seconds")
    parser.add_argument("--render-depth", type=int, default=0, help="Rerender rounds for discovered SPA pages, 0 means initial only")
    parser.add_argument("--cookie", default="", help="Cookie: key1=val1; key2=val2")
    parser.add_argument("--authorization", default="", help="Authorization: Bearer xxx")
    parser.add_argument("--mode", default="pages", choices=["pages", "api", "full"],
                       help="pages=HTML/JS only, api=JSON+JS, full=all (default pages)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose diagnostics")
    return parser


def build_config(args: argparse.Namespace) -> CrawlerConfig:
    tool_config = load_tool_config(args.config)
    config_targets = split_config_values(tool_config.get("target_keywords", []))
    config_extra_seeds = split_config_values(tool_config.get("extra_seeds", []))
    config_skip_dirs = set(split_config_values(tool_config.get("skip_dirs", [])))
    cli_targets = parse_target_keywords(args.target)
    target_kw = cli_targets or set(config_targets)

    config = CrawlerConfig(
        threads=max(1, args.threads),
        max_depth=max(0, args.depth),
        outdir=Path(args.out),
        root=Path(args.root),
        max_size=max(1, int(args.max_size * 1024 * 1024)),
        timeout=max(1.0, args.timeout),
        retries=max(0, args.retries),
        retry_backoff=max(0.0, args.retry_backoff),
        delay=max(0.0, args.delay),
        batch_size=max(0, args.batch_size),
        max_urls=max(0, args.max_urls),
        target_kw=target_kw,
        include_css=args.include_css,
        include_json=args.include_json,
        parse_json_links=args.parse_json_links,
        retry_failed=args.retry_failed,
        resume_parse_existing=not args.no_resume_parse,
        no_extra_seeds=args.no_extra_seeds,
        render=args.render,
        render_timeout=max(1.0, args.render_timeout),
        render_depth=max(0, args.render_depth),
        verbose=args.verbose,
        cookies=args.cookie,
        authorization=args.authorization,
        mode=args.mode,
        extra_seeds=config_extra_seeds,
    )
    if config_skip_dirs:
        config.skip_dirs.update(config_skip_dirs)
    config.skip_dirs.update(args.skip_dir)
    config.skip_dirs.add(config.outdir.name)
    return config


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = build_config(args)

    crawler = RemoteSiteCrawler(config)

    # Open links.jsonl for tracking discovered URLs
    crawler.links_file = open(config.links_path, "a", encoding="utf-8")

    try:
        print("STEP 0: Restore previous state...")
        manifest_records = crawler.load_manifest()
        frontier_loaded = crawler.load_frontier()
        existing_files = crawler.load_existing_hashes_without_manifest()
        if manifest_records:
            print(f"  manifest records: {manifest_records}")
        if frontier_loaded:
            print(f"  frontier restored: {frontier_loaded} pending URLs")
        if existing_files:
            print(f"  existing file hashes: {existing_files}")

        print("STEP 1: Extract seed URLs...")
        seed_count = crawler.scan_local_seed_urls()
        print(f"  local scanned seeds: {seed_count}")

        cli_seed_count = 0
        for seed in args.seed:
            if crawler.add_url(seed, depth=0, source_url="cli", reason="cli-seed"):
                cli_seed_count += 1
        if cli_seed_count:
            print(f"  CLI seeds:           {cli_seed_count}")

        if args.seed_file:
            file_seed_count = crawler.add_seed_file(Path(args.seed_file))
            print(f"  file seeds:          {file_seed_count}")

        root_count = crawler.add_domain_roots()
        extra_count = crawler.add_extra_seeds()
        print(f"  added roots:         {root_count}")
        print(f"  configured seeds:    {extra_count}")

        if not args.no_sitemap:
            sitemap_count = crawler.add_sitemap_seeds()
        else:
            sitemap_count = 0

        render_count = crawler.collect_rendered_urls(list(crawler.pending))
        if render_count:
            print(f"  render-captured seeds: {render_count}")

        print(f"  initial queue:       {len(crawler.pending)} URLs")
        print(f"  target keywords:     {', '.join(sorted(config.target_kw))}")

        print(f"\nSTEP 2: BFS recursive crawl (max_depth={config.max_depth or 'unlimited'}, "
              f"mode={config.mode})...")
        crawler.save_frontier()
        crawler.crawl()

    finally:
        if crawler.links_file:
            crawler.links_file.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
