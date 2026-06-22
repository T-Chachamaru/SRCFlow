"""srcflow.constants - extracted from ai_src.py"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent



TARGETS_DIR = ROOT / "targets"



TOOLS_DIR = ROOT / "tools"



CONFIG_DIR = ROOT / "config"



KNOWN_WRAPPERS = {"ffuf-safe", "gau-urls", "katana-crawl", "paramspider-urls"}



SECRET_ARG_NAMES = {"--cookie", "--authorization", "-b"}



SECRET_HEADER_ARG_NAMES = {"-H", "--header"}



SECRET_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token"}



SECRET_HEADER_PREFIXES = tuple(f"{name}:" for name in sorted(SECRET_HEADER_NAMES))



LINE_URL_RE = re.compile(r"https?://[^\s\"'`<>)\]]+", re.I)



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



PASSIVE_STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".webm", ".avi", ".mov", ".css",
}



TEST_STATUS_VALUES = {
    "confirmed": "confirmed",
    "rejected": "rejected",
    "needs-account": "needs account",
    "needs-more-context": "needs more context",
    "needs-normal-flow": "needs normal flow",
    "needs-param-source": "needs param source",
    "needs-precondition": "needs precondition",
    "out-of-scope": "out of scope",
}



FLOW_STATUS_VALUES = {
    "normal-flow-ok": "normal flow ok",
    "needs-normal-flow": "needs normal flow",
    "needs-param-source": "needs param source",
    "needs-precondition": "needs precondition",
    "variant-tested": "variant tested",
    "blocked": "blocked",
}



CONFIG_LIST_FIELDS = [
    "target_keywords", "extra_seeds", "skip_dirs", "third_party_domains",
    "skip_extensions", "api_prefixes", "api_path_regexes",
    "known_endpoints", "special_keywords", "garbage_substrings",
    "extract_patterns",
]



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



HOP_BY_HOP_HEADERS = {
    "accept-encoding", "connection", "content-length", "host", "http2-settings",
    "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding",
    "upgrade",
}

