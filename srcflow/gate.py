"""srcflow.gate - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from srcflow.constants import BANNED_TITLE_PATTERNS, GATE_PATTERNS, PLACEHOLDER_VALUES, POC_PATTERN, REPORT_URL_RE
from srcflow.io_helpers import append_metric
from srcflow.scope import parse_scope, url_in_scope
from srcflow.utils import eprint, target_dir

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

