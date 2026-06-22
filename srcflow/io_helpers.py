"""srcflow.io_helpers - extracted from ai_src.py"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from srcflow.utils import utc_now

def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")



def read_json_file(path: Path, default: object | None = None) -> object:
    if not path.exists():
        return {} if default is None else default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {} if default is None else default



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



def request_recipes_path(base: Path) -> Path:
    return base / "state" / "request_recipes.jsonl"



def flow_tests_path(base: Path) -> Path:
    return base / "state" / "flow_tests.jsonl"



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



def read_request_recipes(base: Path) -> list[dict[str, object]]:
    return read_jsonl(request_recipes_path(base))



def read_flow_tests(base: Path) -> list[dict[str, object]]:
    return read_jsonl(flow_tests_path(base))

