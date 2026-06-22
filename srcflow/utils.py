"""srcflow.utils - extracted from ai_src.py"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from srcflow.constants import CONFIG_DIR, TARGETS_DIR

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



def parse_first_number(value: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", value)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None



def number_value(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (OverflowError, ValueError):
            return default
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default



def metric_display(value: object) -> str:
    if value in (None, "", -1):
        return "-"
    return str(value)



def display_command(parts: list[object]) -> str:
    return subprocess.list2cmdline([str(part) for part in parts])



def counter_dict(values: Counter) -> dict[str, int]:
    return {str(key): int(values[key]) for key in sorted(values)}



def row_time(row: dict[str, object] | None) -> str:
    return str(row.get("time", "")) if row else ""



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

