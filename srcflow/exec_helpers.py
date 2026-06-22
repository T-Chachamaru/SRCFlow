"""srcflow.exec_helpers - extracted from ai_src.py"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from srcflow.constants import ROOT, SECRET_ARG_NAMES, SECRET_HEADER_ARG_NAMES, SECRET_HEADER_NAMES, SECRET_HEADER_PREFIXES, TOOLS_DIR
from srcflow.utils import eprint

def redact_header_value(value: str) -> str:
    name, sep, header_value = value.partition(":")
    if sep and name.strip().lower() in SECRET_HEADER_NAMES:
        return f"{name.strip()}: REDACTED"
    return re.sub(r"(?i)\bBearer\s+\S+", "Bearer REDACTED", value)



def redact_cmd(cmd: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    redact_next_header = False
    for part in cmd:
        text = str(part)
        lower = text.lower()
        if redact_next:
            redacted.append("REDACTED")
            redact_next = False
            continue
        if redact_next_header:
            redacted.append(redact_header_value(text))
            redact_next_header = False
            continue
        if text.startswith("-") and "=" in text:
            flag_part, _, value_part = text.partition("=")
            flag_lower = flag_part.lower()
            if flag_lower in SECRET_ARG_NAMES:
                redacted.append(f"{flag_part}=REDACTED")
                continue
            if flag_lower in SECRET_HEADER_ARG_NAMES:
                redacted.append(f"{flag_part}={redact_header_value(value_part)}")
                continue
        if lower in SECRET_ARG_NAMES:
            redacted.append(text)
            redact_next = True
            continue
        if lower in SECRET_HEADER_ARG_NAMES:
            redacted.append(text)
            redact_next_header = True
            continue
        if any(lower.startswith(prefix) for prefix in SECRET_HEADER_PREFIXES):
            redacted.append(redact_header_value(text))
            continue
        redacted.append(re.sub(r"(?i)\bBearer\s+\S+", "Bearer REDACTED", text))
    return redacted



def run_cmd(cmd: list[str], cwd: Path = ROOT, timeout: float | None = None) -> int:
    print("+ " + subprocess.list2cmdline(redact_cmd(cmd)), flush=True)
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        eprint(f"Command timed out after {timeout}s: {subprocess.list2cmdline(redact_cmd(cmd))}")
        return 124
    return proc.returncode



def run_capture(cmd: list[str], cwd: Path = ROOT, timeout: float | None = None) -> tuple[int, str]:
    print("+ " + subprocess.list2cmdline(redact_cmd(cmd)), flush=True)
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        eprint(f"Command timed out after {timeout}s: {subprocess.list2cmdline(redact_cmd(cmd))}")
        return 124, str(output)
    return proc.returncode, proc.stdout



def local_tool(name: str) -> str:
    local_exe = TOOLS_DIR / "bin" / f"{name}.exe"
    local_cmd = TOOLS_DIR / "bin" / f"{name}.cmd"
    local_plain = TOOLS_DIR / "bin" / name
    if local_exe.exists():
        return str(local_exe)
    if local_cmd.exists():
        return str(local_cmd)
    if local_plain.exists():
        return str(local_plain)
    return shutil.which(name) or ""



def require_local_tool(name: str) -> str:
    path = local_tool(name)
    if not path:
        raise FileNotFoundError(f"{name} not found. Run scripts/install_tools.ps1 first.")
    return path



def find_tool_path(tool: str) -> str:
    local_exe = TOOLS_DIR / "bin" / f"{tool}.exe"
    local_cmd = TOOLS_DIR / "bin" / f"{tool}.cmd"
    local_plain = TOOLS_DIR / "bin" / tool
    if local_exe.exists():
        return str(local_exe)
    if local_cmd.exists():
        return str(local_cmd)
    if local_plain.exists():
        return str(local_plain)
    return shutil.which(tool) or ""

