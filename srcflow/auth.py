"""srcflow.auth - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from srcflow.io_helpers import read_json_file, write_json
from srcflow.utils import ensure_target_dirs, eprint, target_dir, utc_now

def auth_store_path(base: Path) -> Path:
    return base / "auth.local.json"



def split_header_line(value: str) -> tuple[str, str] | None:
    name, sep, header_value = value.partition(":")
    if not sep or not name.strip():
        return None
    return name.strip(), header_value.strip()



def auth_header_lines(auth: dict[str, object]) -> list[str]:
    headers = auth.get("headers")
    if not isinstance(headers, dict):
        return []
    result = []
    for key, value in headers.items():
        if str(key).strip() and str(value).strip():
            result.append(f"{str(key).strip()}: {str(value).strip()}")
    return result



def header_name(value: str) -> str:
    name, _sep, _header_value = value.partition(":")
    return name.strip().lower()



def merge_header_lines(profile_headers: list[str], explicit_headers: list[str]) -> list[str]:
    explicit_names = {header_name(item) for item in explicit_headers if header_name(item)}
    merged = [item for item in profile_headers if header_name(item) and header_name(item) not in explicit_names]
    merged.extend(explicit_headers)
    return merged



def resolve_env_value(profile: dict[str, object], value_key: str, env_key: str) -> str:
    direct = profile.get(value_key)
    if direct:
        return str(direct)
    env_name = profile.get(env_key)
    if env_name:
        return os.environ.get(str(env_name), "")
    return ""



def load_auth_profile(base: Path, name: str) -> dict[str, object]:
    if not name:
        return {"name": "", "cookie": "", "authorization": "", "headers": {}}
    path = auth_store_path(base)
    if not path.exists():
        raise FileNotFoundError(f"auth profile file not found: {path}")
    raw = read_json_file(path, {})
    if not isinstance(raw, dict):
        raise ValueError(f"auth profile file must be a JSON object: {path}")
    profiles = raw.get("profiles", raw)
    if not isinstance(profiles, dict):
        raise ValueError(f"auth profile file must contain a profiles object: {path}")
    profile = profiles.get(name)
    if not isinstance(profile, dict):
        available = ", ".join(sorted(str(key) for key in profiles.keys())) or "-"
        raise KeyError(f"auth profile not found: {name} (available: {available})")

    cookie = resolve_env_value(profile, "cookie", "cookie_env")
    authorization = resolve_env_value(profile, "authorization", "authorization_env")
    headers: dict[str, str] = {}

    raw_headers = profile.get("headers", {})
    if isinstance(raw_headers, dict):
        for key, value in raw_headers.items():
            if isinstance(value, dict) and value.get("env"):
                resolved = os.environ.get(str(value.get("env")), "")
            else:
                resolved = str(value)
            if str(key).strip() and resolved:
                headers[str(key).strip()] = resolved
    elif isinstance(raw_headers, list):
        for item in raw_headers:
            parsed = split_header_line(str(item))
            if parsed:
                headers[parsed[0]] = parsed[1]

    raw_header_env = profile.get("headers_env", {})
    if isinstance(raw_header_env, dict):
        for key, env_name in raw_header_env.items():
            resolved = os.environ.get(str(env_name), "")
            if str(key).strip() and resolved:
                headers[str(key).strip()] = resolved

    if authorization and not any(key.lower() == "authorization" for key in headers):
        headers["Authorization"] = authorization
    if cookie and not any(key.lower() == "cookie" for key in headers):
        headers["Cookie"] = cookie
    return {
        "name": name,
        "role": profile.get("role", ""),
        "username": profile.get("username", ""),
        "password": profile.get("password", ""),
        "login_url": profile.get("login_url", ""),
        "tenant": profile.get("tenant", ""),
        "cookie": cookie,
        "authorization": authorization,
        "headers": headers,
        "note": profile.get("note", ""),
    }



def load_auth_profile_for_args(base: Path, profile_name: str) -> dict[str, object] | None:
    if not profile_name:
        return None
    try:
        auth = load_auth_profile(base, profile_name)
    except Exception as exc:
        eprint(f"Auth profile error: {exc}")
        return None
    headers = auth.get("headers")
    header_count = len(headers) if isinstance(headers, dict) else 0
    print(f"Auth profile: {profile_name} (headers={header_count})")
    return auth



def safe_profile_summary(name: str, profile: dict[str, object]) -> str:
    headers = profile.get("headers", {})
    header_count = len(headers) if isinstance(headers, dict) else len(headers) if isinstance(headers, list) else 0
    has_cookie = bool(profile.get("cookie") or profile.get("cookie_env"))
    has_authorization = bool(profile.get("authorization") or profile.get("authorization_env"))
    has_username = bool(profile.get("username"))
    has_password = bool(profile.get("password"))
    role = str(profile.get("role") or "")
    note = str(profile.get("note") or "")
    details = (
        f"role={role or '-'} username={'yes' if has_username else 'no'} "
        f"password={'yes' if has_password else 'no'} cookie={'yes' if has_cookie else 'no'} "
        f"authorization={'yes' if has_authorization else 'no'} headers={header_count}"
    )
    return f"- {name}: {details}" + (f" note={note}" if note else "")



def auth_profile_names(base: Path) -> tuple[list[str], str]:
    path = auth_store_path(base)
    if not path.exists():
        return [], ""
    try:
        raw = read_json_file(path, {})
    except Exception as exc:
        return [], f"invalid auth.local.json: {exc}"
    profiles = raw.get("profiles", raw) if isinstance(raw, dict) else {}
    if not isinstance(profiles, dict):
        return [], "invalid auth.local.json: missing profiles object"
    return sorted(str(key) for key in profiles.keys()), ""



def cmd_auth_profiles(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    path = auth_store_path(base)
    if not path.exists():
        print(f"No local auth profiles: {path}")
        print("Create one with: python ai_src.py auth-set <target> <profile> --cookie \"...\"")
        return 0
    try:
        raw = read_json_file(path, {})
    except Exception as exc:
        eprint(f"Auth profile error: {exc}")
        return 1
    profiles = raw.get("profiles", raw) if isinstance(raw, dict) else {}
    if not isinstance(profiles, dict):
        eprint(f"Invalid auth profile file: {path}")
        return 1
    if args.show_secrets:
        if args.profile:
            profile = profiles.get(args.profile)
            if profile is None:
                eprint(f"Auth profile not found: {args.profile}")
                return 2
            print(json.dumps({args.profile: profile}, ensure_ascii=False, indent=2))
        else:
            print(json.dumps({"profiles": profiles}, ensure_ascii=False, indent=2))
        return 0
    print(f"Auth profiles: {path}")
    for name in sorted(str(key) for key in profiles.keys()):
        profile = profiles.get(name)
        if not isinstance(profile, dict):
            continue
        print(safe_profile_summary(name, profile))
    return 0



def cmd_auth_set(args: argparse.Namespace) -> int:
    base = target_dir(args.target)
    ensure_target_dirs(base)
    path = auth_store_path(base)
    raw = read_json_file(path, {"profiles": {}})
    if not isinstance(raw, dict):
        raw = {"profiles": {}}
    profiles = raw.setdefault("profiles", {})
    if not isinstance(profiles, dict):
        raw["profiles"] = {}
        profiles = raw["profiles"]

    existing = profiles.get(args.profile)
    profile = dict(existing) if isinstance(existing, dict) else {}
    if args.role:
        profile["role"] = args.role
    if args.username:
        profile["username"] = args.username
    if args.password:
        profile["password"] = args.password
    if args.login_url:
        profile["login_url"] = args.login_url
    if args.tenant:
        profile["tenant"] = args.tenant
    if args.cookie:
        profile["cookie"] = args.cookie
    if args.cookie_env:
        profile["cookie_env"] = args.cookie_env
        profile.pop("cookie", None)
    if args.authorization:
        profile["authorization"] = args.authorization
    if args.authorization_env:
        profile["authorization_env"] = args.authorization_env
        profile.pop("authorization", None)
    headers = dict(profile.get("headers", {})) if isinstance(profile.get("headers"), dict) else {}
    for item in args.header or []:
        parsed = split_header_line(item)
        if not parsed:
            eprint(f"Invalid header, expected 'Name: value': {item}")
            return 2
        headers[parsed[0]] = parsed[1]
    if headers:
        profile["headers"] = headers
    headers_env = dict(profile.get("headers_env", {})) if isinstance(profile.get("headers_env"), dict) else {}
    for item in args.header_env or []:
        name, sep, env_name = item.partition("=")
        if not sep or not name.strip() or not env_name.strip():
            eprint(f"Invalid header env, expected 'Header-Name=ENV_VAR': {item}")
            return 2
        headers_env[name.strip()] = env_name.strip()
    if headers_env:
        profile["headers_env"] = headers_env
    if args.note:
        profile["note"] = args.note
    profile["updated_at"] = utc_now()
    profiles[args.profile] = profile
    raw["warning"] = "Local session material for authorized testing. This file is gitignored; do not commit it."
    write_json(path, raw)
    print(f"Auth profile saved: {args.profile} -> {path}")
    print("Stored fields: " + ", ".join(sorted(key for key in profile.keys() if key != "updated_at")))
    return 0

