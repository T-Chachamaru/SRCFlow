"""srcflow.wizard - extracted from ai_src.py"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from srcflow.audit import cmd_validate_config
from srcflow.auth import auth_store_path, split_header_line
from srcflow.constants import CONFIG_DIR, KNOWN_WRAPPERS, ROOT, TARGETS_DIR
from srcflow.io_helpers import append_metric, write_json
from srcflow.scope import normalize_host, parse_allowed_wrappers
from srcflow.utils import ensure_target_dirs, eprint, slugify, target_dir, utc_now

def render_scope(name: str, domains: list[str], seeds: list[str]) -> str:
    template = (TARGETS_DIR / "_template" / "scope.md").read_text(encoding="utf-8")
    domain_lines = "\n".join(f"  - {domain}" for domain in domains) or "  - TODO"
    seed_lines = "\n".join(f"  - {seed}" for seed in seeds) or "  - TODO"
    rendered = template.replace("- Target: TODO", f"- Target: {slugify(name)}")
    rendered = re.sub(r"- Domains:\n(?:  - .+\n)+", f"- Domains:\n{domain_lines}\n", rendered)
    rendered = re.sub(r"- Seed URLs:\n(?:  - .+\n)+", f"- Seed URLs:\n{seed_lines}\n", rendered)
    return rendered



def replace_scope_line(text: str, label: str, value: str) -> str:
    return re.sub(rf"^- {re.escape(label)}:.*$", f"- {label}: {value}", text, flags=re.M)



def replace_scope_list(text: str, label: str, values: list[str], fallback: str = "TODO") -> str:
    clean = [item.strip() for item in values if item.strip()]
    if not clean:
        clean = [fallback]
    block = f"- {label}:\n" + "\n".join(f"  - {item}" for item in clean) + "\n"
    return re.sub(rf"^- {re.escape(label)}:\n(?:  - .*(?:\n|$))*", block, text, flags=re.M)



def replace_scope_section_list(text: str, section: str, next_section: str, values: list[str]) -> str:
    clean = [item.strip() for item in values if item.strip()]
    block = f"## {section}\n\n" + "\n".join(f"- {item}" for item in clean) + "\n\n"
    pattern = rf"## {re.escape(section)}\n\n.*?\n## {re.escape(next_section)}"
    return re.sub(pattern, block + f"## {next_section}", text, flags=re.S)



def render_scope_from_wizard(name: str, setup: dict[str, object]) -> str:
    template = (TARGETS_DIR / "_template" / "scope.md").read_text(encoding="utf-8")
    rendered = template

    def text_value(key: str, default: str = "TODO") -> str:
        value = str(setup.get(key) or "").strip()
        return value or default

    def list_value(key: str) -> list[str]:
        value = setup.get(key)
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    rendered = replace_scope_line(rendered, "Status", text_value("authorization_status", "TODO - pending"))
    rendered = replace_scope_line(rendered, "Authorization source", text_value("authorization_source"))
    rendered = replace_scope_line(rendered, "Window", text_value("authorization_window"))
    rendered = replace_scope_line(rendered, "Owner / SRC", text_value("owner"))
    rendered = replace_scope_line(rendered, "Tester identity", text_value("tester_identity"))
    rendered = replace_scope_line(rendered, "Target", slugify(name))

    rendered = replace_scope_list(rendered, "Domains", list_value("domains"))
    rendered = replace_scope_list(rendered, "IP ranges", list_value("ip_ranges"), "N/A")
    rendered = replace_scope_list(rendered, "Apps / packages", list_value("apps"), "N/A")
    rendered = replace_scope_list(rendered, "Seed URLs", list_value("seeds"))
    rendered = replace_scope_list(rendered, "Allowed environments", list_value("allowed_environments"), "production read-only")

    rendered = replace_scope_section_list(rendered, "Out Of Scope", "Test Accounts", list_value("out_of_scope"))

    rendered = replace_scope_line(rendered, "Anonymous / no-auth baseline", text_value("account_anonymous", "no cookies"))
    rendered = replace_scope_line(rendered, "Low privilege", text_value("account_low", "TODO"))
    rendered = replace_scope_line(rendered, "Peer user", text_value("account_peer", "TODO"))
    rendered = replace_scope_line(rendered, "Admin / high privilege", text_value("account_admin", "only if explicitly approved"))
    rendered = replace_scope_line(rendered, "Test tenant / organization", text_value("test_tenant", "TODO"))

    rendered = replace_scope_line(rendered, "Max threads", text_value("max_threads", "5"))
    rendered = replace_scope_line(rendered, "Max request rate", text_value("max_request_rate", "2 req/s"))
    rendered = replace_scope_line(rendered, "Allowed wrappers", ", ".join(list_value("allowed_wrappers")) or ", ".join(sorted(KNOWN_WRAPPERS)))
    rendered = replace_scope_line(rendered, "Disallowed scan types", text_value("disallowed_scan_types", "brute force, destructive, DoS, intrusive fuzzing"))

    rendered = replace_scope_line(rendered, "Evidence handling", text_value("evidence_handling", "user-managed evidence handling"))
    rendered = replace_scope_line(rendered, "Maximum records to view", text_value("max_records", "3"))
    rendered = replace_scope_line(rendered, "Screenshot allowed", text_value("screenshot_allowed", "yes"))
    rendered = replace_scope_line(rendered, "Response body storage allowed", text_value("response_body_storage", "yes, within authorization"))

    notes = list_value("notes") or [
        "Keep evidence minimal.",
        "Stop before irreversible state changes unless explicit test data is available.",
    ]
    rendered = re.sub(
        r"## Notes\n\n.*\Z",
        "## Notes\n\n" + "\n".join(f"- {note}" for note in notes) + "\n",
        rendered,
        flags=re.S,
    )
    return rendered



def split_wizard_items(value: str) -> list[str]:
    if value.strip().lower() in {"n/a", "na", "none", "no", "-"}:
        return []
    parts = re.split(r"[,;\n\uFF0C\uFF1B]+", value)
    result: list[str] = []
    for part in parts:
        item = part.strip()
        if item and item not in result:
            result.append(item)
    return result



def normalize_wizard_domain(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    return normalize_host(value)



def normalize_wizard_domains(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        domain = normalize_wizard_domain(value)
        if domain and domain not in result:
            result.append(domain)
    return result



def normalize_wizard_seed(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    return "https://" + value.strip("/") + "/"



def normalize_wizard_seeds(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        seed = normalize_wizard_seed(value)
        if seed and seed not in result:
            result.append(seed)
    return result



def default_seed_urls(domains: list[str]) -> list[str]:
    return [f"https://{domain}/" for domain in domains if domain]



def normalize_wizard_wrappers(values: list[str]) -> list[str]:
    if not values:
        return sorted(KNOWN_WRAPPERS)
    joined = ", ".join(values)
    parsed = parse_allowed_wrappers(joined)
    if parsed is None:
        return sorted(KNOWN_WRAPPERS)
    return parsed



def first_profile_by_hint(profiles: dict[str, dict[str, object]], hint: str) -> str:
    hint = hint.lower()
    for name in sorted(profiles):
        profile = profiles.get(name, {})
        role = str(profile.get("role", "")).lower() if isinstance(profile, dict) else ""
        if hint in name.lower() or hint in role:
            return name
    return ""



def account_label_for_profile(name: str) -> str:
    return f"auth.local.json profile: {name}" if name else "N/A"



def prompt_wizard_value(label: str, default: str = "", required: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            value = input(f"{label}{suffix}: ").strip()
        except EOFError:
            value = ""
        if not value and default:
            value = default
        if value or not required:
            return value
        print("Required. Enter a value or press Ctrl+C to cancel.")



def prompt_wizard_list(label: str, default: list[str] | None = None, required: bool = False) -> list[str]:
    default = default or []
    default_text = ", ".join(default)
    suffix = f" [{default_text}]" if default_text else ""
    while True:
        try:
            raw = input(f"{label}{suffix}: ").strip()
        except EOFError:
            raw = ""
        values = list(default) if not raw and default else split_wizard_items(raw)
        if values or not required:
            return values
        print("Required. Use comma-separated values, or press Ctrl+C to cancel.")



def prompt_wizard_yes_no(label: str, default: bool = False) -> bool:
    default_text = "Y/n" if default else "y/N"
    try:
        value = input(f"{label} [{default_text}]: ").strip().lower()
    except EOFError:
        value = ""
    if not value:
        return default
    return value in {"y", "yes"}



def target_config_output(value: str, target_name: str) -> tuple[str, Path]:
    if value == "default":
        label = slugify(target_name)
        return label, CONFIG_DIR / f"{label}.json"
    path = Path(value)
    if path.suffix.lower() == ".json" or path.parent != Path("."):
        output = path if path.is_absolute() else ROOT / path
        return str(path), output
    return value, CONFIG_DIR / f"{value}.json"



def build_wizard_config(setup: dict[str, object]) -> dict[str, object]:
    def list_value(key: str) -> list[str]:
        value = setup.get(key)
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    data: dict[str, object] = {
        "extends": "default.json",
        "target_keywords": list_value("target_keywords") or list_value("domains"),
        "extra_seeds": list_value("seeds"),
    }
    optional_lists = (
        "api_prefixes",
        "api_path_regexes",
        "known_endpoints",
        "garbage_substrings",
    )
    for key in optional_lists:
        values = list_value(key)
        if values:
            data[key] = values
    return data



def collect_wizard_auth_profiles(default: bool = False, quick: bool = False) -> dict[str, dict[str, object]]:
    label = "Add local auth profiles for Agent automation now?"
    if not prompt_wizard_yes_no(label, default=default):
        return {}
    names = prompt_wizard_list("Auth profile names", ["low"] if quick else ["low", "peer"])
    profiles: dict[str, dict[str, object]] = {}
    print("These values are written to targets/<target>/auth.local.json, which is gitignored.")
    print("The Agent can read this file for browser login and authenticated request automation.")
    for name in names:
        print(f"")
        print(f"Auth profile: {name}")
        role = prompt_wizard_value("Role / auth context", name)
        profile: dict[str, object] = {"role": role or name}
        if quick:
            material = prompt_wizard_value("Auth material type: cookie / token / password / both", "cookie").lower()
            tenant = prompt_wizard_value("Tenant / organization")
            if tenant:
                profile["tenant"] = tenant
            if any(word in material for word in ("password", "both", "account", "login")):
                login_url = normalize_wizard_seed(prompt_wizard_value("Login URL"))
                username = prompt_wizard_value("Username / login identifier")
                password = prompt_wizard_value("Password")
                if login_url:
                    profile["login_url"] = login_url
                if username:
                    profile["username"] = username
                if password:
                    profile["password"] = password
            if any(word in material for word in ("cookie", "session", "both")):
                cookie = prompt_wizard_value("Cookie header value")
                if cookie:
                    profile["cookie"] = cookie
            if any(word in material for word in ("token", "bearer", "authorization", "both")):
                authorization = prompt_wizard_value("Authorization header value")
                if authorization:
                    profile["authorization"] = authorization
        else:
            for key, prompt in (
                ("username", "Username / login identifier"),
                ("password", "Password"),
                ("login_url", "Login URL"),
                ("tenant", "Tenant / organization"),
            ):
                value = prompt_wizard_value(prompt)
                if value:
                    profile[key] = value
            cookie = prompt_wizard_value("Cookie header value")
            authorization = prompt_wizard_value("Authorization header value")
            if cookie:
                profile["cookie"] = cookie
            if authorization:
                profile["authorization"] = authorization
        headers = prompt_wizard_list("Extra headers as 'Name: value'")
        note = "" if quick else prompt_wizard_value("Auth profile note")
        parsed_headers: dict[str, str] = {}
        for header in headers:
            parsed = split_header_line(header)
            if parsed:
                parsed_headers[parsed[0]] = parsed[1]
            else:
                print(f"Skipping invalid header: {header}")
        if parsed_headers:
            profile["headers"] = parsed_headers
        if note:
            profile["note"] = note
        profile["updated_at"] = utc_now()
        profiles[name] = profile
    return profiles



def default_out_of_scope_items() -> list[str]:
    return [
        "Third-party domains unless explicitly listed above.",
        "Production destructive actions.",
        "Denial of service, stress testing, credential stuffing, social engineering.",
        "Bulk export of sensitive data.",
        "Payment, SMS, email, push notification, or irreversible workflows unless explicit test data is provided.",
        "Employee, customer, or private tenant data outside the approved test accounts.",
    ]



def collect_target_wizard(args: argparse.Namespace) -> dict[str, object] | None:
    if args.full_wizard:
        return collect_full_target_wizard(args)
    return collect_quick_target_wizard(args)



def collect_quick_target_wizard(args: argparse.Namespace) -> dict[str, object] | None:
    target = slugify(args.name)
    print("Target setup wizard (quick)")
    print("Only core setup is asked up front. Use --full-wizard for every template field.")
    print("Credentials/session material belongs in local auth profiles, not authorization fields.")
    print("Use comma-separated values for list prompts. Enter N/A for an empty list.")
    print("")

    domains = normalize_wizard_domains(prompt_wizard_list("In-scope domains", sorted(set(args.domain or []))))
    default_seeds = normalize_wizard_seeds(args.seed or []) or default_seed_urls(domains)
    seeds = normalize_wizard_seeds(prompt_wizard_list("Seed URLs", default_seeds))
    ip_ranges = prompt_wizard_list("In-scope IP/CIDR ranges")
    if not domains and not ip_ranges:
        print("Warning: no domain or IP/CIDR was provided. Scope guards will block active commands until scope is completed.")

    owner = prompt_wizard_value("SRC / owner / authorization source", "TODO - confirm authorization source")
    tester_default = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    tester_identity = prompt_wizard_value("Tester identity", tester_default)
    auth_window = prompt_wizard_value("Authorization window", "N/A / program default")
    apps = prompt_wizard_list("Apps / packages")
    allowed_environments = prompt_wizard_list("Allowed environments", ["production read-only"])

    setup: dict[str, object] = {
        "authorization_status": "written authorization confirmed / pending",
        "authorization_source": owner,
        "authorization_window": auth_window,
        "owner": owner,
        "tester_identity": tester_identity,
        "domains": domains,
        "ip_ranges": ip_ranges,
        "apps": apps,
        "seeds": seeds,
        "allowed_environments": allowed_environments,
        "out_of_scope": default_out_of_scope_items(),
        "account_anonymous": "no cookies",
        "account_low": "N/A",
        "account_peer": "N/A",
        "account_admin": "only if explicitly approved",
        "test_tenant": "N/A",
        "max_threads": "5",
        "max_request_rate": "2 req/s",
        "allowed_wrappers": sorted(KNOWN_WRAPPERS),
        "disallowed_scan_types": "brute force, destructive, DoS, intrusive fuzzing",
        "evidence_handling": "user-managed evidence handling",
        "max_records": "3",
        "screenshot_allowed": "yes",
        "response_body_storage": "yes, within authorization",
        "notes": [
            "Generated with quick setup wizard.",
            "Agent should ask only for missing authorization/account context that cannot be inferred safely.",
        ],
        "target_keywords": domains,
        "api_prefixes": [],
        "api_path_regexes": [],
        "known_endpoints": [],
        "garbage_substrings": [],
    }

    if not prompt_wizard_yes_no("Use recommended safety and evidence defaults?", default=True):
        setup["max_threads"] = prompt_wizard_value("Max threads", "5")
        setup["max_request_rate"] = prompt_wizard_value("Max request rate", "2 req/s")
        setup["allowed_wrappers"] = normalize_wizard_wrappers(prompt_wizard_list("Allowed wrappers", sorted(KNOWN_WRAPPERS)))
        setup["disallowed_scan_types"] = prompt_wizard_value("Disallowed scan types", "brute force, destructive, DoS, intrusive fuzzing")
        setup["max_records"] = prompt_wizard_value("Maximum records to view", "3")

    auth_profiles = collect_wizard_auth_profiles(default=True, quick=True)
    if auth_profiles:
        setup["auth_profiles"] = auth_profiles
        first_low = first_profile_by_hint(auth_profiles, "low") or next(iter(sorted(auth_profiles)))
        first_peer = first_profile_by_hint(auth_profiles, "peer")
        setup["account_low"] = account_label_for_profile(first_low)
        setup["account_peer"] = account_label_for_profile(first_peer)
        for profile in auth_profiles.values():
            if isinstance(profile, dict) and profile.get("tenant"):
                setup["test_tenant"] = str(profile.get("tenant"))
                break

    if prompt_wizard_yes_no("Add advanced endpoint extraction hints now?", default=False):
        setup["target_keywords"] = prompt_wizard_list("Config target keywords", domains)
        setup["api_prefixes"] = prompt_wizard_list("Extra API prefixes")
        setup["api_path_regexes"] = prompt_wizard_list("Extra API path regexes")
        setup["known_endpoints"] = prompt_wizard_list("Extra known endpoints")
        setup["garbage_substrings"] = prompt_wizard_list("Extra garbage substrings")

    note = prompt_wizard_value("Additional note")
    if note:
        notes = setup.get("notes")
        if isinstance(notes, list):
            notes.append(note)

    config_label, config_path = target_config_output(args.config, target)
    setup["config_label"] = config_label
    setup["config_path"] = str(config_path)

    print("")
    print("Summary")
    print(f"- Target: {target}")
    print(f"- Domains: {', '.join(domains) or '-'}")
    print(f"- IP/CIDR: {', '.join(ip_ranges) or '-'}")
    print(f"- Seeds: {', '.join(seeds) or '-'}")
    print(f"- Auth profiles: {', '.join(sorted(auth_profiles)) if auth_profiles else '-'}")
    print(f"- Allowed wrappers: {', '.join(setup['allowed_wrappers']) if isinstance(setup.get('allowed_wrappers'), list) else setup.get('allowed_wrappers')}")
    print(f"- Config: {config_path}")
    if not prompt_wizard_yes_no("Write these target files?", default=True):
        print("Wizard cancelled; no files were written.")
        return None
    return setup



def collect_full_target_wizard(args: argparse.Namespace) -> dict[str, object] | None:
    target = slugify(args.name)
    print("Target setup wizard (full)")
    print("Credentials/session material may be entered only for local auth profiles.")
    print("They are written to targets/<target>/auth.local.json, which is gitignored and intended for Agent automation.")
    print("Use comma-separated values for list prompts. Enter N/A for an empty list.")
    print("")

    domains = normalize_wizard_domains(prompt_wizard_list("In-scope domains", sorted(set(args.domain or []))))
    default_seeds = normalize_wizard_seeds(args.seed or []) or default_seed_urls(domains)
    seeds = normalize_wizard_seeds(prompt_wizard_list("Seed URLs", default_seeds))
    ip_ranges = prompt_wizard_list("In-scope IP/CIDR ranges")
    if not domains and not ip_ranges:
        print("Warning: no domain or IP/CIDR was provided. Scope guards will block active commands until scope is completed.")

    default_out = default_out_of_scope_items()

    setup: dict[str, object] = {
        "authorization_status": prompt_wizard_value("Authorization status", "TODO - written authorization confirmed / pending"),
        "authorization_source": prompt_wizard_value("Authorization source"),
        "authorization_window": prompt_wizard_value("Authorization window", "TODO - YYYY-MM-DD HH:mm to YYYY-MM-DD HH:mm, timezone"),
        "owner": prompt_wizard_value("Owner / SRC"),
        "tester_identity": prompt_wizard_value("Tester identity"),
        "domains": domains,
        "ip_ranges": ip_ranges,
        "apps": prompt_wizard_list("Apps / packages"),
        "seeds": seeds,
        "allowed_environments": prompt_wizard_list("Allowed environments", ["production read-only"]),
        "out_of_scope": default_out + prompt_wizard_list("Additional out-of-scope items"),
        "account_anonymous": prompt_wizard_value("Anonymous baseline", "no cookies"),
        "account_low": prompt_wizard_value("Low-privilege test account identifier"),
        "account_peer": prompt_wizard_value("Peer-user test account identifier"),
        "account_admin": prompt_wizard_value("Admin/high-privilege account identifier", "only if explicitly approved"),
        "test_tenant": prompt_wizard_value("Test tenant / organization"),
        "max_threads": prompt_wizard_value("Max threads", "5"),
        "max_request_rate": prompt_wizard_value("Max request rate", "2 req/s"),
        "allowed_wrappers": normalize_wizard_wrappers(prompt_wizard_list("Allowed wrappers", sorted(KNOWN_WRAPPERS))),
        "disallowed_scan_types": prompt_wizard_value("Disallowed scan types", "brute force, destructive, DoS, intrusive fuzzing"),
        "evidence_handling": "user-managed evidence handling",
        "max_records": prompt_wizard_value("Maximum records to view", "3"),
        "screenshot_allowed": prompt_wizard_value("Screenshot allowed", "yes"),
        "response_body_storage": prompt_wizard_value("Response body storage allowed", "yes, within authorization"),
        "notes": prompt_wizard_list("Additional notes"),
        "target_keywords": prompt_wizard_list("Config target keywords", domains),
        "api_prefixes": prompt_wizard_list("Extra API prefixes"),
        "api_path_regexes": prompt_wizard_list("Extra API path regexes"),
        "known_endpoints": prompt_wizard_list("Extra known endpoints"),
        "garbage_substrings": prompt_wizard_list("Extra garbage substrings"),
    }
    auth_profiles = collect_wizard_auth_profiles(default=False, quick=False)
    if auth_profiles:
        setup["auth_profiles"] = auth_profiles

    config_label, config_path = target_config_output(args.config, target)
    setup["config_label"] = config_label
    setup["config_path"] = str(config_path)

    print("")
    print("Summary")
    print(f"- Target: {target}")
    print(f"- Domains: {', '.join(domains) or '-'}")
    print(f"- IP/CIDR: {', '.join(ip_ranges) or '-'}")
    print(f"- Seeds: {', '.join(seeds) or '-'}")
    print(f"- Config: {config_path}")
    if not prompt_wizard_yes_no("Write these target files?", default=True):
        print("Wizard cancelled; no files were written.")
        return None
    return setup



def cmd_init_target(args: argparse.Namespace) -> int:
    base = target_dir(args.name)

    setup: dict[str, object] | None = None
    config_label = args.config
    config_path: Path | None = None
    if args.wizard or args.full_wizard:
        setup = collect_target_wizard(args)
        if setup is None:
            return 2
        domains = sorted(set(str(item) for item in setup.get("domains", []) if str(item).strip()))
        seeds = sorted(set(str(item) for item in setup.get("seeds", []) if str(item).strip()))
        config_label = str(setup.get("config_label") or args.config)
        config_path = Path(str(setup.get("config_path")))
    else:
        domains = sorted(set(args.domain or []))
        seeds = sorted(set(args.seed or []))

    ensure_target_dirs(base)
    scope_path = base / "scope.md"
    if setup is not None:
        pending_paths = [scope_path, base / "domains.txt", base / "seeds.txt"]
        if config_path is not None:
            pending_paths.append(config_path)
        auth_profiles = setup.get("auth_profiles")
        if isinstance(auth_profiles, dict) and auth_profiles:
            pending_paths.append(auth_store_path(base))
        existing_paths = [path for path in pending_paths if path.exists()]
        if existing_paths and not args.force:
            print("The following files already exist:")
            for path in existing_paths:
                print(f"- {path}")
            if not prompt_wizard_yes_no("Overwrite existing files?", default=False):
                print("Wizard cancelled; no files were overwritten.")
                return 2
        scope_path.write_text(render_scope_from_wizard(args.name, setup), encoding="utf-8")
        if config_path is not None:
            write_json(config_path, build_wizard_config(setup))
        if isinstance(auth_profiles, dict) and auth_profiles:
            write_json(auth_store_path(base), {
                "warning": "Local credentials and session material for authorized testing. This file is gitignored; do not commit it.",
                "created_at": utc_now(),
                "profiles": auth_profiles,
            })
    else:
        if not scope_path.exists():
            scope_path.write_text(render_scope(args.name, domains, seeds), encoding="utf-8")
        elif domains or seeds:
            existing = scope_path.read_text(encoding="utf-8", errors="ignore")
            if "- Target: TODO" in existing and "Authorization source: TODO" in existing:
                scope_path.write_text(render_scope(args.name, domains, seeds), encoding="utf-8")

    if domains:
        (base / "domains.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")
    if seeds:
        (base / "seeds.txt").write_text("\n".join(seeds) + "\n", encoding="utf-8")

    state = {
        "target": slugify(args.name),
        "created_at": utc_now(),
        "domains": domains,
        "seeds": seeds,
        "config": config_label,
        "notes": "Generated with setup wizard." if setup is not None else "Fill scope.md before active testing.",
    }
    write_json(base / "state" / "target.json", state)
    append_metric(base, "init_target", {
        "domains_count": len(domains),
        "seeds_count": len(seeds),
        "config": config_label,
        "wizard": setup is not None,
        "auth_profiles": sorted((setup.get("auth_profiles") or {}).keys()) if setup is not None and isinstance(setup.get("auth_profiles"), dict) else [],
    })

    print(f"Target ready: {base}")
    print(f"Edit scope:   {base / 'scope.md'}")
    if config_path is not None:
        print(f"Config:       {config_path}")
        try:
            cmd_validate_config(argparse.Namespace(config=config_label))
        except Exception as exc:
            eprint(f"Config validation warning: {exc}")
    return 0

