#!/usr/bin/env python3
"""AI SRC workspace orchestrator.

This script is a thin entry point that delegates to the srcflow package.
The implementation has been split into modules under srcflow/ for maintainability.

For backward compatibility, all public functions and constants are re-exported
so that `import ai_src` continues to work as before.
"""
from __future__ import annotations

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# -- Constants --
from srcflow.constants import (
    ROOT, TARGETS_DIR, TOOLS_DIR, CONFIG_DIR,
    KNOWN_WRAPPERS, SECRET_ARG_NAMES, SECRET_HEADER_ARG_NAMES,
    SECRET_HEADER_NAMES, SECRET_HEADER_PREFIXES,
    LINE_URL_RE,
    GATE_PATTERNS, BANNED_TITLE_PATTERNS, POC_PATTERN,
    REPORT_URL_RE, PLACEHOLDER_VALUES,
    KATANA_PROFILES, FFUF_PROFILES,
    KATANA_BLOCKED_PASSTHROUGH, FFUF_BLOCKED_PASSTHROUGH,
    PASSIVE_STATIC_EXTENSIONS,
    TEST_STATUS_VALUES, FLOW_STATUS_VALUES,
    CONFIG_LIST_FIELDS, JS_RANK_KEYWORDS,
    HOP_BY_HOP_HEADERS,
)

# -- Utils --
from srcflow.utils import (
    eprint, utc_now, slugify, target_dir, ensure_target_dirs,
    read_lines_file, deep_merge, resolve_config_path, load_config,
    parse_first_number, number_value, metric_display, display_command,
    counter_dict, row_time, latest_event, event_data,
)

# -- IO helpers --
from srcflow.io_helpers import (
    write_json, read_json_file, append_jsonl, read_jsonl,
    metrics_path, endpoint_tests_path, request_recipes_path,
    flow_tests_path, append_metric,
    read_metric_events, read_endpoint_tests,
    read_request_recipes, read_flow_tests,
)

# -- Scope --
from srcflow.scope import (
    parse_allowed_wrappers, parse_ip_network_value,
    parse_ip_address_value, ip_in_ranges,
    parse_scope, scope_list,
    normalize_host, host_matches, host_in_scope,
    url_host, url_in_scope,
    require_scope_ready, require_url_in_scope, require_wrapper_allowed,
    cap_int_by_scope, cap_rate_by_scope, delay_from_scope,
    urls_from_line, scoped_urls_from_file, write_scoped_seed_file,
    ffuf_candidate_summary, snapshot_file,
    require_domain_in_scope,
    raw_scope_field, missing_setup_value,
    target_state_config, endpoint_export_count,
)

# -- Exec helpers --
from srcflow.exec_helpers import (
    redact_header_value, redact_cmd,
    run_cmd, run_capture,
    local_tool, require_local_tool, find_tool_path,
)

# -- Auth --
from srcflow.auth import (
    auth_store_path, split_header_line, auth_header_lines,
    header_name, merge_header_lines, resolve_env_value,
    load_auth_profile, load_auth_profile_for_args,
    safe_profile_summary, auth_profile_names,
    cmd_auth_profiles, cmd_auth_set,
)

# -- Metrics --
from srcflow.metrics_logic import (
    summarize_target_metrics, brief_event, render_flywheel,
    cmd_metrics, cmd_flywheel,
)

# -- Audit --
from srcflow.audit import (
    build_target_audit, print_target_audit,
    cmd_audit_target, cmd_validate_config,
    validate_config_object,
    cmd_tools, tool_status_rows,
    cmd_status, count_files,
)

# -- Wizard --
from srcflow.wizard import (
    render_scope, replace_scope_line, replace_scope_list,
    replace_scope_section_list, render_scope_from_wizard,
    split_wizard_items, normalize_wizard_domain, normalize_wizard_domains,
    normalize_wizard_seed, normalize_wizard_seeds,
    default_seed_urls, normalize_wizard_wrappers,
    first_profile_by_hint, account_label_for_profile,
    prompt_wizard_value, prompt_wizard_list, prompt_wizard_yes_no,
    target_config_output, build_wizard_config,
    collect_wizard_auth_profiles, default_out_of_scope_items,
    collect_target_wizard, collect_quick_target_wizard,
    collect_full_target_wizard, cmd_init_target,
)

# -- Crawler --
from srcflow.crawler import cmd_crawl, cmd_extract

# -- Wrappers --
from srcflow.wrappers import (
    normalize_passthrough, passthrough_has_flag,
    validate_passthrough, profile_args,
    cmd_katana_crawl, cmd_ffuf_safe,
)

# -- Passive --
from srcflow.passive import (
    passive_source_paths, passive_seed_candidates,
    passive_param_summary, refresh_passive_state,
    cmd_gau_urls, cmd_paramspider_urls,
)

# -- Gate --
from srcflow.gate import (
    checked_gate_count, cjk_count, first_heading,
    field_value, extract_report_urls, infer_target_from_report,
    cmd_gate,
)

# -- HAR import --
from srcflow.har_import import (
    query_keys_from_url, body_keys_from_har,
    har_headers_to_dict,
    recipe_id, recipe_from_har_entry,
    append_unique_recipes, recipe_method_path, find_recipe,
    cmd_import_har,
)

# -- Rank JS --
from srcflow.rank_js import manifest_url_by_path, cmd_rank_js

# -- Recipes --
from srcflow.recipes import cmd_recipe_list, cmd_recipe_run

# -- Probe --
from srcflow.probe import http_status_class, cmd_probe

# -- Logging commands --
from srcflow.logging_cmds import cmd_log_test, cmd_log_flow, cmd_checkpoint

# -- Diff endpoints --
from srcflow.diff_endpoints import endpoint_records, cmd_diff_endpoints, iter_exported_endpoints

# -- CLI --
from srcflow.cli import build_parser, main

if __name__ == "__main__":
    raise SystemExit(main())
