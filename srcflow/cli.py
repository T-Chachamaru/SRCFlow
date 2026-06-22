"""srcflow.cli - CLI parser and main entry point"""
from __future__ import annotations

import argparse
import sys

from srcflow.audit import cmd_audit_target, cmd_validate_config, cmd_tools, cmd_status
from srcflow.auth import cmd_auth_profiles, cmd_auth_set
from srcflow.crawler import cmd_crawl, cmd_extract
from srcflow.diff_endpoints import cmd_diff_endpoints
from srcflow.gate import cmd_gate
from srcflow.har_import import cmd_import_har
from srcflow.logging_cmds import cmd_log_test, cmd_log_flow, cmd_checkpoint
from srcflow.metrics_logic import cmd_metrics, cmd_flywheel
from srcflow.passive import cmd_gau_urls, cmd_paramspider_urls
from srcflow.probe import cmd_probe
from srcflow.rank_js import cmd_rank_js
from srcflow.recipes import cmd_recipe_list, cmd_recipe_run
from srcflow.wizard import cmd_init_target
from srcflow.wrappers import cmd_katana_crawl, cmd_ffuf_safe
from srcflow.constants import FFUF_PROFILES, FLOW_STATUS_VALUES, KATANA_PROFILES, TEST_STATUS_VALUES

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI SRC workspace CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init-target", help="create target sandbox")
    p.add_argument("name")
    p.add_argument("--domain", action="append", default=[])
    p.add_argument("--seed", action="append", default=[])
    p.add_argument("--config", default="default", help="config name or JSON path")
    p.add_argument("--wizard", action="store_true", help="interactively collect scope and target config")
    p.add_argument("--full-wizard", action="store_true", help="ask every template field instead of the quick wizard")
    p.add_argument("--force", action="store_true", help="allow wizard to overwrite existing target/config files after confirmation")
    p.set_defaults(func=cmd_init_target)

    p = sub.add_parser("crawl", help="crawl HTML/JS resources")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--mode", choices=["pages", "api", "full"], default="pages")
    p.add_argument("--config", default="default", help="config name or JSON path")
    p.add_argument("--target-kw", action="append", default=[])
    p.add_argument("--seed", action="append", default=[])
    p.add_argument("--include-css", action="store_true")
    p.add_argument("--include-json", action="store_true")
    p.add_argument("--parse-json-links", action="store_true")
    p.add_argument("--render", action="store_true")
    p.add_argument("--render-timeout", type=float, default=15.0)
    p.add_argument("--render-depth", type=int, default=0)
    p.add_argument("--cookie", default="")
    p.add_argument("--authorization", default="")
    p.add_argument("--auth-profile", default="", help="load Cookie/Authorization from targets/<target>/auth.local.json")
    p.add_argument("--max-size", type=float, default=5.0)
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--process-timeout", type=float, default=0.0, help="maximum crawler process runtime in seconds; 0 disables")
    p.add_argument("--no-katana-seeds", action="store_true", help="do not include state/katana_seeds.txt in crawl")
    p.add_argument("--no-passive-seeds", action="store_true", help="do not include state/passive_seeds.txt from gau/ParamSpider")
    p.add_argument("--max-urls", type=int, default=0)
    p.add_argument("--batch-size", type=int, default=0)
    p.set_defaults(func=cmd_crawl)

    p = sub.add_parser("extract", help="extract endpoints from crawled files")
    p.add_argument("target")
    p.add_argument("--sites-dir")
    p.add_argument("--out")
    p.add_argument("--config", default="default", help="config name or JSON path")
    p.add_argument("--target-kw", action="append", default=[])
    p.add_argument("--all-domains", action="store_true")
    p.add_argument("--no-known", action="store_true")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("gate", help="validate report quality gates and target scope")
    p.add_argument("report")
    p.add_argument("--target", help="target name for scope validation; required unless inferred from targets/<target>/reports")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("status", help="show target status")
    p.add_argument("target")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("audit-target", help="audit target readiness without enforcing a state machine")
    p.add_argument("target")
    p.add_argument("--config", default="", help="config name or JSON path; defaults to target state/config")
    p.add_argument("--json", action="store_true", help="print machine-readable audit output")
    p.set_defaults(func=cmd_audit_target)

    p = sub.add_parser("metrics", help="summarize passive target metrics")
    p.add_argument("target")
    p.add_argument("--json", action="store_true", help="print machine-readable summary")
    p.add_argument("--limit", type=int, default=10, help="recent metric events to print; 0 disables")
    p.set_defaults(func=cmd_metrics)

    p = sub.add_parser("flywheel", help="write passive learning notes from metrics")
    p.add_argument("target")
    p.add_argument("--out", help="output markdown path; use - to print only")
    p.add_argument("--print", dest="print_report", action="store_true", help="also print the generated markdown")
    p.set_defaults(func=cmd_flywheel)

    p = sub.add_parser("checkpoint", help="append compressed loop state")
    p.add_argument("target")
    p.add_argument("--direction")
    p.add_argument("--tested")
    p.add_argument("--findings")
    p.add_argument("--next")
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("log-test", help="append one structured endpoint test record")
    p.add_argument("target")
    p.add_argument("endpoint")
    p.add_argument("--base-url")
    p.add_argument("--recipe-id", default="")
    p.add_argument("--flow", default="")
    p.add_argument("--method", default="")
    p.add_argument("--status", choices=sorted(TEST_STATUS_VALUES), required=True)
    p.add_argument("--params", default="")
    p.add_argument("--function", default="")
    p.add_argument("--attack-surface", default="")
    p.add_argument("--auth-context", default="")
    p.add_argument("--requests", default="")
    p.add_argument("--expected", default="")
    p.add_argument("--actual", default="")
    p.add_argument("--evidence", default="")
    p.add_argument("--next", default="")
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_log_test)

    p = sub.add_parser("probe", help="low-risk status probe for extracted endpoints")
    p.add_argument("target")
    p.add_argument("--endpoints")
    p.add_argument("--base-url", help="base URL for relative endpoints")
    p.add_argument("--method", choices=["HEAD", "OPTIONS", "GET"], default="HEAD")
    p.add_argument("--authorization", default="")
    p.add_argument("--cookie", default="")
    p.add_argument("--auth-profile", default="", help="load headers from targets/<target>/auth.local.json")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--delay", type=float, default=0.2)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--out")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("tools", help="check local tool availability")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("recipe-list", help="list imported normal request recipes")
    p.add_argument("target")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_recipe_list)

    p = sub.add_parser("recipe-run", help="replay one normal request recipe")
    p.add_argument("target")
    p.add_argument("recipe", help="recipe id, unique URL substring, or method/path substring")
    p.add_argument("--auth-profile", default="", help="merge auth headers from targets/<target>/auth.local.json")
    p.add_argument("--method", default="", help="override recipe method")
    p.add_argument("--data", default="", help="override recipe body")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--no-redirects", action="store_true")
    p.add_argument("--body-sample", type=int, default=500)
    p.add_argument("--out")
    p.set_defaults(func=cmd_recipe_run)

    p = sub.add_parser("log-flow", help="append normal-flow or variant-flow testing record")
    p.add_argument("target")
    p.add_argument("flow")
    p.add_argument("--recipe", default="")
    p.add_argument("--endpoint", default="")
    p.add_argument("--status", choices=sorted(FLOW_STATUS_VALUES), required=True)
    p.add_argument("--auth-context", default="")
    p.add_argument("--preconditions", default="")
    p.add_argument("--param-sources", default="")
    p.add_argument("--success-indicators", default="")
    p.add_argument("--variant-plan", default="")
    p.add_argument("--actual", default="")
    p.add_argument("--next", default="")
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_log_flow)

    p = sub.add_parser("auth-profiles", help="list local ignored auth profiles for a target")
    p.add_argument("target")
    p.add_argument("profile", nargs="?", help="optional profile name")
    p.add_argument("--show-secrets", action="store_true", help="print stored local credentials/session material for agent use")
    p.set_defaults(func=cmd_auth_profiles)

    p = sub.add_parser("auth-set", help="save or update a local ignored auth profile for agent automation")
    p.add_argument("target")
    p.add_argument("profile")
    p.add_argument("--role", default="")
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.add_argument("--login-url", default="")
    p.add_argument("--tenant", default="")
    p.add_argument("--cookie", default="")
    p.add_argument("--cookie-env", default="", help="environment variable that contains the Cookie header value")
    p.add_argument("--authorization", default="")
    p.add_argument("--authorization-env", default="", help="environment variable that contains the Authorization header value")
    p.add_argument("--header", action="append", default=[], help="extra header as 'Name: value'")
    p.add_argument("--header-env", action="append", default=[], help="extra header as 'Name=ENV_VAR'")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_auth_set)

    p = sub.add_parser("validate-config", help="validate config JSON and regexes")
    p.add_argument("config", help="config name or JSON path")
    p.set_defaults(func=cmd_validate_config)

    p = sub.add_parser("diff-endpoints", help="compare two endpoints JSON exports")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--out")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_diff_endpoints)

    p = sub.add_parser("import-har", help="extract API candidates from a browser HAR file")
    p.add_argument("har")
    p.add_argument("--target", help="filter by host keyword")
    p.add_argument("--workspace-target", help="target name; filters requests through targets/<target>/scope.md")
    p.add_argument("--out")
    p.add_argument("--as-endpoints", action="store_true", help="export in endpoints.json-compatible format")
    p.add_argument("--as-recipes", action="store_true", help="append in-scope HAR requests to state/request_recipes.jsonl")
    p.set_defaults(func=cmd_import_har)

    p = sub.add_parser("rank-js", help="rank crawled JS/HTML files for manual review")
    p.add_argument("sites_dir")
    p.add_argument("--out")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_rank_js)

    p = sub.add_parser("gau-urls", help="fetch historical URLs with gau and update passive discovery state")
    p.add_argument("target")
    p.add_argument("domain")
    p.add_argument("--out")
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--blacklist", default="png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,mp3,webm")
    p.add_argument("--providers", default="")
    p.add_argument("--from", dest="from_date", default="")
    p.add_argument("--to", dest="to_date", default="")
    p.add_argument("--timeout", type=float, default=120.0, help="maximum runtime in seconds for the gau process")
    p.add_argument("--fp", action="store_true", help="gau --fp, collapse different parameter values of same endpoint")
    p.add_argument("--subs", action="store_true", help="gau --subs, include subdomains and then scope-filter output")
    p.set_defaults(func=cmd_gau_urls)

    p = sub.add_parser("paramspider-urls", help="fetch historical parameterized URLs with ParamSpider")
    p.add_argument("target")
    p.add_argument("domain")
    p.add_argument("--out")
    p.add_argument("--placeholder", default="", help="ParamSpider -p placeholder for parameter values")
    p.add_argument("--proxy", default="")
    p.add_argument("--timeout", type=float, default=90.0, help="maximum runtime in seconds for the ParamSpider process")
    p.set_defaults(func=cmd_paramspider_urls)

    p = sub.add_parser(
        "katana-crawl",
        help="run katana URL discovery with conservative defaults",
        epilog="Native katana args may be appended after --; safety/state flags such as -u, -o, -rl, -c and scope overrides are blocked.",
    )
    p.add_argument("target")
    p.add_argument("url")
    p.add_argument("--out")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--rate-limit", type=int, default=5)
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--process-timeout", type=float, default=180.0, help="maximum wrapper runtime in seconds; 0 disables")
    p.add_argument("--headless", action="store_true")
    p.add_argument("--auth-profile", default="", help="add auth headers from targets/<target>/auth.local.json")
    p.add_argument("--profile", choices=sorted(KATANA_PROFILES), default="default", help="small preset of native katana args")
    p.set_defaults(func=cmd_katana_crawl, allow_passthrough=True)

    p = sub.add_parser(
        "ffuf-safe",
        help="run ffuf with conservative low-rate defaults",
        epilog="Native ffuf args may be appended after --; safety/state flags such as -u, -o, -of, -rate and -t are blocked.",
    )
    p.add_argument("target")
    p.add_argument("url", help="target URL; FUZZ may be here, in --header, or in --data")
    p.add_argument("wordlist")
    p.add_argument("--out")
    p.add_argument("--rate", type=int, default=20)
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--process-timeout", type=float, default=300.0, help="maximum wrapper runtime in seconds; 0 disables")
    p.add_argument("--method", default="", help="optional HTTP method; defaults to POST when --data is used")
    p.add_argument("--header", action="append", default=[], help="ffuf -H header; may contain FUZZ")
    p.add_argument("--auth-profile", default="", help="add auth headers from targets/<target>/auth.local.json")
    p.add_argument("--data", default="", help="ffuf -d request body; may contain FUZZ")
    p.add_argument("--match-codes", default="200,204,301,302,307,401,403")
    p.add_argument("--extensions", help="ffuf -e value, for example .js,.json")
    p.add_argument("--filter-size", help="ffuf -fs value")
    p.add_argument("--profile", choices=sorted(FFUF_PROFILES), default="default", help="small preset of native ffuf args")
    p.set_defaults(func=cmd_ffuf_safe, allow_passthrough=True)

    return parser



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)
    if getattr(args, "allow_passthrough", False):
        args.tool_args = unknown
    elif unknown:
        parser.error("unrecognized arguments: " + " ".join(unknown))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

