#!/usr/bin/env python3
"""Offline smoke test for the SRCFlow CLI.

The test creates a temporary local target, serves a tiny in-scope app from
127.0.0.1, then exercises the major CLI command families without touching any
real external target.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
AI_SRC = ROOT / "ai_src.py"
TARGETS_DIR = ROOT / "targets"
CONFIG_DIR = ROOT / "config"
SENSITIVE_COOKIE = "SMOKESESSION=secret-cookie-value"
SENSITIVE_AUTH = "Bearer secret-token-value"
SENSITIVE_HEADER = "secret-api-key-value"


class SmokeError(RuntimeError):
    pass


class SmokeRunner:
    def __init__(self, keep: bool = False) -> None:
        self.keep = keep
        self.target = "srcflow-smoke"
        self.target_dir = TARGETS_DIR / self.target
        self.config_path = CONFIG_DIR / f"{self.target}.json"
        self.tmpdir = Path(tempfile.mkdtemp(prefix="srcflow-smoke-"))
        self.site_dir = self.tmpdir / "site"
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.server: http.server.ThreadingHTTPServer | None = None
        self.server_thread: threading.Thread | None = None

    def run(self) -> None:
        try:
            self.clean_workspace()
            self.write_site()
            self.start_server()
            self.write_target_files()
            self.exercise_cli()
        finally:
            self.stop_server()
            if not self.keep:
                self.clean_workspace()
                shutil.rmtree(self.tmpdir, ignore_errors=True)

    def clean_workspace(self) -> None:
        remove_under(self.target_dir, TARGETS_DIR, self.target)
        remove_under(self.config_path, CONFIG_DIR, f"{self.target}.json")

    def write_site(self) -> None:
        self.site_dir.mkdir(parents=True, exist_ok=True)
        (self.site_dir / "index.html").write_text(
            """<!doctype html>
<html>
<head><title>SRCFlow smoke</title></head>
<body>
  <a href="/app.js">app</a>
  <a href="/api/users?tenantId=t1&page=1">users</a>
  <script src="/app.js"></script>
</body>
</html>
""",
            encoding="utf-8",
        )
        (self.site_dir / "app.js").write_text(
            """const apiRoot = "/api/";
fetch("/api/users?tenantId=t1&page=1");
fetch("/api/users/123/profile");
axios.post("/api/orders/export", { orderId: "ord-1", tenantId: "t1" });
window.OPENAPI = "/openapi.json";
""",
            encoding="utf-8",
        )
        (self.site_dir / "openapi.json").write_text(
            json.dumps({"openapi": "3.0.0", "paths": {"/api/users": {}}}),
            encoding="utf-8",
        )

    def start_server(self) -> None:
        handler = handler_for(self.site_dir)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def stop_server(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join(timeout=5)

    def write_target_files(self) -> None:
        subprocess.run(
            [
                sys.executable,
                str(AI_SRC),
                "init-target",
                self.target,
                "--domain",
                "127.0.0.1",
                "--seed",
                self.base_url + "/",
                "--config",
                self.target,
            ],
            cwd=ROOT,
            check=True,
        )
        scope = self.target_dir / "scope.md"
        text = scope.read_text(encoding="utf-8")
        replacements = {
            "- Status: TODO - written authorization confirmed / pending.": "- Status: written authorization confirmed.",
            "- Authorization source: TODO - SRC program URL, email, contract, ticket, or internal approval ID.": "- Authorization source: local smoke-test fixture.",
            "- Window: TODO - YYYY-MM-DD HH:mm to YYYY-MM-DD HH:mm, timezone.": "- Window: 2026-06-22 00:00 to 2026-06-23 00:00 Asia/Hong_Kong.",
            "- Owner / SRC: TODO - organization and contact.": "- Owner / SRC: SRCFlow local smoke test.",
            "- Tester identity: TODO - account, team, or handle used for authorization.": "- Tester identity: automated local smoke test.",
            "- Max threads:": "- Max threads: 2",
            "- Max request rate:": "- Max request rate: 20",
            "- Allowed wrappers: ffuf-safe, gau-urls, katana-crawl, paramspider-urls, or narrower": "- Allowed wrappers: ffuf-safe, gau-urls, katana-crawl, paramspider-urls",
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        scope.write_text(text, encoding="utf-8")
        self.config_path.write_text(
            json.dumps(
                {
                    "extends": "default.json",
                    "target_keywords": ["127.0.0.1"],
                    "extra_seeds": [self.base_url + "/"],
                    "api_prefixes": ["/api/", "/openapi"],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self.write_auth_profiles()
        self.write_har()

    def write_auth_profiles(self) -> None:
        env = os.environ.copy()
        env["SRCFLOW_SMOKE_HEADER"] = SENSITIVE_HEADER
        self.cmd(
            "auth-set",
            self.target,
            "low",
            "--role",
            "low privilege",
            "--username",
            "low@example.test",
            "--password",
            "local-only-password",
            "--cookie",
            SENSITIVE_COOKIE,
            "--authorization",
            SENSITIVE_AUTH,
            "--header-env",
            "X-Api-Key=SRCFLOW_SMOKE_HEADER",
            expect=0,
            env=env,
        )

    def write_har(self) -> None:
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "SRCFlow smoke", "version": "1"},
                "entries": [
                    {
                        "startedDateTime": "2026-06-22T00:00:00.000Z",
                        "time": 1,
                        "request": {
                            "method": "GET",
                            "url": self.base_url + "/api/users?tenantId=t1&page=1",
                            "headers": [
                                {"name": "User-Agent", "value": "smoke"},
                                {"name": "Cookie", "value": SENSITIVE_COOKIE},
                            ],
                            "queryString": [],
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [{"name": "Content-Type", "value": "application/json"}],
                            "content": {"mimeType": "application/json", "text": "{}"},
                        },
                    },
                    {
                        "startedDateTime": "2026-06-22T00:00:01.000Z",
                        "time": 1,
                        "request": {
                            "method": "POST",
                            "url": self.base_url + "/api/orders/export",
                            "headers": [{"name": "Content-Type", "value": "application/json"}],
                            "postData": {
                                "mimeType": "application/json",
                                "text": "{\"orderId\":\"ord-1\",\"tenantId\":\"t1\"}",
                            },
                            "queryString": [],
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [{"name": "Content-Type", "value": "application/json"}],
                            "content": {"mimeType": "application/json", "text": "{}"},
                        },
                    },
                    {
                        "startedDateTime": "2026-06-22T00:00:02.000Z",
                        "time": 1,
                        "request": {
                            "method": "GET",
                            "url": "https://outside.example/api/leak",
                            "headers": [],
                            "queryString": [],
                        },
                        "response": {"status": 200, "statusText": "OK", "headers": [], "content": {}},
                    },
                ],
            }
        }
        self.har_path = self.tmpdir / "smoke.har"
        self.har_path.write_text(json.dumps(har, ensure_ascii=False, indent=2), encoding="utf-8")

    def exercise_cli(self) -> None:
        self.cmd("validate-config", self.target, expect=0)
        audit = self.cmd("audit-target", self.target, "--config", self.target, "--json", expect=0)
        audit_data = json.loads(audit.stdout)
        assert_equal(audit_data["status"], "ready", "audit-target status")

        self.cmd("tools", expect=0)
        self.cmd("status", self.target, expect=0)
        self.cmd("auth-profiles", self.target, expect=0)
        self.cmd("auth-profiles", self.target, "low", "--show-secrets", expect=0)

        crawl = self.cmd(
            "crawl",
            self.target,
            "--config",
            self.target,
            "--depth",
            "1",
            "--threads",
            "5",
            "--process-timeout",
            "30",
            "--auth-profile",
            "low",
            "--no-katana-seeds",
            "--no-passive-seeds",
            "--max-urls",
            "8",
            expect=0,
            env={"SRCFLOW_SMOKE_HEADER": SENSITIVE_HEADER},
        )
        assert_not_contains(crawl.stdout, SENSITIVE_COOKIE, "crawl stdout leaked cookie")
        assert_not_contains(crawl.stdout, SENSITIVE_AUTH, "crawl stdout leaked authorization")
        assert_not_contains(crawl.stdout, SENSITIVE_HEADER, "crawl stdout leaked header env value")

        self.cmd("extract", self.target, "--config", self.target, expect=0)
        endpoints = read_json(self.target_dir / "state" / "endpoints.json")
        assert_true(endpoints["total_unique"] >= 3, "extract should find API endpoints")

        rank_out = self.tmpdir / "rank.json"
        self.cmd("rank-js", str(self.target_dir / "raw" / "remote_sites"), "--out", str(rank_out), expect=0)
        assert_true(read_json(rank_out)["files"], "rank-js should rank downloaded files")

        har_out = self.tmpdir / "har-endpoints.json"
        self.cmd(
            "import-har",
            str(self.har_path),
            "--workspace-target",
            self.target,
            "--as-endpoints",
            "--as-recipes",
            "--out",
            str(har_out),
            expect=0,
        )
        har_export = read_json(har_out)
        assert_equal(har_export["total_raw"], 2, "import-har should scope-filter out external URL")
        assert_equal(har_export["total_unique"], 2, "import-har total_unique must not double-count by_domain and relative")
        recipes = (self.target_dir / "state" / "request_recipes.jsonl").read_text(encoding="utf-8")
        assert_contains(recipes, "/api/users", "import-har should append recipes")

        self.cmd("recipe-list", self.target, expect=0)
        self.cmd("recipe-run", self.target, "GET /api/users", "--timeout", "5", expect=0)
        self.cmd(
            "log-flow",
            self.target,
            "user list normal flow",
            "--recipe",
            "GET /api/users",
            "--status",
            "normal-flow-ok",
            "--param-sources",
            "HAR query tenantId,page",
            "--success-indicators",
            "HTTP 200",
            expect=0,
        )
        self.cmd(
            "log-test",
            self.target,
            "/api/users",
            "--base-url",
            self.base_url,
            "--method",
            "GET",
            "--status",
            "rejected",
            "--function",
            "list",
            "--attack-surface",
            "horizontal authorization",
            "--actual",
            "local smoke endpoint returned only fixture data",
            expect=0,
        )
        self.cmd("probe", self.target, "--base-url", self.base_url, "--method", "GET", "--limit", "5", "--delay", "0", expect=0)

        self.write_passive_sources()
        metrics = self.cmd("metrics", self.target, "--json", expect=0)
        metrics_data = json.loads(metrics.stdout)
        assert_true(metrics_data["recipes"]["records"] >= 2, "metrics should include recipes")
        assert_true(metrics_data["flows"]["records"] >= 1, "metrics should include flow records")
        assert_true(metrics_data["endpoint_tests"]["records"] >= 1, "metrics should include endpoint tests")
        assert_true(metrics_data["passive"]["passive_param_names"] >= 2, "metrics should include passive params")
        self.cmd("flywheel", self.target, "--out", str(self.tmpdir / "flywheel.md"), expect=0)
        self.cmd("checkpoint", self.target, "--direction", "smoke", "--tested", "CLI", "--findings", "none", "--next", "done", expect=0)

        self.write_endpoint_diff_files()
        diff_out = self.tmpdir / "endpoint-diff.json"
        self.cmd("diff-endpoints", str(self.tmpdir / "old.json"), str(self.tmpdir / "new.json"), "--out", str(diff_out), expect=0)
        diff_data = read_json(diff_out)
        assert_true(diff_data["added"], "diff-endpoints should report added endpoints")

        good_report = self.write_good_report()
        self.cmd("gate", str(good_report), "--target", self.target, expect=0)
        bad_report = self.tmpdir / "cors-report.md"
        bad_report.write_text("# CORS 配置问题\n\nTODO\n", encoding="utf-8")
        self.cmd("gate", str(bad_report), "--target", self.target, expect=1)

        self.cmd("log-test", self.target, "https://outside.example/api", "--status", "rejected", expect=2)
        self.cmd("ffuf-safe", self.target, self.base_url + "/api/FUZZ", str(self.tmpdir / "missing-wordlist.txt"), "--", "-u", "http://evil.test/FUZZ", expect=2)
        self.cmd("katana-crawl", self.target, "https://outside.example/", expect=2)
        self.cmd("gau-urls", self.target, "outside.example", "--timeout", "1", expect=2)
        self.cmd("paramspider-urls", self.target, "outside.example", "--timeout", "1", expect=2)

    def write_passive_sources(self) -> None:
        state = self.target_dir / "state"
        (state / "gau_urls.txt").write_text(
            "\n".join(
                [
                    self.base_url + "/api/users?tenantId=t1&page=1",
                    self.base_url + "/assets/logo.png",
                    "https://outside.example/api/users?tenantId=x",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (state / "paramspider_urls.txt").write_text(
            self.base_url + "/api/orders/export?orderId=ord-1&tenantId=t1\n",
            encoding="utf-8",
        )
        import ai_src

        summary = ai_src.refresh_passive_state(self.target_dir, ai_src.parse_scope(self.target_dir))
        assert_equal(summary["url_count"], 3, "passive state should keep all scoped URLs")
        assert_equal(summary["seed_count"], 2, "passive seeds should exclude static assets")

    def write_endpoint_diff_files(self) -> None:
        old = {
            "total_unique": 1,
            "total_raw": 1,
            "by_domain": {},
            "relative": [{"endpoint": "/api/users", "sources": 1, "type": "OLD", "normalized": "/api/users"}],
        }
        new = {
            "total_unique": 2,
            "total_raw": 2,
            "by_domain": {},
            "relative": [
                {"endpoint": "/api/users", "sources": 1, "type": "OLD", "normalized": "/api/users"},
                {"endpoint": "/api/orders/export", "sources": 1, "type": "NEW", "normalized": "/api/orders/export"},
            ],
        }
        (self.tmpdir / "old.json").write_text(json.dumps(old), encoding="utf-8")
        (self.tmpdir / "new.json").write_text(json.dumps(new), encoding="utf-8")

    def write_good_report(self) -> Path:
        report = self.target_dir / "reports" / "smoke-report.md"
        chinese = (
            "本地烟测报告用于验证质量门，不代表真实漏洞。该夹具只访问授权的 127.0.0.1 临时服务，"
            "通过多个对象标识和参数证明命令链路可以记录可复现证据、影响、误报排除和修复建议。"
        )
        report.write_text(
            f"""# 本地烟测对象级授权验证

## 授权范围

- Target: {self.target}
- Scope: {self.base_url}/api/users 与 {self.base_url}/api/orders/export，均为本地临时服务。
- Test time: 2026-06-22 00:00 Asia/Hong_Kong，本地自动化烟测。

## 漏洞结论

- Type: 对象级授权验证烟测
- Severity: 中
- Impact: {chinese}

## 复现步骤

```bash
curl -i '{self.base_url}/api/users?tenantId=t1&page=1' -H 'Cookie: SMOKESESSION=redacted'
curl -i '{self.base_url}/api/orders/export?orderId=ord-1&tenantId=t1' -H 'Authorization: Bearer redacted'
```

## 证据

- Expected: 服务端必须基于当前用户、租户和角色校验对象访问。
- Actual: 本地夹具返回固定测试数据，证明报告 gate 可以验证可复现命令和范围 URL。
- Verified IDs / parameters: tenantId=t1、page=1、orderId=ord-1、tenantId=t1。
- Accounts / roles compared: anonymous、low privilege。
- Normal flow source: browser HAR fixture and request recipe replay。

## 影响评估

- Confidentiality: 如果真实系统缺少对象校验，攻击者可能读取其他租户用户列表或订单导出结果。
- Integrity: 如果同类接口允许写操作，攻击者可能修改其他租户对象；本烟测没有执行写入。
- Availability: 本测试只发送少量本地请求，不影响可用性；真实缺陷可能导致批量导出被滥用。

## 误报排除

- Not CORS / security header / version disclosure / Self-XSS: 已排除这些无实际影响类别，报告聚焦服务端授权与敏感数据访问。
- Multiple-account or unauthenticated comparison: 已比较 anonymous 与 low privilege 的请求上下文。
- Cross-interface parameter migration attempted: 已将 tenantId 与 orderId 在列表、详情和导出接口之间迁移验证。
- Why this is not only a configuration observation: 证据包含可执行 curl、具体参数、范围 URL 和 C/I/A 影响。

## 修复建议

- Remediation: Enforce object-level authorization on server side for every user, tenant, and export endpoint.
- 建议: 绑定资源访问到认证用户、租户和角色，并为 IDOR、越权导出增加回归测试。

## 7 道验证门

- [x] 有可复现 PoC / curl / 可执行命令。
- [x] 报告的是实际安全影响，不是现象。
- [x] 已验证多个 ID / 参数，或说明限制。
- [x] 操作全部在授权范围内。
- [x] 已排除 CORS / 安全头 / 版本号 / Self-XSS 等误报。
- [x] 已尝试跨接口参数迁移，或说明不适用。
- [x] 影响评估具体覆盖 C/I/A。
""",
            encoding="utf-8",
        )
        return report

    def cmd(self, *args: str, expect: int, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, str(AI_SRC), *args]
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=merged_env,
        )
        print("$ " + subprocess.list2cmdline(redact_values(cmd)))
        print(redact_text(proc.stdout))
        if proc.returncode != expect:
            raise SmokeError(f"expected exit {expect}, got {proc.returncode}: {' '.join(args)}")
        return proc


def handler_for(directory: Path) -> type[http.server.SimpleHTTPRequestHandler]:
    class SmokeHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, directory=str(directory), **kwargs)

        def log_message(self, format: str, *args: object) -> None:
            return

        def end_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def do_GET(self) -> None:
            if self.path.startswith("/api/users"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"users":[{"id":123,"tenantId":"t1"}]}')
                return
            if self.path.startswith("/api/orders/export"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"exportId":"exp-1","tenantId":"t1"}')
                return
            super().do_GET()

        def do_HEAD(self) -> None:
            if self.path.startswith("/api/"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                return
            super().do_HEAD()

        def do_POST(self) -> None:
            if self.path.startswith("/api/orders/export"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"exportId":"exp-1"}')
                return
            self.send_response(404)
            self.end_headers()

    return SmokeHandler


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def remove_under(path: Path, root: Path, expected_name: str) -> None:
    if not path.exists():
        return
    resolved = path.resolve()
    root_resolved = root.resolve()
    if resolved.name != expected_name:
        raise SmokeError(f"refusing to remove unexpected path: {resolved}")
    if root_resolved not in resolved.parents:
        raise SmokeError(f"refusing to remove path outside {root_resolved}: {resolved}")
    if resolved.is_dir():
        shutil.rmtree(resolved)
    else:
        resolved.unlink()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def redact_text(value: str) -> str:
    for secret in (SENSITIVE_COOKIE, SENSITIVE_AUTH, SENSITIVE_HEADER, "local-only-password"):
        value = value.replace(secret, "REDACTED")
    return value


def redact_values(values: list[str]) -> list[str]:
    return [redact_text(str(value)) for value in values]


def assert_true(value: object, message: str) -> None:
    if not value:
        raise SmokeError(message)


def assert_equal(actual: object, expected: object, message: str) -> None:
    if actual != expected:
        raise SmokeError(f"{message}: expected {expected!r}, got {actual!r}")


def assert_contains(haystack: str, needle: str, message: str) -> None:
    if needle not in haystack:
        raise SmokeError(message)


def assert_not_contains(haystack: str, needle: str, message: str) -> None:
    if needle in haystack:
        raise SmokeError(message)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run offline SRCFlow CLI smoke tests")
    parser.add_argument("--keep", action="store_true", help="keep generated target/config/tmp files for debugging")
    args = parser.parse_args(argv)
    try:
        SmokeRunner(keep=args.keep).run()
    except SmokeError as exc:
        print(f"SMOKE FAILED: {exc}", file=sys.stderr)
        return 1
    print("SMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
