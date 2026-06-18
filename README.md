# SRCFlow

SRCFlow 是一个运行在现有代码 Agent CLI 之上的 SRC 工作区。它适配 Codex、Claude Code、Gemini CLI 等工具，提供目录结构、提示词、目标配置、保守工具封装、字典管理、被动度量、飞轮复盘和报告质量门控。

## 当前设计

- Agent 运行时：Codex、Claude Code、Gemini CLI 等现有代码 Agent。
- 浏览器能力：假设运行环境有浏览器 MCP，或等价的浏览器自动化与 Network 观察能力。
- 外部 CLI 工具：`katana` 和 `ffuf`。
- 工具接入方式：通过 `katana-crawl` 和 `ffuf-safe` 两个薄 wrapper 调用原生工具，同时做 scope 校验、速率限制、输出管理、度量记录和危险参数拦截。
- 循环方式：通过提示词、skills、metrics 和 flywheel 做软 loop 。
- 授权边界：每个目标都在 `targets/<target>/` 下维护，必须受 `scope.md` 约束。
- 报告语言：最终漏洞报告用中文，并且必须通过报告门控。

## 目录结构

```text
AGENTS.md                         Agent 规则和工作流主入口
CLAUDE.md / GEMINI.md             其他 Agent CLI 的入口文件，指向 AGENTS.md
ai_src.py                         工作区 CLI 与薄编排器
config/                           通用和目标专用的端点提取配置
examples/                         scope、配置、端点测试记录示例
payloads/src-payload/             本地 payload 与字典集合
scripts/                          安装脚本、爬虫、提取器、PowerShell helper
skills/                           核心规则、端点发现、端点测试等提示模块
targets/<target>/                 目标 scope、原始数据、状态、记录和报告
tools/bin/                        可选的本地 katana/ffuf 二进制文件
tools/README.md                   工具安装和 wrapper 说明
```

## 环境准备

必需：

- Python 3.10+。
- 一个能读取项目规则文件的代码 Agent CLI。
- 浏览器 MCP，或等价的浏览器自动化与 Network 观察能力。

推荐：

- Go，用于安装 `katana` 和 `ffuf`。

安装 Python 依赖：

```powershell
python -m pip install -r requirements.txt
```

安装或刷新外部工具：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_tools.ps1
python ai_src.py tools
```

安装脚本会依次检查 `PATH`、`%USERPROFILE%\go\bin`、`go install` 和 GitHub release Windows amd64 zip。如果自动安装失败，查看：

```powershell
Get-Content .\tools\TO_DOWNLOAD.txt
```

然后把对应的 `.exe` 手工放到 `tools/bin`。

## 创建目标

初始化一个目标工作区：

```powershell
python ai_src.py init-target demo --domain example.com --seed https://www.example.com/ --config default
```

然后检查并补全：

- `targets/demo/scope.md`
- `targets/demo/domains.txt`
- `targets/demo/seeds.txt`
- `config/demo.json`

`scope.md` 是授权边界文件，应包含授权来源、测试窗口、域名、IP/CIDR 范围、App、种子 URL、禁区、测试账号、速率限制、允许的 wrapper 和证据处理规则。

参考文件：

- [examples/scope.example.md](examples/scope.example.md)
- [examples/target-config.example.json](examples/target-config.example.json)
- [targets/_template/scope.md](targets/_template/scope.md)

## 启动 Agent 会话

在项目根目录启动你的 Agent CLI。新目标建议给 Agent 这段启动提示：

```text
Read AGENTS.md, skills/core.md, skills/endpoint-discovery.md,
skills/endpoint-testing.md, and targets/demo/scope.md.

Operate only within scope for target demo.

Use the soft SRCFlow loop:
1. Sample the target with browser Network observation before crawling.
2. Collect API hosts, URL patterns, request wrappers, auth headers,
   query keys, body keys, JS chunk patterns, and SPA routes.
3. Use katana-crawl on useful in-scope seeds or routes when it can
   improve URL coverage.
4. Update config/demo.json and validate it.
5. Crawl HTML/JS and include scoped katana seeds automatically.
6. Extract endpoints, rank JS/HTML, compare snapshots, and iterate.
7. Test endpoint families with minimum safe requests.
8. Use ffuf-safe only for narrow scoped discovery questions.
9. Use metrics and flywheel as soft reflection aids.
10. Only write Chinese vulnerability reports that pass the gates.
```

把 `demo` 换成当前目标名。提示词保持英文是为了和项目内 skills 一致；最终报告仍然要求中文。

## Loop 工作流

SRCFlow 主要围绕三个循环工作。模型负责选择测试方向，但 scope、wrapper、metrics 和报告门控负责约束越界、低质量结论和不可复盘的输出。

### Loop A：爬取前的模式采样

对新目标运行爬虫前：

1. 阅读 `targets/<target>/scope.md`。
2. 确认允许的 seed domain、seed URL、IP/CIDR、速率限制和 `Allowed wrappers`。
3. 运行 `python ai_src.py tools`。
4. 用浏览器 MCP 访问授权范围内的代表性页面，并观察 Network。
5. 收集 API host、base path、静态资源 host、JS chunk 规律、auth header、query key、body key 和 SPA route。
6. 当 katana 能补充 in-scope URL 覆盖时，再使用 `katana-crawl`。
7. 更新 `config/<target>.json`。
8. 运行 `python ai_src.py validate-config <target>`。
9. 再运行 `crawl`。

katana 补充入口示例：

```powershell
python ai_src.py katana-crawl demo https://www.example.com/ --depth 2
python ai_src.py katana-crawl demo https://app.example.com/ --profile routes -- -iqp
python ai_src.py katana-crawl demo https://app.example.com/ --profile headless-xhr -- -fx
```

`katana-crawl` 会写入：

- `targets/demo/state/katana_urls.txt`
- `targets/demo/state/katana_seeds.txt`

主爬虫会自动消费 `state/katana_seeds.txt`，除非显式传入 `--no-katana-seeds`。

### Loop B：爬取后的端点发现

校验配置：

```powershell
python ai_src.py validate-config demo
```

爬取 HTML/JS：

```powershell
python ai_src.py crawl demo --config demo --depth 2 --threads 10 --mode pages
```

登录态信息应在运行时传入，不写入配置文件：

```powershell
python ai_src.py crawl demo --config demo --cookie "SESSION=REDACTED"
```

提取端点并排序高价值 JS/HTML 文件：

```powershell
python ai_src.py extract demo --config demo
python ai_src.py rank-js .\targets\demo\raw\remote_sites --limit 30
```

`extract` 会在 `targets/demo/state/snapshots/` 下自动写入前后快照，并在适合比较时打印 `diff-endpoints` 命令。

比较两轮端点结果：

```powershell
python ai_src.py diff-endpoints .\targets\demo\state\snapshots\endpoints-before-xxx.json .\targets\demo\state\snapshots\endpoints-after-xxx.json
```

导入浏览器 HAR 作为补充线索：

```powershell
python ai_src.py import-har .\captures\demo.har --workspace-target demo --target example.com --as-endpoints
```

优先使用 `--workspace-target`，这样 HAR 请求会经过 `targets/<target>/scope.md` 过滤。

### Loop C：逐端点测试

对每个端点或端点家族：

1. 从 JS、HTML、HAR、Network、请求体、query string 和响应字段中找参数。
2. 判断功能类型：列表、详情、导出、上传、删除、更新、管理、认证、搜索、支付或业务流程。
3. 选择最可能的攻击面：未授权访问、IDOR、垂直越权、租户隔离、文件访问、注入、上传校验、流程绕过或敏感信息泄露。
4. 使用授权测试账号和最少安全请求验证。
5. 记录状态：`confirmed`、`rejected`、`needs account`、`needs more context` 或 `out of scope`。
6. 根据结果决定下一个端点，或回到配置/发现循环。

记录一次有意义的端点测试：

```powershell
python ai_src.py log-test demo /api/resource/1 --base-url https://www.example.com --method GET --status rejected --params "id" --function detail --attack-surface IDOR --auth-context "low privilege" --actual "403"
```

低风险端点探测：

```powershell
python ai_src.py probe demo --base-url https://www.example.com --method HEAD --limit 100
```

`probe` 只能产生信号，不能单独证明安全影响。

## ffuf-safe 与字典

本地字典在 [payloads/src-payload/](payloads/src-payload/) 下。选择字典前先读 [payloads/src-payload/README.md](payloads/src-payload/README.md)。

`ffuf-safe` 适合回答小而明确的 scoped 问题：

- 相邻路径。
- 隐藏 action。
- query 参数名。
- header 名或值。
- body key 或 value。
- 已经出现行为线索后的窄范围文件读取或注入探测。

示例：

```powershell
python ai_src.py ffuf-safe demo https://www.example.com/api/FUZZ .\payloads\src-payload\fuzzing\api-paths\api路径\API字典.txt --profile paths -- -fc 404 -ac
python ai_src.py ffuf-safe demo "https://www.example.com/api/search?FUZZ=test" .\payloads\src-payload\fuzzing\params\参数字典\web参数字典.txt --profile params -- -fc 404 -ac
python ai_src.py ffuf-safe demo https://www.example.com/api/action .\payloads\src-payload\fuzzing\params\参数字典\CommonDebugParamNames.txt --header "X-Feature: FUZZ" --profile params -- -ac
python ai_src.py ffuf-safe demo https://www.example.com/api/search .\payloads\src-payload\fuzzing\params\参数字典\web参数字典.txt --method POST --data '{"keyword":"FUZZ"}' --profile params -- -ac
```

`FUZZ` 可以放在 URL、`--header` 或 `--data` 中。

`ffuf-safe` 会写入：

- `targets/demo/state/ffuf-safe.json`
- `targets/demo/state/ffuf_candidates.json`

候选结果必须手工验证。原始 ffuf 输出不能直接写成报告。

## Wrapper 护栏

会发请求或调用外部工具的命令会做 scope 校验：

- `crawl` 校验 CLI seed、scope seed、config `extra_seeds` 和 scoped katana seeds。
- `probe` 校验 `--base-url`，并跳过 `endpoints.json` 里的越界绝对 URL。
- `import-har --workspace-target` 通过当前目标 scope 过滤 HAR 请求。
- `katana-crawl` 和 `ffuf-safe` 校验目标 URL、IP/CIDR scope、速率/并发上限和 `Allowed wrappers`。
- `--` 后的原生工具参数会透传，但覆盖目标 URL、输出路径、输出格式、scope、速率、并发、raw request 或 input command execution 的参数会被拒绝。

这些护栏能降低误操作概率，但不能替代人工阅读授权范围。

## Metrics 与 Flywheel

`ai_src.py` 会为有意义的工作区动作记录被动事件：

- crawl
- extract
- katana
- ffuf
- probe
- log-test
- checkpoint
- gate

度量事件流位置：

```text
targets/<target>/state/metrics.jsonl
```

查看度量：

```powershell
python ai_src.py metrics demo
```

生成飞轮复盘：

```powershell
python ai_src.py flywheel demo
```

飞轮输出位置：

```text
targets/<target>/state/flywheel.md
```

metrics 和 flywheel 只提供软提示。它们可以帮助 Agent 反思方向，但不能强制状态迁移，也不能覆盖目标的真实行为。

长会话中写入上下文检查点：

```powershell
python ai_src.py checkpoint demo --direction "endpoint discovery" --tested "..." --findings "..." --next "..."
```

## 报告门控

最终漏洞报告是中文，并且必须描述真实、可复现、有影响的安全问题。

门控命令：

```powershell
python ai_src.py gate .\targets\demo\reports\finding.md --target demo
```

不在 `targets/<target>/reports/` 下的报告必须传入 `--target`，否则 gate 失败。

报告必须包含：

- 授权范围。
- 可复现 PoC、curl 或可执行命令。
- 适用时提供多 ID 或多参数验证。
- 具体的机密性、完整性或可用性影响。
- 误报排除。
- 修复建议。

如果任何门控失败，继续测试，不输出漏洞结论。

## CLI 命令

主命令：

```text
init-target       创建目标工作区
crawl             爬取 HTML/JS 资源
extract           从已爬取文件中提取端点
gate              校验报告质量门和目标 scope
status            查看目标状态
metrics           汇总被动度量
flywheel          写入被动复盘笔记
checkpoint        追加压缩后的 loop 上下文
log-test          追加结构化端点测试记录
probe             对已提取端点做低风险状态探测
tools             检查本地工具可用性
validate-config   校验配置 JSON 和正则
diff-endpoints    比较两个 endpoints JSON
import-har        从浏览器 HAR 中提取 API 候选
rank-js           对已爬取 JS/HTML 进行人工审查排序
katana-crawl      使用保守默认值运行 katana URL 发现
ffuf-safe         使用保守低速默认值运行 ffuf
```

查看具体命令帮助：

```powershell
python ai_src.py <command> --help
```

## 输出位置

常见目标输出：

```text
targets/<target>/raw/remote_sites/          爬取到的 HTML/JS/assets/manifest 数据
targets/<target>/state/endpoints.json       当前提取到的端点集合
targets/<target>/state/snapshots/           extract 生成的端点快照
targets/<target>/state/katana_urls.txt      katana wrapper 原始 scoped 输出
targets/<target>/state/katana_seeds.txt     供 crawl 自动消费的 scoped URL
targets/<target>/state/probe_results.json   低风险端点探测结果
targets/<target>/state/ffuf-safe.json       ffuf-safe 原始 JSON 输出
targets/<target>/state/ffuf_candidates.json ffuf 候选摘要
targets/<target>/state/endpoint_tests.jsonl 结构化端点测试记录
targets/<target>/state/metrics.jsonl        被动度量事件流
targets/<target>/state/flywheel.md          软 loop 复盘笔记
targets/<target>/reports/                   最终中文报告
```

## 维护与验证

修改项目代码或工作流文档后，至少运行：

```powershell
python -m py_compile .\ai_src.py .\scripts\download_remote_sites.py .\scripts\extract_remote_eps.py
python .\ai_src.py --help
python .\scripts\download_remote_sites.py --help
python .\scripts\extract_remote_eps.py --help
python .\ai_src.py validate-config default
python .\ai_src.py tools
git diff --check
```

维护文档时，注意让这些文件保持一致：

- [AGENTS.md](AGENTS.md)
- [skills/core.md](skills/core.md)
- [skills/endpoint-discovery.md](skills/endpoint-discovery.md)
- [skills/endpoint-testing.md](skills/endpoint-testing.md)
- [tools/README.md](tools/README.md)
- [payloads/src-payload/README.md](payloads/src-payload/README.md)
