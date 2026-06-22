# SRCFlow

SRCFlow 是运行在 Codex、Claude Code、Gemini CLI 等现有代码 Agent 之上的 SRC 工作区。它不实现自定义 Agent Runtime，而是提供目录结构、提示词、目标配置、payload 字典、薄 CLI wrapper、被动度量、flywheel 复盘和报告质量门。

## 当前设计

- 浏览器能力：假设 Agent 运行环境具备浏览器 MCP 或等价的浏览器自动化与 Network 观察能力。
- 外部工具：`katana`、`ffuf`、`gau`、`ParamSpider`。
- 工具接入：通过 `gau-urls`、`paramspider-urls`、`katana-crawl`、`ffuf-safe` 薄 wrapper 调用原生工具，同时做 scope 校验、输出管理、度量记录和危险参数拦截。
- 循环方式：不追加强制状态机，通过 `AGENTS.md`、`skills/`、metrics、flywheel 和 checkpoint 让 Agent 维持软 loop。
- 目标边界：每个目标在 `targets/<target>/` 下维护，主动测试必须受 `scope.md` 约束。
- 报告语言：最终漏洞报告使用中文，并且必须通过报告门控。

## 目录结构

```text
AGENTS.md                         Agent 主规则和工作流入口
CLAUDE.md / GEMINI.md             其他 Agent CLI 的入口文件，指向 AGENTS.md
ai_src.py                         工作区 CLI 与薄编排器
config/                           通用和目标专用的端点提取配置
examples/                         scope、配置、发现/测试记录示例
payloads/src-payload/             本地 payload 与字典集合
reports/                          中文报告模板
scripts/                          安装脚本、爬虫、提取器
skills/                           核心规则、目标初始化、端点发现、端点测试
targets/<target>/                 目标 scope、原始数据、状态、记录和报告
tools/bin/                        可选的本地工具二进制或入口程序
tools/README.md                   工具安装和 wrapper 说明
```

## 环境准备

必需：

- Python 3.10+
- 能读取项目规则文件的代码 Agent CLI
- 浏览器 MCP 或等价的浏览器自动化与 Network 观察能力

推荐：

- Go：用于安装 `katana`、`ffuf`、`gau`
- Python/pip：用于安装 `ParamSpider`

安装依赖和工具：

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\scripts\install_tools.ps1
python ai_src.py tools
```

如果自动安装失败，查看：

```powershell
Get-Content .\tools\TO_DOWNLOAD.txt
```

## 推荐运行流程

1. 配好浏览器 MCP 或等价能力。
2. 安装 `katana`、`ffuf`、`gau`、`ParamSpider`，用 `python ai_src.py tools` 确认可用。
3. 运行初始化问答生成目标 scope、seed、config 和本地认证 profile。
4. 在项目根目录启动 Agent，把目标 prompt 复制进去。
5. Agent 首先阅读 `AGENTS.md`、`skills/` 和目标 `scope.md`，运行 `audit-target`。
6. 如果已有配置，Agent 给用户一次显式修改机会；如果缺配置，只问缺少的问题。
7. 问答结束后进入 loop：浏览器 Network 采样、HAR recipe、被动 URL、katana、crawl、extract、rank-js、endpoint testing、metrics/flywheel。
8. 找到可报告漏洞后写中文 report/finding，跑 gate，记录结果，然后继续剩余接口与攻击面。

## 创建目标

推荐使用快速向导：

```powershell
python ai_src.py init-target demo --wizard
```

默认向导只问核心字段：授权来源、测试身份、授权窗口、in-scope 域名/seed、IP/CIDR、App、环境、是否创建本地认证 profile、是否补充高级端点提取提示。

如果确实需要完整模板字段：

```powershell
python ai_src.py init-target demo --full-wizard
```

认证 profile 存在 `targets/<target>/auth.local.json`，该文件被 Git 忽略，供 Agent 自动化登录、带 cookie/token/header 发请求。Agent 需要读取时使用：

```powershell
python ai_src.py auth-profiles demo --show-secrets
python ai_src.py auth-set demo low --role "low privilege" --username low@example.test --password "..." --login-url https://www.example.com/login --cookie "..."
```

## 启动 Agent Prompt 示例

```text
Read AGENTS.md, skills/core.md, skills/target-setup.md,
skills/endpoint-discovery.md, skills/endpoint-testing.md, and
targets/demo/scope.md.

Operate only within scope for target demo.

At startup, run:
python ai_src.py audit-target demo --config demo

Summarize scope, config, auth profile names, wrappers, blockers,
and warnings. If there are no blockers and no user-requested changes,
start the soft SRCFlow loop.
```

## Loop A：爬取前采样

先用浏览器 MCP 访问授权范围内的代表性页面，观察 Network：

- API host、base path、URL pattern
- request wrapper、auth header、cookie 名称
- query key、body key、响应字段
- SPA route、JS chunk、静态资源 host
- 正常业务动作对应的请求与成功响应

导入 HAR 作为端点和正常请求 recipe：

```powershell
python ai_src.py import-har .\captures\demo.har --workspace-target demo --as-endpoints --as-recipes
python ai_src.py recipe-list demo
python ai_src.py recipe-run demo <recipe-id-or-method-path> --auth-profile low
```

## Loop B：被动 URL 与爬取

先用被动工具补充历史 URL 与参数：

```powershell
python ai_src.py gau-urls demo example.com --fp
python ai_src.py paramspider-urls demo example.com
```

输出：

- `targets/demo/state/gau_urls.txt`
- `targets/demo/state/paramspider_urls.txt`
- `targets/demo/state/passive_urls.txt`
- `targets/demo/state/passive_seeds.txt`
- `targets/demo/state/passive_params.json`

再用 katana 补 live URL：

```powershell
python ai_src.py katana-crawl demo https://www.example.com/ --depth 2
python ai_src.py katana-crawl demo https://app.example.com/ --profile routes -- -iqp
python ai_src.py katana-crawl demo https://app.example.com/ --profile headless-xhr -- -fx
```

校验配置并爬取：

```powershell
python ai_src.py validate-config demo
python ai_src.py crawl demo --config demo --depth 2 --threads 10 --mode pages
```

`crawl` 会自动消费 `state/katana_seeds.txt` 和 `state/passive_seeds.txt`，除非显式传入 `--no-katana-seeds` 或 `--no-passive-seeds`。

## Loop C：端点发现与测试

提取端点并排序高价值文件：

```powershell
python ai_src.py extract demo --config demo
python ai_src.py rank-js .\targets\demo\raw\remote_sites --limit 30
```

每个 endpoint family 先恢复正常业务流，再做安全变体。不要只对发现到的 URL 发一个裸请求就下结论。

记录正常流和端点测试：

```powershell
python ai_src.py log-flow demo "resource detail normal flow" --recipe <recipe-id> --status normal-flow-ok --param-sources "Network + list response id"
python ai_src.py log-test demo /api/resource/1 --base-url https://www.example.com --method GET --status needs-normal-flow
python ai_src.py log-test demo /api/resource/1 --base-url https://www.example.com --method GET --status rejected --params "id" --function detail --attack-surface IDOR --auth-context "low privilege" --actual "403"
```

`probe` 只产生状态信号，不等于端点测试：

```powershell
python ai_src.py probe demo --base-url https://www.example.com --method HEAD --limit 100
```

## ffuf-safe 与字典

字典在 [payloads/src-payload/](payloads/src-payload/) 下。使用前先读 [payloads/src-payload/README.md](payloads/src-payload/README.md)。

`ffuf-safe` 适合回答小而明确的 scoped 问题：相邻路径、隐藏 action、query 参数名、header 名/值、body key/value，或已有行为线索后的窄范围文件读取/注入探测。

```powershell
python ai_src.py ffuf-safe demo https://www.example.com/api/FUZZ .\payloads\src-payload\fuzzing\api-paths\api路径\API字典.txt --profile paths -- -fc 404 -ac
python ai_src.py ffuf-safe demo "https://www.example.com/api/search?FUZZ=test" .\payloads\src-payload\fuzzing\params\参数字典\web参数字典.txt --profile params -- -fc 404 -ac
python ai_src.py ffuf-safe demo https://www.example.com/api/search .\payloads\src-payload\fuzzing\params\参数字典\web参数字典.txt --auth-profile low --method POST --data '{"keyword":"FUZZ"}' --profile params -- -ac
```

候选结果必须人工验证，原始 ffuf 输出不能直接写成报告。

## Metrics 与 Flywheel

查看度量：

```powershell
python ai_src.py metrics demo
```

生成复盘：

```powershell
python ai_src.py flywheel demo
```

metrics/flywheel 是软提示，不是状态机。它们会提示 passive URL、recipe、flow、ffuf candidate、endpoint test、gate 等信号，但不能覆盖目标真实行为。

## 报告门控

最终漏洞报告必须是中文，且必须描述真实、可复现、有影响的问题。

```powershell
python ai_src.py gate .\targets\demo\reports\finding.md --target demo
```

报告必须包含授权范围、可复现 PoC/curl/命令、多 ID 或多参数验证、具体 C/I/A 影响、误报排除、修复建议。任何门控失败都继续测试，不输出漏洞结论。

## 常用命令

```text
init-target        创建目标工作区
audit-target       审计目标启动就绪度
status             查看目标状态
tools              检查本地工具可用性
auth-profiles      查看本地认证 profile
auth-set           创建或更新本地认证 profile
validate-config    校验配置 JSON 和正则
gau-urls           使用 gau 做被动 URL 发现
paramspider-urls   使用 ParamSpider 做参数化 URL 发现
katana-crawl       使用 katana 做 live URL 发现
crawl              爬取 HTML/JS 资源
extract            从已爬取文件中提取端点
rank-js            对已爬取 JS/HTML 进行人工审查排序
import-har         从 HAR 中提取 API 候选和请求 recipe
recipe-list        列出正常请求 recipe
recipe-run         重放一个正常请求 recipe
log-flow           记录正常业务流或变体流状态
log-test           记录结构化端点测试
probe              低风险状态探测
ffuf-safe          使用 ffuf 做窄范围 scoped fuzz
metrics            汇总被动度量
flywheel           写入软 loop 复盘笔记
checkpoint         追加压缩后的 loop 上下文
gate               校验中文报告质量门和目标 scope
diff-endpoints     比较两个 endpoints JSON
```

## 维护验证

修改项目代码或工作流文档后，至少运行：

```powershell
python -m py_compile .\ai_src.py .\scripts\download_remote_sites.py .\scripts\extract_remote_eps.py
python .\ai_src.py --help
python .\ai_src.py validate-config default
python .\ai_src.py tools
git diff --check
```
