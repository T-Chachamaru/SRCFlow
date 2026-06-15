# SRCFlow

这是一个运行在 Codex、Claude Code、Gemini CLI 等现有 Agent CLI 之上的 SRC 工作区。提供：

- 通用 Agent 初始化提示词。
- 目标 scope 和配置模板。
- HTML/JS 爬取与端点提取脚本。
- 外部安全工具 wrapper。
- 端点发现、端点验证、报告门控的循环流程。

除 `README.md` 外，仓库内项目文件默认使用英文；最终漏洞报告和 `reports/template.md` 使用中文。

## 快速开始

完整使用方式是：**配好目标 scope 和 config，安装依赖与工具，在项目根目录启动 Agent CLI，然后让 Agent 按本项目流程开始漏洞挖掘**。

### 1. 准备运行环境

必需：

- Python 3.10+。
- 一个支持读取项目初始化文件的 Agent CLI，例如 Codex、Claude Code、Gemini CLI。
- Agent CLI 中已经配置可用的浏览器 MCP，或等价的浏览器自动化与 Network 观察能力。

推荐：

- Go，用于安装 ProjectDiscovery、ffuf 等工具。

安装 Python 依赖：

```powershell
python -m pip install -r requirements.txt
```

安装或刷新外部 CLI：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_tools.ps1
python ai_src.py tools
```

如果安装失败，查看：

```powershell
Get-Content .\tools\TO_DOWNLOAD.txt
```

然后把对应 exe 手工放到 `tools/bin`。

### 2. 初始化目标

示例：

```powershell
python ai_src.py init-target demo --domain example.com --seed https://www.example.com/ --config default
```

然后必须手工填写或确认：

- `targets/demo/scope.md`
- `targets/demo/domains.txt`
- `targets/demo/seeds.txt`
- `config/demo.json`

`scope.md` 只写授权边界：授权来源、测试窗口、域名/IP/APP 范围、禁区、测试账号、速率限制、证据脱敏规则。

参考文件：

- [examples/scope.example.md](examples/scope.example.md)
- [examples/target-config.example.json](examples/target-config.example.json)
- [targets/_template/scope.md](targets/_template/scope.md)

### 3. 在项目根目录启动 Agent CLI

在 项目根目录下启动你的 Agent CLI。项目入口文件如下：

- `AGENTS.md`：通用规则源。
- `CLAUDE.md`：Claude Code 入口，指向 `AGENTS.md`。
- `GEMINI.md`：Gemini CLI 入口，指向 `AGENTS.md`。

适配其他 Agent CLI 时，新增一个该工具会自动读取的薄入口文件即可，内容只需要指向 `AGENTS.md`，不要复制规则正文。

### 4. 给 Agent 的启动提示词

推荐在 Agent CLI 里直接输入：

```text
Read AGENTS.md, skills/core.md, skills/endpoint-discovery.md, skills/endpoint-testing.md, and targets/demo/scope.md.

Operate only within scope. Start the AI SRC workflow for target demo:
1. Use browser MCP for Network sampling before crawling.
2. Collect API hosts, domain keywords, URL patterns, request wrappers, auth headers, query keys, body keys, and SPA routes.
3. Update config/demo.json.
4. Validate config.
5. Crawl HTML/JS.
6. Extract endpoints.
7. Iterate endpoint discovery with snapshots and diff-endpoints until convergence.
8. Test endpoint families through the endpoint-testing loop.
9. Use tool wrappers only as scoped low-rate signal generators.
10. Only write Chinese vulnerability reports that pass the seven gates.
```

把 `demo` 换成你的目标名。

## Agent 会执行的主流程

### 阶段 A：浏览器 MCP 采样

Agent 会先读 `targets/<target>/scope.md`，再用浏览器 MCP 访问授权范围内的种子域名、SPA 路由和 HTML 页面。目标是从 Network 和页面行为中收集：

- API host、域名关键词、网关域名。
- base path、URL path 模式、版本前缀。
- 静态资源 host、JS chunk 命名模式、source map 线索。
- 请求封装函数、动态 path 拼接方式。
- auth header、cookie 名称、query key、JSON body key。
- 能引出更多页面的 SPA route。

授权允许时，Agent 可以通过 wrapper 补充入口：

```powershell
python ai_src.py subdomains demo example.com
python ai_src.py httpx-live demo .\targets\demo\state\subdomains.txt
python ai_src.py katana-crawl demo https://www.example.com/ --depth 2
```

这些工具输出只能作为线索。

### 阶段 B：配置并爬取

Agent 会把采样结果写入 `config/<target>.json`，重点字段包括：

- `target_keywords`
- `extra_seeds`
- `api_prefixes`
- `api_path_regexes`
- `extract_patterns`
- `known_endpoints`
- `garbage_substrings`

校验配置：

```powershell
python ai_src.py validate-config demo
```

爬取 HTML/JS：

```powershell
python ai_src.py crawl demo --config demo --depth 2 --threads 10 --mode pages
```

带登录态时只通过运行时参数传入，不写文件：

```powershell
python ai_src.py crawl demo --config demo --cookie "SESSION=REDACTED"
```

### 阶段 C：端点发现循环

每轮执行：

```powershell
python ai_src.py extract demo --config demo
python ai_src.py rank-js .\targets\demo\raw\remote_sites --limit 30
```

Agent 会阅读：

- `targets/demo/state/endpoints.json`
- 高价值 JS/HTML 文件
- 浏览器 MCP Network 记录
- HAR 或工具输出中的 API 线索

如果发现遗漏，就补 `config/demo.json`，再次运行 `extract`。`extract` 会自动在 `targets/demo/state/snapshots/` 生成前后快照，并打印可直接执行的 `diff-endpoints` 命令。

两轮新增内容只剩重复、已知端点或低价值误报时，端点发现才算收敛。

### 阶段 D：逐端点验证循环

Agent 会按端点族执行：

1. 参数寻找：JS/HTML、Network/HAR、query、body、响应字段。
2. 功能判断：列表、详情、导出、上传、删除、更新、管理、登录、搜索等。
3. 攻击面思考：未授权访问、IDOR、垂直越权、租户隔离、文件访问、注入、上传校验、流程绕过、敏感信息泄露。
4. 安全验证：只用授权账号和最少请求。
5. 记录结果：confirmed、rejected、needs account、needs more context、out of scope。
6. 反思结果：决定下一个端点或是否回到配置迭代。

低风险探测：

```powershell
python ai_src.py probe demo --base-url https://www.example.com --method HEAD --limit 100
```

HAR 辅助输入：

```powershell
python ai_src.py import-har .\captures\demo.har --target example.com --as-endpoints
```

保守 fuzz：

```powershell
python ai_src.py ffuf-safe demo https://www.example.com/FUZZ .\wordlists\paths.txt
```

保守 nuclei：

```powershell
python ai_src.py nuclei-safe demo https://www.example.com
```

`ffuf-safe` 和 `nuclei-safe` 的输出不能直接写报告，必须进入“线索 -> 手工验证 -> 报告门控”的链路。

## 常用命令

查看目标状态：

```powershell
python ai_src.py status demo
```

写入上下文检查点：

```powershell
python ai_src.py checkpoint demo --direction "endpoint discovery" --tested "..." --findings "..." --next "..."
```

比较两轮端点：

```powershell
python ai_src.py diff-endpoints .\targets\demo\state\snapshots\endpoints-before-xxx.json .\targets\demo\state\snapshots\endpoints-after-xxx.json
```

报告门控：

```powershell
python ai_src.py gate .\targets\demo\reports\finding.md
```

## 输出位置

- `targets/<target>/raw/remote_sites/`：爬取到的 HTML/JS/manifest/links。
- `targets/<target>/state/endpoints.json`：当前提取出的 API 端点。
- `targets/<target>/state/snapshots/`：每次提取自动生成的端点快照。
- `targets/<target>/state/subdomains.txt`：`subfinder` wrapper 输出。
- `targets/<target>/state/live_hosts.jsonl`：`httpx` wrapper 输出。
- `targets/<target>/state/katana_urls.txt`：`katana` wrapper 输出。
- `targets/<target>/state/probe_results.json`：低风险端点探测结果。
- `targets/<target>/reports/`：最终中文报告。

## 改造项目

优先改配置。

- 通用规则源：[AGENTS.md](AGENTS.md)。
- 核心提示词：[skills/core.md](skills/core.md)。
- 端点发现流程：[skills/endpoint-discovery.md](skills/endpoint-discovery.md)。
- 逐端点验证流程：[skills/endpoint-testing.md](skills/endpoint-testing.md)。
- 端点提取脚本：[scripts/extract_remote_eps.py](scripts/extract_remote_eps.py)。
- 爬取脚本：[scripts/download_remote_sites.py](scripts/download_remote_sites.py)。
- 工作区 CLI：[ai_src.py](ai_src.py)。
- 配置示例：[examples/target-config.example.json](examples/target-config.example.json)。

改完至少运行：

```powershell
python -m py_compile .\ai_src.py .\scripts\download_remote_sites.py .\scripts\extract_remote_eps.py
python .\ai_src.py --help
python .\scripts\download_remote_sites.py --help
python .\scripts\extract_remote_eps.py --help
python .\ai_src.py validate-config default
```

## 报告要求

最终漏洞报告是中文，且必须通过 7 道验证门：

- 有可复现 PoC、curl 或可执行命令。
- 报告真实安全影响，不报告现象。
- 多 ID 或多参数验证，或说明限制。
- 全部操作在授权范围内。
- 排除 CORS、安全头、版本泄露、Self-XSS 等误报。
- 尝试跨接口参数迁移，或说明不适用。
- C/I/A 影响具体。

不通过门控时继续测试，不输出漏洞结论。
