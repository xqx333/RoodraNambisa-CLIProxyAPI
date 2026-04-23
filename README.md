# CLI 代理 API

一个为 CLI 提供 OpenAI/Gemini/Claude/Codex 兼容 API 接口的代理服务器。

现已支持通过 OAuth 登录接入 OpenAI Codex（GPT 系列）和 Claude Code。

你可以使用本地或多账户的 CLI 方式，通过任何与 OpenAI（包括 Responses）/Gemini/Claude 兼容的客户端和 SDK 进行访问。

## 本分支与上游主分支的区别

当前分支在上游主线基础上额外维护了下面这些能力：

- 增加了账号自动处理能力：
  - 支持把明显失效的账号自动停用并排队删除
  - 支持对反复撞额度的账号自动禁用，或者达到阈值后自动清理
- 增加了使用统计持久化：
  - 使用统计会落盘到日志目录
  - 启动时自动恢复
  - 删除账号时同步删除对应统计
  - 定期对账修正统计和账号不同步的问题
- 增加了新路由策略：
  - `routing.strategy=random`
  - 同优先级内随机选择账号
  - 重试时降到下一档可用优先级
- 强化了内部入口和本地访问限制：
  - Gemini CLI 内部接口默认受开关控制
  - 需要 API key
  - 只允许本机回环地址访问
- 补了 Responses WebSocket / Codex WebSocket 一致性修复：
  - tool repair 并发安全
  - transcript 修补
  - session 生命周期收口
- 补了高并发下的调度和更新优化：
  - 账号更新先进入内存
  - 慢的模型同步放到后台
  - scheduler 热路径减少锁竞争
- 补了使用统计里的 `client_ip` 统一口径：
  - HTTP 日志和 usage 统计共用同一套解析规则
  - 快照合并去重把 `client_ip` 也纳入判断
- 增加了 Codex-backed OpenAI Images 兼容层：
  - 支持 `POST /v1/images/generations`
  - 支持 `POST /v1/images/edits`
  - 官方 Images 请求会转换为 Codex Responses 的 `image_generation` tool 调用

如果你是从上游主线迁移到这个分支，优先关注这些配置项：

- `auth-maintenance`
- `usage-statistics-persist-interval-seconds`
- `routing.strategy`
- `enable-gemini-cli-endpoint`


## 功能特性

- 为 CLI 模型提供 OpenAI/Gemini/Claude/Codex 兼容的 API 端点
- 支持 OpenAI Codex（GPT 系列）OAuth 登录
- 支持 Claude Code OAuth 登录
- 支持 Amp CLI 与 IDE 扩展的 provider 路由
- 支持流式与非流式响应
- 支持函数调用 / 工具调用
- 支持多模态输入（文本、图片）
- 支持通过 Codex 账号代理 OpenAI Images 生成 / 编辑接口
- 支持 Gemini / AI Studio / Claude Code / OpenAI Codex 多账户负载均衡
- 支持 Generative Language API Key
- 支持 OpenAI 兼容上游提供商接入
- 提供可复用的 Go SDK

## OpenAI Images 兼容接口

本分支提供 Codex-backed OpenAI Images 兼容层。客户端按官方 OpenAI Images API 请求配置的图片模型时，服务端会自动转换为 Codex Responses 请求：外层模型默认使用 `gpt-5.4`，并通过 `image_generation` tool 调用图片模型。默认图片模型是 `gpt-image-2`。

支持的接口：

- `POST /v1/images/generations`
- `POST /v1/images/edits`

配置项：

```yaml
images:
  codex-model: "gpt-5.4"
  image-model: "gpt-image-2"
  enable-n-aggregation: false
  unsupported-status-code: 400
  override-response-format-url: false
  response-format-url-data-url: false
  override-transparent-background: false
  override-input-fidelity: false
```

说明：

- `model` 默认支持 `gpt-image-2`；如需换成其他 Codex 支持的图片 tool 模型，修改 `images.image-model`，请求里的 `model` 也要使用同一个值。
- `response_format=url` 默认不支持，请求传入 `url` 会直接返回错误。开启 `override-response-format-url` 后会自动按 `b64_json` 处理；开启 `response-format-url-data-url` 后会把图片 base64 包装成 `data:<mime>;base64,...` 放到 `url` 字段返回。
- `background=transparent` 默认保持上游兼容行为，会原样透传给 Codex；开启 `override-transparent-background` 后会自动改成 `auto` 再转发给 Codex。
- `input_fidelity` 默认保持上游兼容行为，会原样透传给 Codex；实测 `gpt-image-2` 会返回 `invalid_input_fidelity_model`。开启 `override-input-fidelity` 后，所有图片请求都会自动不透传该字段。
- `edits` 支持 multipart 的 `image` / `image[]` / `mask`，也支持 JSON 的 `images[].image_url`。
- 暂不支持 JSON `file_id`，因为当前项目没有 OpenAI Files API 兼容层。
- `unsupported-status-code` 控制不支持参数的错误状态码，默认 `400`。
- `override-response-format-url`、`response-format-url-data-url`、`override-transparent-background` 和 `override-input-fidelity` 默认关闭，分别控制对应参数覆盖；其它不支持参数仍会返回错误。
- `override-unsupported-params` 是旧兼容字段，开启时等价于支持的覆盖项都开启；新配置建议使用上面的独立开关。
- `enable-n-aggregation` 默认关闭，`n > 1` 会直接按不支持参数返回错误。开启时，`n > 1` 会拆成多次 Codex 图片调用再聚合，非流式返回多个 `data[]` 并累加 `usage.output_tokens` 等用量字段；流式依次输出多个 `image_generation.completed` 或 `image_edit.completed` 事件。

示例：

```bash
curl http://127.0.0.1:8317/v1/images/generations \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-image-2",
    "prompt": "一只橘猫坐在赛博朋克风格的窗台上",
    "size": "1024x1024",
    "quality": "high",
    "n": 1,
    "response_format": "b64_json"
  }'
```

## 新手入门

CLIProxyAPI 用户手册：[https://help.router-for.me/cn/](https://help.router-for.me/cn/)

## 管理 API 文档

请参见 [MANAGEMENT_API_CN.md](https://help.router-for.me/cn/management/api)

### 管理端访问路径隐藏

如果不希望管理页面和登录/OAuth 入口暴露在固定路径上，可以在配置中设置自定义路径段：

```yaml
remote-management:
  secret-key: "your-management-key"
  access-path: "my-random-path"
```

设置后管理页面会移动到 `/my-random-path/management.html`，管理 API 会移动到 `/my-random-path/v0/management/...`，OAuth 回调也会使用 `/my-random-path/{provider}/callback`。`access-path` 只是路径隐藏，不替代 `secret-key`，管理 API 仍然需要管理密钥。

## Amp CLI 支持

CLIProxyAPI 已内置对 [Amp CLI](https://ampcode.com) 和 Amp IDE 扩展的支持，可让你使用自己的 Google/ChatGPT/Claude OAuth 订阅来配合 Amp 编码工具：

- 提供商路由别名，兼容 Amp 的 API 路径模式：`/api/provider/{provider}/v1...`
- 管理代理，处理 OAuth 认证和账号功能
- 智能模型回退与自动路由
- 以安全为先的设计，管理端点仅限 localhost

当你需要某一类后端的请求 / 响应协议形态时，优先使用 provider-specific 路径，而不是合并后的 `/v1/...` 端点：

- 对于 messages 风格的后端，使用 `/api/provider/{provider}/v1/messages`
- 对于按模型路径暴露生成接口的后端，使用 `/api/provider/{provider}/v1beta/models/...`
- 对于 chat-completions 风格的后端，使用 `/api/provider/{provider}/v1/chat/completions`

这些路径有助于选择协议表面，但当多个后端复用同一个客户端可见模型名时，它们本身并不能保证唯一的推理执行器。实际的推理路由仍然根据请求里的 `model` / `alias` 解析。若要严格固定某个后端，请使用唯一 alias、前缀，或避免多个后端暴露相同的客户端模型名。

**→ [Amp CLI 完整集成指南](https://help.router-for.me/cn/agent-client/amp-cli.html)**

## SDK 文档

- 使用文档：[docs/sdk-usage_CN.md](docs/sdk-usage_CN.md)
- 高级（执行器与翻译器）：[docs/sdk-advanced_CN.md](docs/sdk-advanced_CN.md)
- 认证：[docs/sdk-access_CN.md](docs/sdk-access_CN.md)
- 凭据加载 / 更新：[docs/sdk-watcher_CN.md](docs/sdk-watcher_CN.md)
- 自定义 Provider 示例：`examples/custom-provider`

## 贡献

欢迎贡献，欢迎提交 Pull Request。

1. Fork 仓库
2. 创建功能分支：`git checkout -b feature/amazing-feature`
3. 提交更改：`git commit -m 'Add some amazing feature'`
4. 推送分支：`git push origin feature/amazing-feature`
5. 打开 Pull Request

## 谁与我们在一起

这些项目基于 CLIProxyAPI：

### [vibeproxy](https://github.com/automazeio/vibeproxy)

一个原生 macOS 菜单栏应用，让你可以使用 Claude Code 与 ChatGPT 订阅服务和 AI 编程工具，无需 API 密钥。

### [Subtitle Translator](https://github.com/VjayC/SRT-Subtitle-Translator-Validator)

一款基于浏览器的 SRT 字幕翻译工具，可通过 CLIProxyAPI 使用 Gemini 订阅，内置自动验证与错误修正功能，无需 API 密钥。

### [CCS (Claude Code Switch)](https://github.com/kaitranntt/ccs)

CLI 封装器，用于通过 CLIProxyAPI OAuth 即时切换多个 Claude 账户和替代模型（Gemini、Codex、Antigravity），无需 API 密钥。

### [Quotio](https://github.com/nguyenphutrong/quotio)

原生 macOS 菜单栏应用，统一管理 Claude、Gemini、OpenAI 和 Antigravity 订阅，提供实时配额追踪和智能自动故障转移，支持 Claude Code、OpenCode 和 Droid 等 AI 编程工具，无需 API 密钥。

### [CodMate](https://github.com/loocor/CodMate)

原生 macOS SwiftUI 应用，用于管理 CLI AI 会话（Codex、Claude Code、Gemini CLI），提供统一的提供商管理、Git 审查、项目组织、全局搜索和终端集成。集成 CLIProxyAPI 为 Codex、Claude、Gemini 和 Antigravity 提供统一的 OAuth 认证，支持内置和第三方提供商通过单一代理端点重路由。

### [ProxyPilot](https://github.com/Finesssee/ProxyPilot)

原生 Windows CLIProxyAPI 分支，集成 TUI、系统托盘及多服务商 OAuth 认证，专为 AI 编程工具打造。

### [Claude Proxy VSCode](https://github.com/uzhao/claude-proxy-vscode)

一款 VSCode 扩展，提供在 VSCode 中快速切换 Claude Code 模型的能力，内置 CLIProxyAPI 作为后端，支持后台自动启动和关闭。

### [ZeroLimit](https://github.com/0xtbug/zero-limit)

Windows 桌面应用，基于 Tauri + React 构建，用于通过 CLIProxyAPI 监控 AI 编程助手配额。支持跨 Gemini、Claude、OpenAI Codex 和 Antigravity 账户的使用量追踪，提供实时仪表盘、系统托盘集成和一键代理控制。

### [CPA-XXX Panel](https://github.com/ferretgeek/CPA-X)

面向 CLIProxyAPI 的 Web 管理面板，提供健康检查、资源监控、日志查看、自动更新、请求统计与定价展示，支持一键安装与 systemd 服务。

### [CLIProxyAPI Tray](https://github.com/kitephp/CLIProxyAPI_Tray)

Windows 托盘应用，基于 PowerShell 脚本实现，不依赖任何第三方库。主要功能包括：自动创建快捷方式、静默运行、密码管理、通道切换（Main / Plus）以及自动下载与更新。

### [霖君](https://github.com/wangdabaoqq/LinJun)

霖君是一款用于管理 AI 编程助手的跨平台桌面应用，支持 macOS、Windows、Linux。统一管理 Claude Code、Gemini CLI、OpenAI Codex 等 AI 编程工具，本地代理实现多账户配额跟踪和一键配置。

### [CLIProxyAPI Dashboard](https://github.com/itsmylife44/cliproxyapi-dashboard)

一个面向 CLIProxyAPI 的现代化 Web 管理仪表盘，基于 Next.js、React 和 PostgreSQL 构建。支持实时日志流、结构化配置编辑、API Key 管理、Claude / Gemini / Codex 的 OAuth 提供方集成、使用量分析、容器管理，并可通过配套插件与 OpenCode 同步配置。

### [All API Hub](https://github.com/qixing-jk/all-api-hub)

用于一站式管理 New API 兼容中转站账号的浏览器扩展，提供余额与用量看板、自动签到、密钥一键导出到常用应用、网页内 API 可用性测试，以及渠道与模型同步和重定向。支持通过 CLIProxyAPI Management API 一键导入 Provider 与同步配置。

### [Shadow AI](https://github.com/HEUDavid/shadow-ai)

Shadow AI 是一款专为受限环境设计的 AI 辅助工具，提供无窗口、无痕迹的隐蔽运行方式，并通过局域网实现跨设备的 AI 问答交互与控制。

### [ProxyPal](https://github.com/buddingnewinsights/proxypal)

跨平台桌面应用（macOS、Windows、Linux），以原生 GUI 封装 CLIProxyAPI。支持连接 Claude、ChatGPT、Gemini、GitHub Copilot 及自定义 OpenAI 兼容端点，具备使用分析、请求监控和热门编程工具自动配置功能，无需手动管理 API Key。

### [CLIProxyAPI Quota Inspector](https://github.com/AllenReder/CLIProxyAPI-Quota-Inspector)

上手即用的 CLIProxyAPI 跨平台配额查询工具，支持按账号展示 Codex 5h / 7d 配额窗口、按计划排序、状态着色及多账号汇总分析。

> [!NOTE]
> 如果你开发了基于 CLIProxyAPI 的项目，请提交一个 PR 将其添加到此列表中。

## 更多选择

以下项目是 CLIProxyAPI 的移植版或受其启发：

### [9Router](https://github.com/decolua/9router)

基于 Next.js 的实现，灵感来自 CLIProxyAPI，易于安装使用；自研格式转换（OpenAI / Claude / Gemini / Ollama）、组合系统与自动回退、多账户管理（指数退避）、Next.js Web 控制台，并支持 Cursor、Claude Code、Cline、RooCode 等 CLI 工具。

### [OmniRoute](https://github.com/diegosouzapw/OmniRoute)

一个面向多供应商大语言模型的 AI 网关，提供兼容 OpenAI 的端点，具备智能路由、负载均衡、重试及回退机制。通过添加策略、速率限制、缓存和可观测性，确保推理过程既可靠又具备成本意识。

> [!NOTE]
> 如果你开发了 CLIProxyAPI 的移植或衍生项目，请提交 PR 将其添加到此列表中。

## 许可证

此项目根据 MIT 许可证授权，详细信息请参阅 [LICENSE](LICENSE)。

## 写给所有中国网友的

QQ 群：188637136（满）、1081218164

或

Telegram 群：https://t.me/CLIProxyAPI
