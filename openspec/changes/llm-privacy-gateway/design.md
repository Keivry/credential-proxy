## Context

现状（见 proposal.md — Why）：脱敏是被动式（仅 `/credential` 注册的秘密被替换），输出侧零审计。

技术基线：
- `_llm.py`（1462 行）已完整适配 OpenAI chat/completions、Anthropic /v1/messages、Responses API 三种协议的 SSE 流式，含 token 分片累积还原（`content_buf`/`reasoning_buf`/`arg_buf`）与完成事件识别
- 完成事件现状：Anthropic `content_block_stop` → `block_stop`（清 arg_buf）；Responses `output_item.done` → `item_done`（清 arg_buf）；**OpenAI 格式 `delta.tool_calls` 无专门处理，走 'other'/整行透传分支，无分片累积**
- `_token.py` 提供 `_redact`/`_restore` 可逆替换与 `_register_secret` 注册
- `_matrix.py` 提供 `_ask` + pending requests + ✅/❎ reactions 审批基础设施
- 约束：Python 3.10 兼容（f-string 引号）、锁外网络 I/O、快照安全、全部新功能默认关闭、132 测试 + ruff 全绿

## Goals / Non-Goals

**Goals:**
- 在不改变现有转发链路行为的前提下，新增两个可独立开关的能力：PII 主动脱敏、输出安全审计
- PII 脱敏复用现有 token 机制（`_redact`/`_restore`），避免引入第二套替换体系
- 审计钩子挂在已有协议解析的完成事件上，保持流式体验不被破坏
- 阻断模式零人工干预；审批模式复用 Matrix 审批，与凭据审批体验一致

**Non-Goals:**
- 不引入 Presidio 等重依赖（作为 Phase 3 可选增强，独立 feature flag，不进默认镜像）
- 不做内容语义级「危险文本」检测（如模型直接输出 shell 代码文本而非 tool call）——属 Phase 3，规则风险高
- 不改 Hermes 端 custom provider 配置与 API 格式
- 不做多租户/用户级策略隔离（单用户自部署场景）

## Decisions

### D1: PII 检测引擎 — 规则/正则引擎优先，Presidio 可选

**决策**：Phase 1 内置轻量 recognizer 集（正则 + 校验位/上下文强化），零新增依赖；Phase 3 通过 feature flag 支持 Presidio AnalyzerEngine 作为增强检测器，实现统一的 `PiiDetector` 接口。

**理由**：目标 PII 类型（大陆身份证、手机号、邮箱、银行卡、IPv4、常见 API key 格式）都是强模式，正则可覆盖；Presidio 默认英文模型对中文 NER 效果有限，且 spaCy/transformers 依赖使 Docker 镜像膨胀、延迟 100ms+，与当前 μs 级替换不匹配。

**备选**：
- 全 Presidio：识别率更高，但中文场景收益有限、依赖重、延迟高
- 纯 LLM 检测：不引入（把 PII 发给 LLM 检测本身就违背目的，且不可控）

### D2: PII token 生命周期 — 请求级作用域 + TTL

**决策**：PII 检测出的值使用**请求级映射**（每请求新建 `pii_p2t`/`pii_t2p`），不写入全局 `pwd_to_token`；请求结束（响应完成/连接关闭）即清理。

**理由**：PII 是上下文相关的临时敏感值，永久注册会内存膨胀、跨请求串扰、且与凭据 token 语义混淆（凭据是「可信来源的长期秘密」，PII 是「对话中的临时值」）。请求级映射天然隔离，无需 FIFO 淘汰。

**备选**：写入全局映射 + TTL 过期——增加全局状态复杂度，且 PII 值在请求结束后无还原价值。

**细节**：token 格式用独立前缀（如 `__PII_PHONE_1__`）避免与 `__VG_CRED_*__` 撞车；`_restore` 时请求级映射优先、全局映射兜底，两套映射互不干扰。

### D3: 输出审计钩子 — 挂在已有完成事件上，OpenAI 格式补分片累积

**决策**：审计触发点对齐现有 arg_buf 完成事件：
- Anthropic：`block_stop`（已有，arg_buf 完整）
- Responses：`item_done`（已有，arg_buf 完整）
- OpenAI chat/completions：**新增** `delta.tool_calls` 分片累积（按 index 分组 `function.name` + `function.arguments`），在 `finish_reason == 'tool_calls'` 或流末触发审计

审计通过 → 原样继续；审计拦截 → 进入处置（D4）。审计是纯检查函数（`audit_tool_call(name, args_json) -> AuditVerdict`），不阻塞事件循环。

**理由**：三种协议都已有「工具调用参数完整」的语义边界，挂在这里语义最准、改动最小。OpenAI 格式是 Hermes 实际使用的路径（opencode-go 网关 OpenAI 兼容格式），必须补上才有意义。

**备选**：独立累积所有协议的 tool calls（重复造轮子）——不采用，完成事件已存在。

### D4: 处置模式 — 阻断（默认）与审批（可选）

**决策**：`AUDIT_MODE=block`（默认）：危险调用被替换为一条带说明的 assistant 拒绝消息（`content` 说明、无 `tool_calls`），客户端（Hermes）收到后不会执行工具，后续流正常继续。`AUDIT_MODE=approve`：挂起该 tool call 转发，通过 Matrix `_ask` 请求 ✅/❎，超时默认拒绝；批准后按原格式补发 tool call 事件。

**理由**：
- 阻断模式对 cron/无人值守场景安全（无人工依赖，不阻塞）
- 拒绝消息用「无 tool_calls 的 assistant content」是最兼容的注入形态——Hermes 按普通助手回复处理，不会尝试执行
- 审批模式复用 `_matrix.py` 现有 `_ask`/pending/超时机制，与凭据审批同构，改动小

**备选**：审批挂起整个 SSE 流（先不发任何内容直到审批结束）——延迟大、破坏流式体验；审批通过后重放——复杂且浪费。

**流式细节**：审批模式下，危险 tool call 的 delta 分片已缓冲未 flush，挂起后暂停该流的事件写入；批准后继续 flush 原格式事件。阻断模式下无需挂起，直接在完成点注入拒绝消息事件。

### D5: 配置 — 环境变量 + 可选策略文件

**决策**：
- `PII_REDACTION_ENABLED`（默认 off）、`PII_RESPONSE_SIDE`（默认 on，当 PII 功能开启时）
- `AUDIT_MODE`（`off`/`block`/`approve`，默认 `off`）、`AUDIT_TIMEOUT`（审批超时秒数，默认 120）
- `AUDIT_POLICY_FILE`（可选 YAML/JSON 策略文件路径；缺省用内置默认策略：危险 shell 命令模式、敏感路径、工具 deny 名单）

**理由**：保持与现有环境变量配置风格一致（`LLM_8878`/`GET_BINARY_HASH` 等），feature flag 默认关闭保证零侵入。

### D6: 代码结构 — 新增两个 Mixin + 策略数据独立

**决策**：
- `_pii.py`：`PiiMixin`（检测器注册表、`detect_and_redact`/`restore`、请求级映射生命周期管理）
- `_audit.py`：`AuditMixin`（策略加载、`audit_tool_call`、阻断/审批处置、审计日志持久化）
- 审计日志：追加写 `DATA_DIR/audit.log`（JSON Lines），与现有 `caller_registry.json` 同目录风格
- `proxy.py` 组合新 Mixin（`CredentialProxy(PiiMixin, AuditMixin, ...)`）；轻量入口按需引入

**理由**：延续 Mixin 拆分模式（7 文件 → 9 文件），职责单一、可独立测试、轻量入口（llm-proxy-only）可只引入 PiiMixin。

## Risks / Trade-offs

- **PII 误报**（11 位数字可能是订单号）→ 只对高置信模式脱敏（如身份证含校验位验证、手机号前缀段验证）；误报代价仅为模型看到占位符，响应侧还原后用户无感
- **PII 漏报**（新格式/上下文型 PII 检测不到）→ 规则引擎覆盖已知强模式；Phase 3 Presidio 增强兜底
- **OpenAI tool_calls 分片累积新增路径的 bug 风险** → 参照 anthropic/responses 已修复的坑（跨块伪还原、null 值、`_PARTIAL_TOKEN_RE` 清理），补集成测试；沿用「跨协议对称审计铁律」
- **审批模式下流挂起**：挂起期间其他事件（如后续 content delta）处理 → 设计为「按事件序挂起」：危险 tool call 之前的 content 已 flush，之后的 content 也缓冲等待，审批完成统一放行/替换。超时默认拒绝避免永久挂起
- **阻断注入的兼容性**：Hermes 可能对「无 tool_calls 的 assistant 消息」的 finish_reason 语义有依赖 → 注入消息保持合法协议结构（`finish_reason: stop`），验证 Hermes 实际行为后调整
- **审计日志含敏感信息** → 只记参数摘要（截断 + 脱敏），不记完整参数值

## Migration Plan

1. 开发按 Phase 顺序：D2 请求级 PII token 机制 → D1 检测器 → D3 审计钩子 → D4 处置 → D5 配置
2. 全部功能默认关闭，先跑全量测试（132 + 新增），再在 llm-proxy-only 本地验证
3. 部署：Docker 镜像 tag 升级（v0.9.x），环境变量按需开启；回滚 = 关闭 feature flag 或回退镜像 tag，无数据迁移
4. Hermes 端零改动（custom provider 配置不变）

## Open Questions

- OpenAI 格式下 `finish_reason == 'tool_calls'` 是否在所有上游（opencode-go 网关透传 DeepSeek）都可靠出现——若不可靠，改用流末 `[DONE]` 前统一审计（实现时用真实流量验证）
- 阻断注入的「拒绝消息」是否需要特殊前缀让 Hermes 明确识别为策略拒绝（而非普通助手回复）——实现时观察 Hermes 行为决定
