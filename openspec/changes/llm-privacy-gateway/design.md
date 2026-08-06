## Context

现状（见 proposal.md — Why）：脱敏是被动式（仅 `/credential` 注册的秘密被替换），输出侧零审计。

技术基线：
- `_llm.py`（1502 行）已完整适配 OpenAI chat/completions、Anthropic /v1/messages、Responses API 三种协议的 SSE 流式，含 token 分片累积还原（`content_buf`/`reasoning_buf`/`arg_buf`）与完成事件识别
- 完成事件现状：Anthropic `content_block_stop` → `block_stop`（清 arg_buf）；Responses `output_item.done` → `item_done`（清 arg_buf）；**OpenAI 格式 `delta.tool_calls` 无专门处理，走 'other'/整行透传分支，无分片累积**
- `_token.py` 提供 `_redact`/`_restore` 可逆替换与 `_register_secret` 注册
- `_matrix.py` 提供 `_ask` + pending requests + ✅/❎ reactions 审批基础设施（reaction 处理器**无发送者白名单校验**，审批加固见 D4）
- 约束：Python 3.10 兼容（f-string 引号）、锁外网络 I/O、快照安全、全部新功能默认关闭、146 测试 + ruff 全绿

## Goals / Non-Goals

**Goals:**
- 在不改变现有转发链路行为的前提下，新增两个可独立开关的能力：PII 主动脱敏、输出安全审计
- PII 脱敏复用现有 token 机制（`_redact`/`_restore`），避免引入第二套替换体系
- 审计钩子挂在已有协议解析的完成事件上，保持流式体验不被破坏
- 阻断模式零人工干预；审批模式复用 Matrix 审批，与凭据审批体验一致

**Non-Goals:**
- 不引入 Presidio 等重依赖（作为 Phase 3 可选增强，独立 feature flag，不进默认镜像）
- 不做内容语义级「危险文本」检测（如模型直接输出 shell 代码文本而非 tool call）——属 Phase 3，规则风险高。**防护边界声明**：规则引擎（正则 + 规范化匹配）提供「防意外、不防对抗」的基线防护；对有意对抗的上游（同形字、深度混淆、动态构造）不作对抗级保证，该边界在策略文件与 README 明示
- 不改 Hermes 端 custom provider 配置与 API 格式
- 不做多租户/用户级策略隔离（单用户自部署场景）

## Decisions

### D1: PII 检测引擎 — 规则/正则引擎优先，Presidio 可选

**决策**：Phase 1 内置轻量 recognizer 集（正则 + 校验位/上下文强化），零新增依赖；Phase 3 通过 feature flag 支持 Presidio AnalyzerEngine 作为增强检测器，实现统一的 `PiiDetector` 接口。

**理由**：目标 PII 类型（大陆身份证、手机号、邮箱、银行卡、IPv4、常见 API key 格式）都是强模式，正则可覆盖；Presidio 默认英文模型对中文 NER 效果有限，且 spaCy/transformers 依赖使 Docker 镜像膨胀、延迟 100ms+，与当前 μs 级替换不匹配。

**备选**：
- 全 Presidio：识别率更高，但中文场景收益有限、依赖重、延迟高
- 纯 LLM 检测：不引入（把 PII 发给 LLM 检测本身就违背目的，且不可控）

**检测字段范围（请求/响应两侧统一）**：请求侧扫描 `messages[].content`（字符串与数组 parts）、system prompt、历史 tool_calls 参数与 tool 结果；响应侧扫描 content、reasoning_content 与 tool 参数 delta。**图片 base64 data URL 必须排除**（对 base64 跑手机号/IP 正则误报后掩码会损坏图像数据）；检测粒度按解析后字段级，JSON 解析失败走透传分支的事件按整行 text-level 兜底。

### D2: PII token 生命周期 — 请求级作用域 + TTL

**决策**：PII 检测出的值使用**请求级映射**（每请求新建 `pii_p2t`/`pii_t2p`），不写入全局 `pwd_to_token`；请求结束（响应完成/连接关闭）即清理。

**理由**：PII 是上下文相关的临时敏感值，永久注册会内存膨胀、跨请求串扰、且与凭据 token 语义混淆（凭据是「可信来源的长期秘密」，PII 是「对话中的临时值」）。请求级映射天然隔离，无需 FIFO 淘汰。

**备选**：写入全局映射 + TTL 过期——增加全局状态复杂度，且 PII 值在请求结束后无还原价值。

**细节**：token 格式用独立前缀（示意格式 `__PII_000001__`——**实际格式含随机段，见下，此处仅为形态示意**；与 `__VG_CRED_NNNNNN__` 同构，不含类型段）避免与 `__VG_CRED_*__` 撞车；`_restore` 时请求级映射优先、全局映射兜底，两套映射互不干扰。**必须为 `__PII_` 前缀新增等价的流式分片残缺清理正则**（仿照 `_PARTIAL_TOKEN_RE` 但独立于凭据版本，不得共用/直接 import 凭据正则）——否则 PII token 在分片边界被切断时（如只收到 `__PII_0000`）残缺片段会随 SSE 透传给客户端，正是该机制要防的泄漏。

**还原/再检测顺序（响应侧，硬性）**：响应转发路径按「**还原 → 响应侧检测 → 转发**」执行——先 `_restore` 还原请求级占位符，再对还原后文本做响应侧 PII 检测，且检测时**跳过 `pii_p2t` 中已存在的值**（请求侧已脱敏、刚被还原的明文不得被再次掩码为新占位符，否则客户端收到占位符而非原文，违背「还原后与原文一致」）；新检测到的值注册到**实时请求级映射**（注意：请求时快照构建于 request 期，不含响应期注册，需查实时映射去重）。**skip 判定按规范化等价匹配**（去除常见分隔符后比对，如带分隔符的 `138-XXXX-5678` 与连续 `138XXXX5678` 视为同值）——否则模型回显时变形（加分隔符/拼接前后缀）会被当作新值二次掩码，客户端收到不可还原占位符。「还原后与原文一致」保证**仅适用于请求期注册值**；响应期新检测 PII 以占位符呈现（响应接收方即 PII 所有者，属预期，不承诺还原）。禁止「先检测后还原」或「还原后不再检测」两种错误顺序——后者会让模型回显的占位符被无条件还原为明文，形成「prompt injection → 模型回显 `__PII_NNNNNN__` → 还原为明文 → 泄漏」完整路径。

**token 不可预测性**：序号连续递增使占位符可枚举（日志/调试输出出现占位符即可推断本请求脱敏数量与顺序）——token 序号使用请求级**随机段**，格式固定为 `__PII_<seq>_<rand4>__`（seq 为请求内递增序号、rand4 为 4 位十六进制随机段；**不采用纯随机无序号方案**——同请求多值需确定性区分，纯随机 6 位 hex 在 ~1000 值规模有碰撞风险）；`_restore` 只还原本请求映射中存在的 token：序号越界/格式不符的一律**原样保留并记审计事件**（不报错、不丢弃、不查全局兜底猜测还原）。

**PII 与全局映射隔离**：PII token 的 `_restore` 路径**禁止触达全局凭据映射**（代码层面隔离，不共用查询函数）；「PII 永不写入全局映射」加测试断言。全局兜底只适用于凭据 token 形态（`__VG_CRED_*__`）。**凭据回显放大路径加固**：`_llm.py` 现有 `used_tokens` 收集（~L581-588）用 `TOKEN_RE` 匹配任意 token 形态，prompt 中字面量 `__VG_CRED_000001__` 会被误拉入 active_t2p → 模型回显后被全局兜底还原为明文——本 change 同时加固：`used_tokens` **仅收集本次请求实际注册产生的 token**（凭据注册表命中 + PII 请求级映射），不收集任意形态匹配；加固后「prompt 字面量 → 回显 → 还原」放大路径关闭。

**明文 PII 分片累积（响应侧）**：spec 要求「跨分片切断的明文 PII 由分片累积机制处理」——SSE 分片可能在 11 位手机号/18 位身份证中间切断，单块检测命中不了。实现：按协议字段维护**滑动窗口缓冲**（复用 content_buf 同款机制，安全部分逐块 flush、尾部持有 `_split_safe_hold` 同款判定）：窗口内拼接后跑 recognizer，命中即注册+掩码；断连时 `byte_buf` 残余部分行按「不完整明文」处理（不泄漏、不强行匹配）；检测粒度按**解析后字段级**（content/reasoning/tool 参数分别累积），字段级解析失败的事件（JSON 解析失败走透传分支的）按整行 text-level 兜底扫描。

### D3: 输出审计钩子 — 挂在已有完成事件上，OpenAI 格式补分片累积

**决策**：审计触发点对齐现有 arg_buf 完成事件：
- Anthropic：`block_stop`（已有，arg_buf 完整）
- Responses：`item_done`（已有，arg_buf 完整）
- OpenAI chat/completions：**新增** `delta.tool_calls` 分片累积（按 index 分组 `function.name` + `function.arguments`），在 `finish_reason == 'tool_calls'` 或流末触发审计
- 非流式整包响应：在响应体解析后、转发前提取 `tool_calls`（OpenAI 格式 `choices[0].message.tool_calls` / Anthropic `content[].tool_use` / Responses `output[]`），同样走 `audit_tool_call` 审计——不得因缺少 SSE 完成事件而跳过

审计通过 → 原样继续；审计拦截 → 进入处置（D4）。审计是纯检查函数（`audit_tool_call(name, args_json) -> AuditVerdict`），不阻塞事件循环。

**审计对抗性**：上游（模型/网关）输出不受信任，纯字符串匹配可被系统性绕过——tool 参数在匹配前先**规范化**：合并重复空白、解析 `\uXXXX`/`\xXX` 转义、按 `;`/`&&`/`|`/换行拆解命令链、递归展开单层变量拼接（`CMD=rm;$CMD -rf`）、识别 `/bin/rm`/`find -delete` 等别名形态；策略文件按「检测器」维度组织（原始匹配 + 规范化匹配双结果，命中任一即判危险）。审计在完成事件处读**掩码前原始 arg_buf**（PII 掩码在 flush 阶段做）——否则 tool 参数中的 IP 被替换为占位符后「网络外传」规则失配，外传调用被放行。规则引擎的防护边界：**防意外、不防对抗**（对抗级语义检测属 Non-Goals），策略文件头部与 README 明示该承诺。

**理由**：三种协议都已有「工具调用参数完整」的语义边界，挂在这里语义最准、改动最小。OpenAI 格式是 Hermes 实际使用的路径（opencode-go 网关 OpenAI 兼容格式），必须补上才有意义。

**备选**：独立累积所有协议的 tool calls（重复造轮子）——不采用，完成事件已存在。

### D4: 处置模式 — 阻断（默认）与审批（可选）

**决策**：`AUDIT_MODE=block`（默认）：危险调用被替换为一条带说明的 assistant 拒绝消息（`content` 说明、无 `tool_calls`），客户端（Hermes）收到后不会执行工具，后续流正常继续。`AUDIT_MODE=approve`：挂起该 tool call 转发，通过 Matrix `_ask` 请求 ✅/❎，超时默认拒绝；批准后按原格式补发 tool call 事件。**审批白名单（硬性）**：reaction 处理器必须校验 (a) 发送者 ∈ 配置的审批人白名单（现有 reaction 处理器无发送者校验，必须补）；(b) reaction 所附 event id 精确匹配该 pending 请求的审批消息 event id；(c) 同一 pending 请求只接受首次判定（幂等）。三项作为 requirement 写入 spec 并配测试。

**理由**：
- 阻断模式对 cron/无人值守场景安全（无人工依赖，不阻塞）
- 拒绝消息用「无 tool_calls 的 assistant content」是最兼容的注入形态——Hermes 按普通助手回复处理，不会尝试执行
- 审批模式复用 `_matrix.py` 现有 `_ask`/pending/超时机制，与凭据审批同构，改动小

**备选**：审批挂起整个 SSE 流（先不发任何内容直到审批结束）——延迟大、破坏流式体验；审批通过后重放——复杂且浪费。

**流式细节（处置状态机）**：三种协议**统一语义**——检测到可疑 tool call（参数命中危险规则）后，在审计 verdict 得出前**暂停该 tool call 的后续事件 flush**：
- Anthropic/Responses：实测 `_flush_anthropic_buf`/`_flush_responses_buf` 是**逐块 flush**（`keep_pending=True` 时 safe 部分已按 `input_json_delta` 事件持续流出）。因此「参数前半段已到达客户端」是既成事实，不可撤回——实现必须**在首个可疑 delta 进入缓冲时即暂停 flush**（判定点前置：按策略对 tool 名/参数前缀做增量预检），并显式声明「已 flush 部分无法撤回」。阻断/拒绝后注入拒绝消息，同时发出对应协议的**终止事件**（如 `block_stop`/`item_done`），避免客户端 tool_use 块 dangling。
- OpenAI：新增累积路径（D3）天然全程缓冲，未出 verdict 前不 flush 任何 tool call 事件——阻断与审批同构。

审批挂起状态机（`AUDIT_MODE=approve` 且触发审批时）五终态：

| 终态 | 触发 | 对客户端 | 对上游连接 | 对 pending 条目 |
|---|---|---|---|---|
| approved | 用户 ✅ | OpenAI：补发完整 tool call 事件；Anthropic/Responses：续传剩余参数 delta + 正常 `block_stop`/`item_done` 终止（**已 flush 部分不可撤回，不得重复拼接**）；挂起期间缓冲 content 统一放行 | 继续读取/正常结束 | 删除 |
| rejected | 用户 ❎ | 注入拒绝消息 + 协议终止事件 | 继续读取/正常结束 | 删除 |
| expired | 超时（默认拒绝） | 注入拒绝消息 + 协议终止事件 | 继续读取/正常结束 | 删除 |
| upstream_down | 上游断连/异常 | 注入拒绝消息 + 协议终止事件 | 关闭 | 删除 |
| client_gone | 客户端提前断连 | —（无客户端可通知） | 关闭 | 删除；未审计 tool call 按 fail-closed 丢弃 |

挂起期间：**继续读上游并缓冲**（不停止读，避免 TCP 背压触发上游 ~120s 断连），但缓冲有上限 `AUDIT_HOLD_MAX_BYTES`（默认 1MB，与 `SSE_MAX_BUF` 同量级）；超限时按 rejected 处理（fail-closed）。审批请求与**流生命周期绑定**：流结束/异常/客户端断连 → 取消审批（`event.set()` + 清理 pending 条目），handler 加 `try/finally` 兜底清理请求级映射；另加**周期清扫兜底**：后台定时任务（周期 60s）扫描孤儿 pending（对应流已结束/异常但条目未清理），置为 rejected 并清理——注意 `_matrix.py` 的 CMD_LOCK 是 lock 命令触发时的一次性清空（`_matrix.py:94-108`），语义不同，仅可作启发参考，不得表述为「复用 CMD_LOCK 机制」；清扫宿主/周期/锁语义在实现时确定（`_cleanup_request` 要求调用者持 `self._lock`），验收见 tasks 6.4。

上游断连时**未完成审计的 tool call 一律丢弃并注入拒绝消息**（fail-closed，与审批超时处置对齐）；连接中断（无 `[DONE]`）时已累积未审计的 tool call 不得静默 flush。`AUDIT_TIMEOUT` 默认 **90s**，与上游 ~120s 断连特征错开（默认值显著小于断连窗口；配置不得落在 110-130s 竞态区间，见 D5 校验）。**处置幂等约定**：approve 模式下超时与上游断连可能并发触发，两路径处置前均先检查 pending 条目是否存在——先到者处置并删除条目，后到者发现条目已删则跳过（防双注入/重复终止事件）。阻断模式下注入的拒绝消息保持合法协议结构（`finish_reason: stop`），拒绝后后续 content 照常转发，客户端对流中间 `finish_reason` 的兼容性列入 9.2 验证清单。

### D5: 配置 — 环境变量 + 可选策略文件

**决策**：
- `PII_REDACTION_ENABLED`（默认 off）、`PII_RESPONSE_SIDE`（默认 on，当 PII 功能开启时）
- `AUDIT_MODE`（`off`/`block`/`approve`，**总开关默认 `off`**；开启审计后默认处置模式为 `block`——两层「默认」需区分：总开关默认关闭 vs 处置模式默认阻断）、`AUDIT_TIMEOUT`（审批超时秒数，默认 **90**；**取值校验 ≥1s 且拒绝 110-130s 区间**——该区间与上游 ~120s 断连特征竞态；命名语义与既有凭据审批 `APPROVAL_TIMEOUT`（实测 300s）对齐，数值独立，审计审批必须避开断连窗口故不能沿用 300）
- `AUDIT_HOLD_MAX_BYTES`（审批挂起期间缓冲上限，默认 1048576）
- `AUDIT_POLICY_FILE`（可选 YAML/JSON 策略文件路径；缺省用内置默认策略：危险 shell 命令模式、敏感路径、工具 deny 名单；策略文件含「检测器」维度示例与防护边界注释）
- `APPROVAL_WHITELIST`（审批人白名单，Matrix 用户 ID 逗号分隔；`AUDIT_MODE=approve` 时必须配置，缺失启动报错）

**理由**：保持与现有环境变量配置风格一致（`LLM_8878`/`GET_BINARY_HASH` 等），feature flag 默认关闭保证零侵入。

### D6: 代码结构 — 新增两个 Mixin + 策略数据独立

**决策**：
- `_pii.py`：`PiiMixin`（检测器注册表、`detect_and_redact`/`restore`、请求级映射生命周期管理）
- `_audit.py`：`AuditMixin`（策略加载、`audit_tool_call`、阻断/审批处置、审计日志持久化）
- 审计日志：追加写 `DATA_DIR/audit.log`（JSON Lines），与现有 `caller_registry.json` 同目录风格
- `proxy.py` 组合新 Mixin（`CredentialProxy(PiiMixin, AuditMixin, ...)`）；轻量入口按需引入。**限制声明**：`AUDIT_MODE=approve` 依赖 MatrixMixin（`_ask`/reactions），仅完整 proxy 支持；轻量入口（llm-proxy-only）配置 approve 时**启动报错**或降级 block，不得静默忽略

**理由**：延续 Mixin 拆分模式（7 文件 → 9 文件），职责单一、可独立测试、轻量入口（llm-proxy-only）可只引入 PiiMixin。

## Risks / Trade-offs

- **PII 误报**（11 位数字可能是订单号）→ 只对高置信模式脱敏（如身份证含校验位验证、手机号前缀段验证）；误报代价仅为模型看到占位符，响应侧还原后用户无感
- **PII 漏报**（新格式/上下文型 PII 检测不到）→ 规则引擎覆盖已知强模式；Phase 3 Presidio 增强兜底
- **OpenAI tool_calls 分片累积新增路径的 bug 风险** → 参照 anthropic/responses 已修复的坑（跨块伪还原、null 值、`_PARTIAL_TOKEN_RE` 清理），补集成测试；沿用「跨协议对称审计铁律」
- **审批模式下流挂起**：挂起期间其他事件（如后续 content delta）处理 → 设计为「按事件序挂起」：危险 tool call 之前的 content 已 flush，之后的 content 也缓冲等待，审批完成统一放行/替换。**挂起期间若缓冲中出现新的危险 tool call，一律 fail-closed（拒绝并注入拒绝消息，不得未经审批统一放行）**；超时默认拒绝避免永久挂起
- **审批消息发送失败**（`_ask` 返回 None，Matrix 不可达）→ 既有凭据路径先例为立即 cleanup + 503（`_credential.py:413-419`）；审计路径同构：立即按 rejected 处置 + 清理 pending 条目，不得空挂至超时
- **阻断注入的兼容性**：Hermes 可能对「无 tool_calls 的 assistant 消息」的 finish_reason 语义有依赖 → 注入消息保持合法协议结构（`finish_reason: stop`），验证 Hermes 实际行为后调整
- **审计日志含敏感信息** → 只记参数摘要（**先脱敏、后截断**：截断会破坏脱敏正则导致片段泄漏，必须先替换密钥形态为 `[REDACTED:<type>]` 再截断，截断边界做半字符保护），不记完整参数值；保留触发规则的规范化片段供复盘。**脱敏数据源**：日志摘要取「审计后、掩码后」文本，脱敏使用**实时请求级映射**（含响应期新注册 PII）——不得从掩码前快照取摘要，否则响应期新检测的 PII 明文会落盘
- **审计日志写失败** → 默认 **fail-closed**（写失败即阻断危险调用 + 打告警），不静默漏记；日志行 `json.dumps` 强制转义并剥离控制字符（`\x00-\x1f`）防日志注入伪造条目；文件权限 0600；大小轮转（10MB × 5 份）

## Migration Plan

1. 开发按 Phase 顺序：D2 请求级 PII token 机制 → D1 检测器 → D3 审计钩子 → D4 处置 → D5 配置
2. 全部功能默认关闭，先跑全量测试（146 + 新增），再在 llm-proxy-only 本地验证
3. 部署：Docker 镜像 tag 升级（v0.9.x），环境变量按需开启；回滚 = 关闭 feature flag 或回退镜像 tag，无数据迁移
4. Hermes 端零改动（custom provider 配置不变）

## Open Questions

- OpenAI 格式下 `finish_reason == 'tool_calls'` 是否在所有上游（opencode-go 网关透传 DeepSeek）都可靠出现——若不可靠，改用流末 `[DONE]` 前统一审计（实现时用真实流量验证）
- 阻断注入的「拒绝消息」是否需要特殊前缀让 Hermes 明确识别为策略拒绝（而非普通助手回复）——实现时观察 Hermes 行为决定
