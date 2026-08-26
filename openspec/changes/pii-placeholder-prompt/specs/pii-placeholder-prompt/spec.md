## Purpose

让上游 LLM 理解 PII 脱敏占位符（`__PII_*__` / `__VG_CRED_*__`）的含义，避免格式敏感型占位符被误判为格式错误、被改写或补全，从而保证响应侧占位符可被正确还原为原始明文。

## ADDED Requirements

### Requirement: 脱敏发生时注入占位符说明

当启用 PII 脱敏（`PII_REDACTION_ENABLED`）且本次请求实际产生了至少一个 `__PII_*__` 或 `__VG_CRED_*__` 占位符时，系统 SHALL 在转发给上游 LLM 之前，向消息序列中注入一条说明提示词，告知模型这些标记是安全网关的脱敏占位符，代表被替换的原始敏感值，应原样保留、不要校验格式、不要推断或补全内容、不要视为输入错误。

当启用 PII 脱敏但本次请求**未产生任何占位符**时，系统 SHALL NOT 注入任何提示词（零注入，不污染 prompt、不消耗额外 token）。

注入判定 SHALL 使用「产生 `__PII_` 占位符 **或** 产生 `__VG_CRED_` 占位符」的 OR 语义——任一类型占位符产生即触发注入。

注入 SHALL 仅在对话尾请求路径生效：非对话尾（`is_dialog_tail == false`，如 `/v1/models`、`/v1/embeddings`、健康检查）请求 SHALL NOT 注入，与 PII 脱敏路径保持一致。

#### Scenario: 请求含 PII 且脱敏后产生占位符

- **WHEN** 请求正文包含手机号 `13812345678`，PII 脱敏启用且实际替换为 `__PII_1_ab12cd34__`
- **THEN** 转发给上游的 messages 中包含一条说明提示词，说明 `__PII_*__` 与 `__VG_CRED_*__` 为脱敏占位符且应原样保留

#### Scenario: 请求不含 PII（无占位符产生）

- **WHEN** 请求正文不含任何可检测 PII，脱敏后无占位符产生
- **THEN** 转发给上游的 messages 与原始请求完全一致，无任何注入

#### Scenario: PII 脱敏未启用

- **WHEN** `PII_REDACTION_ENABLED` 为关闭状态
- **THEN** 不注入任何说明提示词，转发行为与未启用 PII 时完全一致

#### Scenario: 仅凭据占位符触发

- **WHEN** 请求含凭据且脱敏产生 `__VG_CRED_5_...__`，但无 `__PII_` 占位符
- **THEN** 仍注入说明提示词（OR 语义：凭据占位符也触发）

#### Scenario: 非对话尾请求

- **WHEN** 请求路径为 `/v1/models`（非对话尾），body 含 `__PII_` 形态文本
- **THEN** 不注入任何说明提示词，与 PII 脱敏路径一致

### Requirement: 注入位置与消息结构

注入的说明提示词 SHALL 放置在消息序列的合适位置：若消息序列已存在 `system` 角色消息，SHALL 追加到该 system 消息末尾（多条 system 时仅追加第一条，其余不变）；若不存在 system 消息但消息序列非空，SHALL 新建一条 `system` 角色消息插入消息序列头部；若消息序列为空，SHALL 新建一条 `system` 角色消息作为唯一消息。

注入 SHALL 保持消息序列的其余结构不变（角色顺序、内容、工具定义等均不得改变），且注入的说明提示词 SHALL 为静态文本，不含任何真实 PII 值、不含任何本次请求特有的占位符序号。

**内容类型分支**：system 消息的 `content`（或 Anthropic 顶层 `system`）可能是字符串或数组（多部分 blocks）。SHALL 按类型分支处理：

- `content`/`system` 为**字符串**时：末尾追加 `\n\n` + 说明文本；
- `content`/`system` 为**数组**时：向数组末尾追加一个 `{"type": "text", "text": "\n\n<说明文本>"}` 元素（Anthropic system 数组同理追加 text block）；
- 若 `content` 为数组且最后一个元素为 text 类型，SHALL 追加到该 text 元素末尾，否则新增 text 元素。

**多协议结构**：

- OpenAI `chat/completions`：`messages[]` 数组；system 消息为 `{"role": "system", "content": ...}`；
- Anthropic `/v1/messages`：顶层 `system` 字段（字符串或数组）；`messages[]` 数组；
- Responses API：`input[]` 数组；system 条目为 `{"role": "system", "content": ...}`。

#### Scenario: 已有 system 消息

- **WHEN** 请求的 messages 第一条为 `{"role": "system", "content": "你是助手"}`，且脱敏产生占位符
- **THEN** 注入后该 system 消息内容为原内容末尾追加 `\n\n` + 说明提示词，其余消息不变

#### Scenario: 已有 system 消息且 content 为数组

- **WHEN** 请求的 messages 第一条为 `{"role": "system", "content": [{"type": "text", "text": "你是助手"}]}`，且脱敏产生占位符
- **THEN** 注入后该 system 消息 content 数组末尾追加 `{"type": "text", "text": "\n\n<说明提示词>"}` 元素，其余消息不变

#### Scenario: 无 system 消息但有用户消息

- **WHEN** 请求的 messages 为 `[{"role": "user", "content": "查询 13812345678"}]`，且脱敏产生占位符
- **THEN** 注入后 messages 变为 `[{"role": "system", "content": "<说明提示词>"}, {"role": "user", "content": "查询 __PII_1_ab12cd34__"}]`，原用户消息内容不变

#### Scenario: 空消息序列

- **WHEN** 请求的 messages 为空数组，且脱敏产生占位符（如工具定义示例值中检测到 PII）
- **THEN** 注入后 messages 为仅含一条 system 说明提示词的数组

#### Scenario: 多条 system 消息

- **WHEN** 请求的 messages 为 `[{"role": "system", "content": "A"}, {"role": "user", "content": "..."}, {"role": "system", "content": "B"}]`，且脱敏产生占位符
- **THEN** 仅第一条 system 消息（content "A"）末尾追加说明，第二条 system 与其余消息不变

#### Scenario: Anthropic 顶层 system 为数组

- **WHEN** 请求为 Anthropic `/v1/messages`，顶层 `system` 为 `[{"type": "text", "text": "你是助手"}]`，且脱敏产生占位符
- **THEN** system 数组末尾追加 `{"type": "text", "text": "\n\n<说明提示词>"}` 元素

### Requirement: 可配置开关与自定义文案

系统 SHALL 支持环境变量 `PII_PLACEHOLDER_PROMPT` 控制注入行为的开关：默认启用（`1`/`true`/`yes`），设为 `0`/`false`/`no` 时完全禁用注入（即使脱敏产生占位符也不注入）。

系统 SHALL 支持环境变量 `PII_PLACEHOLDER_PROMPT_TEXT` 自定义提示词文案：设置时使用该文案替换内置默认文案；未设置、空字符串或全空白时使用内置默认文案。

自定义文案 SHALL NOT 包含合法形态占位符（`__PII_<digits>_<hex8>__` 或 `__VG_CRED_<digits>__`，**大小写不敏感**）：若命中，系统 SHALL 记录警告日志并回退内置默认文案。校验 SHALL 在截断**之前**执行（防超长文案中截断点之后的合法形态逃逸）。

自定义文案长度 SHALL 有上限（默认 4KB）：超限时记录警告日志并截断，或回退内置默认文案。

**关闭开关短路**：当 `PII_PLACEHOLDER_PROMPT` 为关闭状态时，系统 SHALL NOT 解析/校验 `PII_PLACEHOLDER_PROMPT_TEXT`，亦不做占位符扫描与注入，行为与变更前完全一致。

#### Scenario: 默认启用

- **WHEN** 未设置 `PII_PLACEHOLDER_PROMPT`，且脱敏产生占位符
- **THEN** 注入内置默认说明提示词

#### Scenario: 显式关闭

- **WHEN** `PII_PLACEHOLDER_PROMPT=0`，且脱敏产生占位符
- **THEN** 不注入任何提示词，转发消息与原始请求一致

#### Scenario: 关闭时不解析自定义文案

- **WHEN** `PII_PLACEHOLDER_PROMPT=0` 且设置了 `PII_PLACEHOLDER_PROMPT_TEXT="<含真实占位符的文本>"`
- **THEN** 不注入、不校验该文案，也不因该文案产生任何副作用

#### Scenario: 自定义文案

- **WHEN** `PII_PLACEHOLDER_PROMPT_TEXT="Keep __PII_*__ verbatim"`，且脱敏产生占位符
- **THEN** 注入的说明提示词内容为用户自定义文本，而非内置默认文案

#### Scenario: 自定义文案为空/空白

- **WHEN** `PII_PLACEHOLDER_PROMPT_TEXT=""` 或全空白，且脱敏产生占位符
- **THEN** 注入内置默认说明提示词

#### Scenario: 自定义文案含真实占位符形态

- **WHEN** `PII_PLACEHOLDER_PROMPT_TEXT="Keep __PII_1_ab12cd34__ verbatim"`（含合法形态 `__PII_<digits>_<hex8>__`）
- **THEN** 系统记录警告日志并回退内置默认文案，不注入该含真实形态的文本

#### Scenario: 自定义文案超长

- **WHEN** `PII_PLACEHOLDER_PROMPT_TEXT` 超过 4KB 上限
- **THEN** 系统记录警告日志并截断到上限（或回退内置默认文案），不因超长文案破坏请求

### Requirement: 协议兼容性

注入说明提示词 SHALL 适用于所有已支持的 LLM 协议：OpenAI `chat/completions`、Anthropic `/v1/messages`、Responses API。三种协议的请求结构均可接受 `system` 角色消息（或等价结构），注入后协议语义不变、上游可正常解析。

协议判定 SHALL 以路由 path 为主、body 结构为辅，避免仅凭字段存在性误判分支。

#### Scenario: OpenAI chat/completions 协议

- **WHEN** 请求路径为 `/v1/chat/completions`，messages 含 PII 且脱敏产生占位符
- **THEN** 注入后的请求仍可被上游正常解析，messages 含说明提示词

#### Scenario: Anthropic /v1/messages 协议

- **WHEN** 请求路径为 `/v1/messages`（Anthropic），消息含 PII 且脱敏产生占位符
- **THEN** 注入后的请求仍可被上游正常解析，system 字段（字符串或数组形态）含说明提示词

#### Scenario: Responses API 协议

- **WHEN** 请求路径为 `/v1/responses`，输入含 PII 且脱敏产生占位符
- **THEN** 注入后的请求仍可被上游正常解析，输入中含说明提示词

#### Scenario: body 非合法 JSON

- **WHEN** 请求 body 非合法 JSON（form-data、binary、截断 JSON）且无法解析消息结构
- **THEN** 系统 SHALL NOT 抛异常，SHALL 透传原 body 并不注入

### Requirement: 响应侧还原不受影响

注入说明提示词 SHALL NOT 改变响应侧还原行为：模型回显占位符时，现有「还原 → 响应侧检测 → 转发」流程继续将请求期注册的占位符还原为明文；注入的说明提示词本身不得被当作 PII 检测目标（说明文字中的 `__PII_*__` 为形态描述，非真实占位符）。

注入时机 SHALL 固定为 PII 脱敏（`pii_redact_json_aware`）完成之后、转发上游之前，禁止在注入后再次执行 PII 扫描（防止说明文本自身被二次脱敏）。

自定义文案 SHALL NOT 包含合法形态占位符（`__PII_<digits>_<hex8>__` / `__VG_CRED_<digits>__`）：命中时系统 SHALL 回退内置默认文案（同 R3 约束），从源头避免说明文本被响应侧还原链误匹配。

#### Scenario: 模型回显占位符仍被还原

- **WHEN** 模型响应中包含 `__PII_1_ab12cd34__`（请求期注册占位符）
- **THEN** 响应侧仍按现有机制还原为明文 `13812345678`，与是否注入说明提示词无关

#### Scenario: 说明提示词自身不被脱敏

- **WHEN** 注入的说明提示词文本包含 `__PII_*__` 形态描述
- **THEN** 该说明文字在后续任何 PII 检测中不被当作真实占位符或 PII 值处理，且不会触发响应侧还原

#### Scenario: 注入后不二次扫描

- **WHEN** 注入完成后 body 含说明文本 `__PII_*__`
- **THEN** 该 body 不再经过 PII 脱敏扫描（禁止注入后二次扫描），说明文本不会产生新占位符

#### Scenario: tool_calls 参数中的占位符

- **WHEN** 请求的 tool_calls arguments 含占位符（如 `{"phone": "__PII_1_ab12cd34__"}`），且脱敏产生占位符
- **THEN** 注入的说明提示词明确覆盖 tool_calls/function 参数场景，要求模型同样原样保留、不要改写
