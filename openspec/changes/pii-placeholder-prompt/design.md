## Context

当前 PII 脱敏是纯「替换-还原」机制：请求侧 `_llm.py` handler 在 `is_dialog_tail` 且 `pii_enabled` 时调用 `self._pii_request_scope()` + `pii_redact_json_aware(body_text)`，将检测到的明文 PII 替换为 `__PII_<seq>_<rand8>__` 占位符；凭据路径替换为 `__VG_CRED_<seq>__`。转发上游前**不注入任何说明**，上游只见裸占位符、不知道其含义。动机见 proposal.md - Why。

关键现状约束：

- 脱敏替换发生**在请求 body 文本层面**（`body_text`），`pii_redact_json_aware` 返回替换后的 body；「本次请求是否实际产生占位符」从替换结果判定（`body_text` 中是否含 `__PII_` / `__VG_CRED_`），复用现有 `_llm.py:2188-2189` 的 `has_cred`/`has_pii` 快速路径（`b'__VG_CRED_' in out_body` / `b'__PII_' in out_body`）。
- 三协议入口（OpenAI `chat/completions`、Anthropic `/v1/messages`、Responses API）共用同一请求处理管道，但消息结构不同：chat/completions 用 `messages[]`；Anthropic 用顶层 `system`（字符串**或数组 blocks**）+ `messages[]`；Responses API 用 `input[]`（含 `role: "system"` 的条目）。`content`/`system` 字段可为字符串或数组（多部分 blocks）。
- 响应侧还原（`_llm.py` 还原路径）依赖「模型回显占位符 → 映射还原」，任何改写/补全都会导致还原失配。`used_tokens` 收集（`_llm.py:2228-2233`）只收集实际注册 token，关闭「prompt 字面量 `__VG_CRED_*__` → 回显 → 还原」放大路径。
- 代码规范：Mixin 模式、锁外网络 I/O、快照安全、Python 3.10 f-string 引号兼容、`_redact/_restore` 按长度降序替换。
- 测试：pytest + ruff check/format --check 必须通过。

## Goals / Non-Goals

**Goals:**

- 仅在实际发生脱敏（产生占位符）的请求中注入说明提示词，零脱敏零注入；
- 注入位置合理：优先追加现有 system 消息，无则新建 system 消息头部；兼容 `content`/`system` 字符串与数组两种形态；
- 三协议（OpenAI / Anthropic / Responses）统一适配，注入后协议语义不变；
- 开关可配置（`PII_PLACEHOLDER_PROMPT`），文案可自定义（`PII_PLACEHOLDER_PROMPT_TEXT`）；
- 不改变响应侧还原行为，不泄漏真实 PII。

**Non-Goals:**

- 不改动现有 PII 检测/替换/还原机制本身；
- 不改变凭据脱敏（`__VG_CRED_*__`）的既有行为；
- 不实现「按 PII 类型选择性注入」（如仅 IP/银行卡才注入）——统一注入，逻辑简单；
- 不做多语言自动切换（内置默认文案为中文，用户可通过 `PII_PLACEHOLDER_PROMPT_TEXT` 自定义覆盖）；
- 不处理流式响应侧的提示词注入（只注入请求侧，响应侧无注入需求）。

## Decisions

### D1: 注入时机 — 仅实际产生占位符时注入

**决策**：在请求侧 PII 脱敏完成后、转发上游前，检测 body 中是否含 `__PII_` 或 `__VG_CRED_` 占位符；**只要有一个（OR 语义）就注入**说明提示词；没有则不注入。非对话尾（`is_dialog_tail == false`）请求不注入（与脱敏路径一致）。

**理由**：零脱敏零注入——不污染 prompt、不消耗 token、不引入注入面。只有模型真的会看到占位符时才需要解释。

**备选**：
- 无条件注入（PII 启用就注入）：简单但每次请求都增加 token 消耗 + prompt 污染，且无占位符时纯属噪音。
- 按类型注入（仅 IP/银行卡等格式敏感型）：更精准但需把「是否格式敏感」判定引入替换逻辑，复杂度高、收益边际小（模型对任何占位符都应原样保留）。

### D2: 注入位置 — 追加现有 system，无则新建 system 头部（含数组分支）

**决策**：注入时按协议结构适配，且**兼容字符串与数组两种 content 形态**：

- OpenAI `chat/completions`（`messages[]`）：
  - `content` 为**字符串**：若 `messages[0].role == "system"`，末尾追加 `\n\n` + 说明文本；否则新建 `{"role": "system", "content": "<说明>"}` 插入头部。
  - `content` 为**数组**：若 `messages[0].role == "system"`，向数组末尾追加 `{"type": "text", "text": "\n\n<说明>"}`（若最后一个元素已是 text 则追加到其末尾）；否则新建 system 消息插入头部。
  - 多条 system 时仅追加第一条，其余不变。
- Anthropic `/v1/messages`（顶层 `system` 字段）：
  - `system` 为**字符串**：存在则末尾追加 `\n\n` + 说明；不存在则新建顶层 `system` 字段。
  - `system` 为**数组**：存在则向数组末尾追加 `{"type": "text", "text": "\n\n<说明>"}`；不存在则新建顶层 `system` 字符串。
- Responses API（`input[]`）：
  - 与 OpenAI 同构：`input[0].role == "system"` 则按 content 类型追加；否则新建 `{"role": "system", "content": "<说明>"}` 插入头部。

**理由**：system 消息是模型指令的权威位置，追加到现有 system 末尾可保留用户原有指令优先级、不改变消息顺序语义；新建 system 头部保证模型一定看到。三种协议都有 system 等价结构，统一「追加/新建」策略。数组分支必须显式处理——三协议均允许 `content`/`system` 为 blocks 数组，按字符串拼接会破坏结构导致上游 400/500。

**备选**：
- 追加到 user 消息末尾：会污染用户内容、可能被模型当作对话内容而非指令。
- 新建独立 system 消息放头部（无论有无现有 system）：简单但会与现有 system 并存，可能造成指令重复/冲突。

### D3: 触发判定 — 从替换后 body 文本判定（OR 语义 + 类型统一）

**决策**：注入判定直接检查脱敏后的 `body_text` 是否含 `__PII_` 或 `__VG_CRED_` 占位符形态（OR 语义：任一命中即注入），复用现有 `_llm.py:2188-2192` 的 `has_cred`/`has_pii` 快速路径判定思路。

**类型统一**：判定在 `body_text: str` 层面进行（`out_body_str = out_body if isinstance(out_body, str) else out_body.decode('utf-8', errors='replace')`），再用 `'__PII_' in out_body_str or '__VG_CRED_' in out_body_str`；避免 bytes/str 混用导致漏判。

**理由**：无需修改 PiiDetector 的返回契约；替换结果本身就精确反映「本次请求实际产生了哪些占位符」；与现有快速路径判定逻辑一致，实现成本最低。OR 语义保证凭据占位符同样触发（`__VG_CRED_` 出现即注入，不依赖 `pii_scope`）。

**备选**：
- 让 `pii_redact_json_aware` 返回「是否替换过」标志：需改动函数签名/返回值，波及面大，且凭据路径（`_redact`）与 PII 路径返回结构不同，统一成本高。
- 依赖 `pii_scope`/检测结果判断：scope 只表示「检测范围是否启用」，不代表「实际替换了值」，不可靠。

### D4: 开关与文案 — 两个环境变量，默认开启

**决策**：

- `PII_PLACEHOLDER_PROMPT`：`1`/`true`/`yes` 启用（默认），`0`/`false`/`no` 关闭；值大小写不敏感（`strip().lower()` 归一）。关闭时即使脱敏产生占位符也不注入，且**不解析/校验 `PII_PLACEHOLDER_PROMPT_TEXT`**（短路，零副作用：不截断、不告警、不 regex）。
- `PII_PLACEHOLDER_PROMPT_TEXT`：自定义文案；未设置、空字符串或全空白用内置默认（推荐版中文，见 proposal）；**先校验禁词再截断**（防超长文案中 4096 之后的合法占位符形态被截掉逃逸）；长度上限 4KB，超限截断并警告；若含合法形态占位符（`__PII_\d+_[0-9a-fA-F]{8}__` / `__VG_CRED_\d+__`，**大小写不敏感**）则警告并回退内置默认文案。⚠️ 信任边界：与 `SYSTEM_PROMPT` 同特权，仅运维可写。

解析放在 `proxy.py` 的 `_init_pii`（`proxy.py:213-223` 现有 PII 配置解析处），`parse_pii_env_config` 返回字典新增 `placeholder_prompt_enabled` / `placeholder_prompt_text` 字段，存入 `self.pii_placeholder_prompt_enabled` / `self.pii_placeholder_prompt_text`。

**理由**：与现有 PII 环境变量风格一致（`PII_REDACTION_ENABLED` 等），用户可关闭（担心 prompt 污染/注入面时）或自定义（配合上游模型偏好）。默认开启符合本次变更目的（补上缺失的说明）。文案校验防止自定义文案破坏「说明自身不被脱敏/还原」的安全不变量。

**备选**：
- 无开关强制注入：不给用户关闭能力，违背「简单直接 + 可配置」偏好，且 prompt 注入面争议场景无法退出。
- 文案硬编码：无法适配不同上游模型的语言/指令偏好。

### D5: 注入文本静态性 — 不含真实数据

**决策**：注入文本为静态常量（内置默认）或用户自定义 env（静态，经 D4 校验），**不包含任何真实 PII 值、不包含本次请求特有的占位符序号**。文本中出现的 `__PII_*__` / `__VG_CRED_*__` 是形态通配描述，不是真实占位符。

**理由**：避免注入文本本身成为 PII 泄漏面；避免模型把描述中的形态当成真实占位符去还原（破坏响应侧还原）；满足 spec「说明提示词自身不被脱敏」——形态描述 `__PII_*__` 不会命中 PII 检测（`*` 不是合法 rand8 hex）。

**备选**：
- 把实际占位符序号写进说明（如「本次请求中的 `__PII_1_ab12cd34__`」）：更精确但文本随请求变化、可能被 PII 检测误伤、且静态性被破坏。

### D6: 注入函数错误路径与并发契约

**决策**：

- **非 JSON body**：注入函数首先尝试解析 JSON；若 body 非合法 JSON（form-data/binary/截断），SHALL NOT 抛异常，静默透传原 body 不注入（与 `_llm.py` 现有「JSON 解析失败回退原文」模式一致）。
- **并发契约**：注入操作为**请求作用域纯函数**（`body_text: str → new_body_text: str`），无共享可变状态，无需持锁；不读写 `pii_t2p`/`used_tokens`，与现有脱敏/还原映射无冲突。注入时机固定为 `pii_redact_json_aware` 之后、转发之前，**禁止注入后二次 PII 扫描**。
- **协议判定**：以路由 path 为主（`is_dialog_tail` 已判三协议尾缀）、body 结构为辅，避免仅凭字段存在性误判分支。

**理由**：错误路径显式化避免实现时「注入抛异常导致上游 500」；并发契约明确「无锁纯函数」避免实现者误加锁或误读写映射；禁止二次扫描固化「说明文本自身不被脱敏」的安全不变量。

**备选**：
- 非 JSON body 抛异常：会破坏正常透传，错误处理成本高、收益低。

## Risks / Trade-offs

- [Prompt 污染 / token 消耗] → 仅实际脱敏才注入（D1），无脱敏零注入；注入文本固定长度（推荐版约 100 字符，≈25-30 token），成本可忽略。
- [注入面 / prompt injection 担忧] → 注入文本为固定静态指令、不含外部数据，无用户可控内容（D5 + D6 错误路径）；默认开启但提供 `PII_PLACEHOLDER_PROMPT=0` 关闭。
- [上游可能忽略说明] → 说明只是降低概率的软性手段，不保证模型一定遵守；但「明确告知」远好于「裸占位符」，且响应侧还原（回显即还原）是硬保证（`used_tokens` 只收集实际注册 token，封闭放大面），说明只是辅助。
- [注入文本被 PII 检测误伤] → 内置文案 `__PII_*__` 的 `*` 非合法 hex，不命中真实形态；自定义文案经 D4 校验（含真实形态占位符则回退内置）从源头杜绝；时序上注入在 `pii_redact_json_aware` 之后、禁止二次扫描（D6），双保险。`__VG_CRED_*__` 同理（`*` 非数字，不命中 `__VG_CRED_\d+__`）。
- [三协议结构差异] → 统一「追加/新建 system」策略（D2），Anthropic 顶层 `system` 字符串与数组、Responses `input[]` 结构与 chat 不同——实现时按协议分支处理，测试三协议各覆盖字符串/数组形态。
- [与 prompt cache 交互] → 注入使「有占位符请求」的 system 前缀与「无占位符请求」不同，可能降低 prompt cache 命中率；但占位符请求本就因内容含 PII 而多样性高，cache 命中率本就不高，影响可接受（且说明文本固定，同类请求间 cache 仍可命中）。
- [自定义文案长度/内容滥用] → D4 长度上限 4KB + 真实占位符形态校验回退；`PII_PLACEHOLDER_PROMPT_TEXT` 视为与 `SYSTEM_PROMPT` 同等特权（仅运维可写），文档化信任边界。
- [body 超大时注入性能] → 注入函数为单次 JSON parse + 单点追加 + 序列化，O(n) 线性；已有 `_llm.py` 处理大 body 的既有路径，无新增量级风险。超大 body（10MB 级）压测纳入 tasks 验收。

## Migration Plan

1. 实现 D1-D6 对应代码（`_pii.py` 默认文案常量 + `proxy.py` env 解析 + `_llm.py` 注入函数与接线）；
2. 新增单元测试 + 三协议集成测试（含字符串/数组形态、非 JSON、空串文案、关闭开关）；`pytest` 全量 + `ruff check` / `format --check` 通过；
3. 更新 `README.md` 环境变量表；
4. 发布版本（v0.9.21）：默认开启，无需配置即可生效；如遇问题设 `PII_PLACEHOLDER_PROMPT=0` 回退（零代码回滚）。

## Open Questions

- 无（设计决策均已在本文档 D1-D6 明确；实现细节如有出入在 apply 阶段调整）。
