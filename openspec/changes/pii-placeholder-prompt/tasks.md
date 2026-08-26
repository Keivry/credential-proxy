# Tasks: pii-placeholder-prompt

## 1. 配置解析

- [x] 1.1 在 `proxy.py` 的 `_init_pii`（调用 `parse_pii_env_config`，现有 `proxy.py:213-223`）中新增 `PII_PLACEHOLDER_PROMPT`（默认 `1`，`1/true/yes` 启用，`0/false/no` 关闭）与 `PII_PLACEHOLDER_PROMPT_TEXT`（默认空 → 使用内置文案；空串/全空白视为未设置）解析，存入 `PiiMixin` 实例属性（`self.pii_placeholder_prompt_enabled` / `self.pii_placeholder_prompt_text`）。`parse_pii_env_config` 返回字典新增 `placeholder_prompt_enabled` / `placeholder_prompt_text` 字段。
  - 验收：单测覆盖 `1/true/yes/0/false/no/未设置` 各形态解析结果正确；`proxy.py` 的 `_init_pii` 后属性已就绪；`PII_PLACEHOLDER_PROMPT=0` 时不解析/校验 `PII_PLACEHOLDER_PROMPT_TEXT`（短路）。

- [x] 1.2 自定义文案校验：`PII_PLACEHOLDER_PROMPT_TEXT` 长度上限 4KB（超限截断并告警）；若含合法形态占位符（`__PII_\d+_[0-9a-f]{8}__` 或 `__VG_CRED_\d+__`）则告警并回退内置默认文案。
  - 验收：单测覆盖 `"" / 空白 / 超长(>4KB) / 含真实占位符形态` 四用例：空/空白回落内置、超长截断、含真实形态回退内置并告警。

## 2. 默认文案常量

- [x] 2.1 在 `_pii.py` 定义内置默认说明文案常量（推荐版中文，含 `__PII_*__` 与 `__VG_CRED_*__` 形态说明、原样保留（含 `tool calls`/`function` 参数）、勿校验格式、勿改写补全），作为 `PII_PLACEHOLDER_PROMPT_TEXT` 未设置/非法时的兜底。
  - 验收：常量存在且文本包含 `__PII_*__`、`__VG_CRED_*__`、格式校验、原样保留、tool calls 关键语义；不含任何真实 PII 值、不含合法形态占位符（`__PII_\d+_[0-9a-f]{8}__` / `__VG_CRED_\d+__`）。

## 3. 注入函数

- [x] 3.1 在 `_llm.py`（或 `_pii.py` PiiMixin）新增注入函数，如 `_inject_placeholder_prompt(body_text)`：解析请求 body（JSON），按协议结构注入说明提示词（OpenAI `messages[]` / Anthropic 顶层 `system`（字符串与数组）/ Responses `input[]`），再序列化回 body 文本。注入位置遵循 D2：已有 system → 末尾追加（`\n\n` 分隔，content 为数组时追加 text block）；无 system → 新建 system 消息插入头部；空序列 → 唯一 system 消息；多条 system → 仅追加第一条。
  - 验收：单测覆盖三协议结构注入正确（已有 system 字符串 / 已有 system 数组 / 无 system / 空消息 / 多条 system / Anthropic system 字符串 / Anthropic system 数组）；注入后 JSON 仍合法；`content` 数组追加 text block 不破坏结构。

- [x] 3.2 非 JSON body 错误路径：注入函数对非合法 JSON body（form-data/binary/截断 JSON）SHALL 不抛异常、静默透传原 body 不注入。
  - 验收：单测覆盖 body 非 JSON（如 `not json`、截断 JSON）时返回原 body、无异常；上游请求不受影响。

## 4. 触发判定与接线

- [x] 4.1 在 `_llm.py` 请求侧 PII 脱敏完成、转发上游前（现有 `pii_redact_json_aware` 调用后），接入注入逻辑：判定脱敏后 body 是否含 `__PII_` 或 `__VG_CRED_` 占位符（**OR 语义**，复用 `has_cred`/`has_pii` 快速路径判定思路，统一在 `str` 层面判定）；**仅当**（a）`is_dialog_tail` 且 `pii_enabled`、（b）`pii_placeholder_prompt_enabled`、（c）body 含占位符（`__PII_` 或 `__VG_CRED_`），三者同时满足才注入；任一不满足则原样转发。
  - 验收：单测/集成测试覆盖组合（无脱敏 / 脱敏无占位符 / 脱敏有 PII 占位符 / 脱敏有凭据占位符 / 脱敏有占位符但开关关 / 非对话尾）；零脱敏零注入、无占位符零注入、凭据占位符同样触发注入。

## 5. 协议集成测试

- [x] 5.1 新增三协议集成测试：OpenAI `chat/completions`、Anthropic `/v1/messages`、Responses API，各自覆盖「有脱敏 → 注入成功」「无脱敏 → 零注入」「开关关闭 → 零注入」「自定义文案 → 使用自定义文本」四种场景，断言转发上游的请求 body 结构正确、注入位置正确、响应侧还原不受影响。
  - 验收：新增测试全部通过；`pytest` 全量通过；`ruff check` / `format --check` 通过。

- [x] 5.2 协议结构边缘用例测试：Anthropic `system` 为数组形态（`[{"type": "text", ...}]`）、Responses `input[]` 中 `content` 为数组、`content` 数组含 image block、`input` 含多个 system 条目——断言注入正确追加 text block、不破坏数组结构、其余元素不变。
  - 验收：新增测试全部通过；覆盖 Anthropic system 数组 / Responses input 数组 / content 多 part / 多 system 条目四类。

- [x] 5.3 R5 负向断言测试：注入后 body 再次经 `pii_redact_json_aware` 扫描时 `__PII_*__` 描述不产生新占位符；响应含 `__PII_*__` 字面描述不触发还原；响应含未注册 `__VG_CRED_999__` 不被还原；自定义文案含真实占位符形态（`__PII_1_ab12cd34__`）时回退内置且不触发二次脱敏/还原。
  - 验收：新增测试全部通过；「说明提示词自身不被脱敏」「响应侧还原不受影响」两项 spec R5 要求有独立断言。

## 6. 文档

- [x] 6.1 更新 `README.md` 环境变量表：新增 `PII_PLACEHOLDER_PROMPT`（默认开启，应急关闭开关，不建议长期关闭）与 `PII_PLACEHOLDER_PROMPT_TEXT`（自定义文案，默认内置；空/空白回落内置；上限 4KB；含真实占位符形态回退内置）两行，说明行为与示例。
  - 验收：README 环境变量表包含两项且说明准确；`grep PII_PLACEHOLDER README.md` 命中两行。

## 7. 边界与非功能

- [x] 7.1 超大 body 压测：10MB 级 body（含 PII）注入路径性能与内存——断言注入耗时 < 既有脱敏路径耗时量级、无内存放大（不复制整个 body 多次）。
  - 验收：压测用例通过；注入为 O(n) 线性、单次 JSON parse + 序列化。

- [x] 7.2 错误处理与日志：注入函数 JSON 解析失败、序列化异常、自定义文案校验告警——断言日志记录（level/字段）且不抛异常、不影响转发。
  - 验收：单测覆盖注入异常路径日志；异常时透传原 body。

- [x] 7.3 组合用例：`PII_PLACEHOLDER_PROMPT=0` + 设置 `PII_PLACEHOLDER_PROMPT_TEXT`——断言不注入、不校验文案、无副作用；空 `messages`/`input` 且 body 含 PII——断言注入唯一 system 消息。
  - 验收：组合用例测试通过。
