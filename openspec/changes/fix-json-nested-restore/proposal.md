## Why

v0.9.9 的 JSON-aware 热修复解决了顶层 JSON 叶节点中 `"`/`\`/`\n` 与 `\uXXXX` 转义的破坏，但在流式 SSE 整行 `data: {…}` 与 `tool_calls.arguments` 等嵌套 JSON 字符串场景仍稳定复现 `JSONDecodeError`（`Expecting ',' delimiter` / `Invalid \escape`）。若上游返回含含特殊字符的凭据，本次换页必触发工具调用参数解析失败。需在保持现有语义的前提下一次性闭环。

## What Changes

- `_token.py`：叶字符串若本身为 JSON（strip 后 `lstrip("\ufeff")` 再判 `{`/`[` 开头且可解析为 `dict/list`）则对内层同走 `walk→redact/restore→dumps`，失败回退 plain；覆盖 `_redact_json_aware` 与 `_restore_json_aware`
- `_pii.py`：`_pii_json_walk` 同步支持嵌套 JSON 字符串的递归处理（含 BOM 剥离），失败回退 `detect_and_redact`
- `_llm.py`：新增 `_pii_process_sse_line` 对 `data: {JSON}` 行做 JSON-aware（含嵌套），替换 slow path 的 `data:` 行；非流式整包的嵌套由 walk 层递归覆盖（不做外层二次 `loads`）；`_strip_token_forms_json_aware` 同步嵌套
- 不改变对外 API、配置、存储格式；`ensure_ascii=False, separators=(',',':')` 与 v0.9.9 保持一致（空白压缩、`\uXXXX`→明文属语义等价，非字节级保持，见 design D4）

## Capabilities

### New Capabilities
- `json-safe-redaction`: 脱敏/还原在所有 JSON 承载路径上不破坏 JSON 结构完整性（含特殊字符、`\u` 转义、嵌套 JSON 字符串、流式 SSE 行）

### Modified Capabilities
- 无（`openspec/specs` 当前为空；本 change 引入首个能力）

## Impact

- 影响文件：`_token.py`、`_pii.py`、`_llm.py`、`pii_llm_test.py`/`llm_test.py`（新增用例）
- 影响 API：`POST /{tail}` 的三对话尾（`chat/completions` / `v1/messages` / `v1/responses`）的请求脱敏与流式/非流式响应还原；`v1/models` 等非对话尾不受影响（原样透传，见 spec）
- 协议矩阵：`chat/completions` 的 `tool_calls[].function.arguments` 与 `v1/responses` 的 `output[].function_call.arguments` 为字符串套 JSON（本 change 覆盖）；`v1/messages` 的 `content[].tool_use.input` 为已解析对象非字符串套字符串，仅顶层 walk（豁免）
- 依赖：无新增依赖；`ruff` / `pytest` 门禁保持；`CHANGELOG.md` 追加 `v0.9.10` 条目
