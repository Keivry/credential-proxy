## Purpose

确保脱敏与还原在所有 JSON 承载路径上不破坏 JSON 结构完整性，覆盖流式/非流式、三协议与嵌套 JSON 字符串场景。

## ADDED Requirements

### Requirement: Top-level JSON leaves SHALL remain valid JSON after redaction
系统在处理下游请求体为合法 JSON（object/array）时，对凭据/PII 的脱敏 SHALL 仅对解码后叶字符串值操作，再经 `json.dumps(ensure_ascii=False, separators=(',',':'))` 回写，不在序列化文本上做子串替换。

#### Scenario: Request with special chars stays valid JSON
- **WHEN** 请求体为 `{"content":"p@ss\"quote"}` 且凭据含 `"` 时走 `_redact_json_aware`
- **THEN** 输出仍为合法 JSON 且 `content` 解码后等于 token

#### Scenario: Request with unicode escape not hijacked
- **WHEN** 请求体含 `"\u0031"` 且凭据为 `0031`
- **THEN** 输出仍为合法 JSON，且不对转义序列内部做替换

### Requirement: Top-level JSON leaves SHALL remain valid JSON after restore
系统在处理上游响应体为合法 JSON 时的凭据/PII 还原 SHALL 同叶节点语义，`dumps` 负责转义含 `"`/`\`/`\n` 的明文，不在序列化文本上做 `token→pwd` 的 plain 替换。

#### Scenario: Response restore with quote stays valid
- **WHEN** 响应体为 `{"choices":[{"message":{"content":"echo __VG_CRED_000001__"}}]}` 且 token 映射到 `p@ss"quote`
- **THEN** 输出为合法 JSON 且 `content` 解码后为 `echo p@ss"quote`

### Requirement: Nested JSON strings in leaf values SHALL be handled recursively
当叶字符串本身为 JSON 文本（`lstrip("\ufeff")` 后 strip 再判以 `{`/`[` 开头且可 `json.loads` 为 `dict/list`）时，系统 SHALL 对内层同走 walk→redact/restore→dumps，失败回退 plain；BOM 前缀 `\ufeff` SHALL 被视为可剥离前缀。

#### Scenario: Nested tool_calls.arguments restored without breaking inner JSON
- **WHEN** 响应体为 `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"{\"key\":\"__VG_CRED_000001__\"}"}}]}}]}` 且 token 为 `p@ss"quote`
- **THEN** 外层仍为合法 JSON，且 `arguments` 解码后仍为合法 JSON，其 `key` 值为 `p@ss"quote`

#### Scenario: Nested fallback keeps plain leaf intact
- **WHEN** 叶字符串为 `"{not json"`（`{` 开头但不可解析）
- **THEN** 系统对其按普通字符串还原，不抛异常且外层仍合法

#### Scenario: Nested with BOM prefix handled
- **WHEN** 叶字符串为 `"\ufeff{\"key\":\"__VG_CRED_000001__\"}"` 且 token 为 `p@ss"quote`
- **THEN** BOM 被剥离后内层仍走递归，外层与内层均合法

### Requirement: SSE data lines SHALL remain valid JSON after restore
对 `data: {JSON}` 形态的流式行，系统 SHALL 按 `split(":",1)[1].lstrip(" \t")` 剥离前缀（含 `data:[DONE]`/`data:  [DONE]` 多空格兼容）后，对 `payload.lstrip("\ufeff").strip()` 判空/`[DONE]` 早退，非 `{`/`[` 开头回退 plain，否则对 payload 做 JSON-aware（含嵌套与 BOM 剥离），再重建 `data: ` + payload；`data: [DONE]` 与非 JSON payload SHALL 原样保留。

#### Scenario: Streaming tool_calls line stays valid
- **WHEN** 流式行 `data: {"choices":[{"delta":{"tool_calls":[{"function":{"arguments":"{\"key\":\"__VG_CRED_000001__\"}"}}]}}]}` 经 `_pii_process_sse_line`
- **THEN** 输出行仍为 `data: ` + 合法 JSON，且内层 `arguments` 同 Scenario 3.1

#### Scenario: DONE and non-JSON lines untouched
- **WHEN** 行 `data: [DONE]`、`data:[DONE]`、`data:  `、`data: not-json` 经同一路径
- **THEN** 行原样输出，不抛异常

#### Scenario: BOM-prefixed SSE line handled
- **WHEN** 行 `data: \ufeff{"choices":[]}` 经同一路径
- **THEN** BOM 剥离后仍按 JSON-aware 处理且合法

### Requirement: Fallback SHALL stay closed on non-JSON and errors
当文本非合法 JSON 或内层解析/还原抛异常时，系统 SHALL 回退到 plain 路径，不泄露异常且不破坏原文结构；日志可记录 debug；半行残余（跨 chunk 未以 `\n` 结尾）不在 JSON-aware 范围，仅 best-effort 回退。

#### Scenario: Non-JSON body falls back
- **WHEN** 文本为 `hello __VG_CRED_000001__ world` 非 JSON
- **THEN** 走 plain 替换，输出为明文替换结果

#### Scenario: Malformed JSON fallback does not throw
- **WHEN** 文本为 `{"a": "unterminated`（缺引号）
- **THEN** 输出为 plain 替换结果，不抛 `JSONDecodeError` 到调用方

#### Scenario: Half-line residual fallback is best-effort
- **WHEN** 流结束残余为 `data: {"choices":` 半行 JSON
- **THEN** 回退 plain，不保证 JSON 合法，不抛异常

### Requirement: Serialization form MAY change but semantic equality SHALL hold
`json.dumps(ensure_ascii=False, separators=(',',':'))` 的空白压缩与 `\uXXXX`→明文 SHALL 被视为等价形态；语义等价（`json.loads` 相等）即通过，不要求字节级一致。

#### Scenario: Whitespace and escapes may change but semantic equal
- **WHEN** 输入为 `{"a": 1, "b": 2}` 含空格或 `"\u4e2d\u6587"` 
- **THEN** 输出可能为 `{"a":1,"b":2}` 或 `{"content":"中文"}`，`json.loads` 相等即验收通过

### Requirement: Non-conversation tails SHALL not be redacted
对 `tail` 非 `chat/completions|v1/messages|v1/responses` 的请求（如 `v1/models`），系统 SHALL 不触发请求/响应 JSON-aware 路径，原样透传。

#### Scenario: Models pass-through
- **WHEN** 请求 `GET /v1/models` 带含凭据子串的 body
- **THEN** 不做脱敏/还原，响应 JSON 不被改写
