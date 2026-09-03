## Why

LLM 脱敏反向代理在 SSE 流式还原路径上存在结构破坏与语义分裂：`_mk_sse_event` 重建丢字段、多 `choices` 聚合丢第二路、拼块 `parsed_obj` 错配复用、缓冲事件二次还原漂移，导致下游 SDK `JSONDecodeError` 或工具调用残缺可执行。需在不改变脱敏语义的前提下修复流式保真问题。

## What Changes

- 统一 SSE 事件重建口径：保留上游 `id/model/choices` 结构，仅替换文本 delta 字段，不再拼装裸最小事件。
- 修复多行拼块与 `data_buffer` 聚合路径：逐行独立解析还原，`event:/id:` 行原样保留不进还原。
- 收敛缓冲事件还原次数：`tool_calls_pending_events` verdict 后单次还原，避免二次 `loads→walk→dumps` 漂移与占位符泄漏回退。
- 对齐三协议工具参数语义：Anthropic `partial_json` / Responses `function_call_arguments` / OpenAI `tool_calls.arguments` 统一攒整段 + 完成事件单次 `json-aware` flush。
- 补齐跨分片 token 保护与通道覆盖：扩展候选感知类型、对齐 fast/slow 行缓冲、补 `refusal` 通道进缓冲。

## Capabilities

### New Capabilities

- `streaming-restore-fidelity`: SSE 流式还原的结构保真（事件重建保留上游结构、多行块逐行还原、序列化口径统一）。
- `tool-call-integrity`: 工具调用完整性（参数攒整段、完成事件单次 flush、阻断后不泄漏残缺参数、不误杀正常 content）。
- `cross-shard-token-safety`: 跨分片 token 安全（残缺前缀 hold、候选感知扩展、fast/slow 行缓冲对齐、无换行持有上限）。
- `rework-followup`: 返工收尾（死代码去留收敛、最小断言三件套、回退透传语义、refusal 独立重建、多 data 行逐条解析与截断对齐）。

### Modified Capabilities

- 无（本仓库 `openspec/specs/` 尚未建立，全部按新能力建 spec）。

## Impact

- 影响代码：`_llm.py`（SSE 主循环 slow/fast 双链、`_pii_process_sse_line`、`_flush_*_buf`、`_handle_*_event`、`_mk_*_event` 系列）、`utils/json_walk.py`（仅复用，不改语义）、`_token.py`（仅复用正则，不改 token 格式）。
- 影响协议：OpenAI `chat/completions`、Anthropic `v1/messages`、OpenAI `v1/responses` 三协议流式。
- 不影响：token 格式（`__VG_CRED__/__PII__`）、请求侧脱敏语义、审计 verdict 语义、部署与 API。
