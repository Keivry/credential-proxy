## Purpose

保证 LLM 代理在任何上游异常、审计拦截、PII 剥离或并发交织下，对 LLM 对话端点永不向客户端返回 200 空体或空 SSE 流，确保 hermes 等调用方可解析并可观测，避免 JSONDecodeError 重试后沉默。

## ADDED Requirements

### Requirement: 流式与非流式永不透出 200 空体

系统 SHALL 在所有 LLM 对话端点（`chat/completions` / `v1/messages` / `v1/responses`）的流式与非流式路径上，永不向客户端返回 `200` 且空体/`0 data events` 的响应。当上游返回 `200` 但实际未向客户端写入任何字节时，系统 SHALL 兜底注入按协议形态的最小可解析内容或转为 `502`，并记录错误日志。

#### Scenario: 上游空流被兜底注入

- **WHEN** 上游对 `v1/responses` 返回 `200` 且 `content-type: text/event-stream` 但 0 个 `data:` 事件
- **THEN** 代理不返回 `200 0 bytes`，而是注入一条按 `v1/responses` 形态的 `response.output_text.delta` 事件（或 `chat/completions` / `v1/messages` 对应形态），`hermes` 可解析，日志记 `LLM 上游返回空流已兜底`

#### Scenario: fast 路径空流同样兜底

- **WHEN** `fast` 路径（无 `audit/pii`）上游对 `chat/completions` 返回 `200` 但 `fast_bytes_written==0`
- **THEN** 同样按 `tail` 形态注入 `chat` 事件，与 `heavy` 守门一致，仅 `upstream.status==200` 时注入

#### Scenario: 审计 hold 悬挂不导致空流

- **WHEN** 流式处理中已进入 `audit_hold`（等待 `item_done` 审计），上游在 `item_done` 前断流
- **THEN** 流末 SHALL 强制按 `rejected` 处置 `hold`（丢弃缓冲或注入拒绝），并按 `bytes_written==0` 守门注入，确保客户端收到至少一条可解析事件而非空流

#### Scenario: 非流式剥离后空体转 502

- **WHEN** 非流式上游返回非空 `JSON`，但经 `_pii_response_process` + `_strip_token_forms` 剥离幻觉 token 后结果为空白
- **THEN** 代理不返回 `200 空 JSON`，而是返回 `502` 且 `content-type: application/json`，`body={"error":{"message":"empty after strip"}}`，并记 `error` 日志

#### Scenario: 上游 502/401 不误判为空流注入

- **WHEN** 上游返回 `502` 或 `401` 且带 `JSON` 错误体
- **THEN** 代理按原状态码透传该 `JSON` 错误体，不触发空流注入

### Requirement: 空体守门按实际写入字节判定

系统 SHALL 以“是否真正向客户端 `resp` 写入过字节”（`bytes_written` 仅 `await resp.write` 成功计数，`SSE_CLIENT_GONE/ConnectionResetError` 不计）作为空体判定依据，而非仅 `sse_event_count`。`heavy` 与 `fast` 两路径、三种协议形态的守门逻辑 SHALL 一致，且仅当 `upstream.status==200` 时触发注入（`502/401` 透传）。

#### Scenario: 有 data 计数但未写入仍视为需兜底

- **WHEN** 上游发送了 `data:` 行（`sse_event_count>0`），但因 `audit_hold` 缓冲或 `safe/pending` 持有导致实际 `bytes_written==0`
- **THEN** 流末仍判定为需兜底并注入

### Requirement: 流式错误可观测

系统 SHALL 在空流兜底、非空剥离、以及 `hold` 悬挂强制处置时记录结构化错误日志（包含 `method/target/status/bytes`），便于与 `hermes JSONDecodeError` 关联排查。

#### Scenario: 空流日志与 hermes 关联

- **WHEN** 触发空流兜底
- **THEN** 日志包含 `target_url` 与 `bytes`，且 `hermes` 侧不再出现 `JSONDecodeError` 重试 5 次后沉默

