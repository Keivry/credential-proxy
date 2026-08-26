## Purpose

加固流式 SSE 三层缓冲与终止/保活语义，保证 WHATWG 帧完整性、正文本按行替换不切断 token、工具参数攒整段不炸转义，且长持有有保活不超时。

## ADDED Requirements

### Requirement: SSE 帧完整性与空行/注释透传（WHATWG）

系统 SHALL 对上游 `text/event-stream` 按 WHATWG `stream = [BOM] *event` / `event = *(comment/field) end-of-line` / `end-of-line = CRLF/LF/CR` 分行，其中 `BOM`（`U+FEFF` / `0xEF 0xBB 0xBF`）仅在流首字节单次剥离一次（`EF`/`BB`/`BF` 被 TCP 分片时累积 ≥3 字节后判定）；末尾孤立 `\r` 需跨 chunk 粘合判定（不立即 `replace` 为 `\n` 误判空行），`comment = ":" *any-char`（含 `: keepalive` 保活）与空行透传不走 `field` 解析（注释行不经 `walk`/`_strip_partials` 但中间日志 `response_original.jsonl` 需审计）；`field = 1*name-char [":" [space] *any-char]` 其中 `space` 仅为 `U+0020` 单空格；每事件以空行 `end-of-line` 分隔后才聚合 `data` 字段，同一事件内多 `data:` 行按 WHATWG 以 `\n` 拼接为单一 `payload`（proxy 单 `data:` 行亦合法，按单行 `payload` 处理）；`data:` 字段值按 `line.split(":",1)[1]` 取值后若以单空格开头则剥离该空格，再 `lstrip("\ufeff")`（防 `BOM` 黏连）后判空/`[DONE]`/非 JSON 早退，否则走共享 walk；`event`/`id` 透传不参与 `payload` 合并；`retry` 仅当值全为 ASCII 数字时透传否则丢弃（WHATWG `retry` 校验）；`safe` 侧经 `_strip_partials` 后再转发。

#### Scenario: CRLF 与 CR 单行不误判

- **WHEN** 上游以 `CRLF` 或单 `CR` 分隔 SSE 行
- **THEN** 仍按 WHATWG 先归一 `CRLF→LF` 与 `CR→LF` 后按 `LF` 分行，不残留 `\r`

#### Scenario: 注释保活不被解析

- **WHEN** 行以 `:` 开头（如 `: keepalive` 或 `:` 空注释）
- **THEN** 透传不 `json.loads`，不记 `sse_event_count`，不走共享 walk

#### Scenario: 半行重建不误判 JSON

- **WHEN** 上游将 `data: {"a":1}\n` 在 `{"a` 处跨 chunk 截断为 `data: {"a` + `":1}\n`
- **THEN** 第一 chunk 不判为 JSON 不替换，第二 chunk `byte_buf` 重建后走 walk，无 `JSONDecodeError`

### Requirement: 正文本逻辑行缓冲（line_buf）

系统 SHALL 对 `delta.content` / `delta.reasoning_content`/`delta.reasoning`（厂商扩展兼容） / `delta.refusal`（含 Anthropic `text`/`thinking` 的 `text_delta`/`thinking_delta`/`signature_delta` 豁免不进 `line_buf`，Responses `output_text`/`reasoning_text`/`refusal`/`reasoning_summary_text`/`audio.transcript` 的 `delta`，以及 `code_interpreter_call_code.delta`/`shell_call_command.delta` 等文本载荷）做逻辑行缓冲（`line_buf` 阈值 `16KB/30s` 对 Chat/Anthropic/Responses 三协议文本 `delta` 均生效，`_handle_responses_event`/`_handle_anthropic_event` 同阈值）：`delta_text.replace('\r\n','\n').replace('\r','\n')` 预归一后 `line_buf += delta_text; while '\n' in line_buf: line,line_buf = split('\n',1); line+='\n'; restored=_pii_response_process(line); safe=_strip_partials(restored); emit(safe)`；无 `\n` 时整行持有不 flush，**除非命中超长强制阈值（`LINE_BUF_FLUSH=16KB` 或 `LINE_BUF_MAX_AGE=30s`）则按 Requirement 超长强制处置**。

#### Scenario: 跨分片 token 在同一行内还原

- **WHEN** `__PII_12` 在行1 `data:` 的 `delta` 尾与行2的 `delta` 首跨 `data:` 行切断，但同属正文同一逻辑行 `\n` 内
- **THEN** `line_buf` 将两段合并后同一行内还原，不发残缺 `__PII_12`

#### Scenario: 无换行短答仅行级持有

- **WHEN** 回答为 `密码是 123...` 50 字无 `\n` 且累计 `<16KB` 且持有 `<30s`
- **THEN** 至流末 `\n` 前持有不转发，流末一次性 flush（配合 16KB/30s 兜底不超时）

#### Scenario: 邮箱与 IP 行内不泄漏

- **WHEN** 行内含 `user@exa` + `mple.com` 跨 `data:` 切断
- **THEN** 同一行内合并后判定，不提前 flush 片段邮箱

#### Scenario: refusal 同行缓冲不泄漏
- **WHEN** 上游 `delta.refusal` 含 `13800138000` 且跨 `data:` 行切断
- **THEN** `line_buf` 同正文本行缓冲合并后还原，不旁路透传

#### Scenario: 多 choices 遍历不漏还原
- **WHEN** 上游 `choices` 含 `n=2` 且 `choices[1].delta.content` 含 `__PII_1_ab12cd34__`
- **THEN** 遍历 `choices[]` 全量，`choices[1]` 同样经 `line_buf` 还原

#### Scenario: 多 data 行同事件聚合
- **WHEN** 同一 SSE 事件含两行 `data: {"choices":[{"delta":{"content":"a"}}]}` 与 `data: {"choices":[{"delta":{"content":"b"}}]}` 以空行分隔前未 `dispatch`
- **THEN** `data:` 值以 `\n` 拼接为单一 `payload` 后再 `loads`，不按单行误判 JSON

#### Scenario: 空 data 行保留空行（WHATWG last LF 等价）
- **WHEN** 同一事件含 `data: a` / `data:` / `data: b` 三行（中间为空 `data:` 行）
- **THEN** 以 `\n` 拼接为 `a\n\nb`（WHATWG `data buffer` 先 append `\n` 后剥最后 `\n` 的等价 `join`），不丢空行

#### Scenario: CRLF 跨 chunk 不误判空行
- **WHEN** 上游 chunk 边界切在 `\r`|`\n` 之间（前 chunk 末尾孤立 `\r`，后 chunk 首 `\n`）
- **THEN** 不将孤立 `\r` 立即转为 `\n` 触发空行 `dispatch`，待下 chunk 到达后整体按 `CRLF` 一次归一

#### Scenario: BOM 跨 chunk 仍剥离
- **WHEN** 流首 `0xEF 0xBB 0xBF` 被分片为 `EF`|`BB BF` 两 chunk
- **THEN** 累积 ≥3 字节后仍单次剥离，不因分片残留 `EF` 导致首行解析失败

### Requirement: 工具参数攒整段与 JSON-aware（arg_buf）

系统 SHALL 对 `tool_calls[].function.arguments` / `function_call.arguments`（deprecated） / Anthropic `input_json_delta.partial_json`（`signature_delta` 不含文本不进 `arg_buf` 仅透传） / Responses `function_call_arguments.delta` / `mcp_call_arguments.delta` / `custom_tool_call_input.delta` / `code_interpreter_call_code.delta` / `shell_call_command.delta` 等 stringified JSON/参数做 `arg_buf += delta` 攒整段（`audio.delta` 为音频字节不进 `arg_buf`/`line_buf`，`audio.transcript.delta` 文本进 `line_buf`；`file_search/web_search/image_generation/computer_call` 等 `succeeded/searching/in_progress` 中间态不进缓冲仅透传），仅在 `chat: finish_reason in (tool_calls, function_call, stop, length, content_filter) 或 [DONE]` / Anthropic `content_block_stop` / Responses `response.output_item.done` / `response.content_part.done` / `response.output_text.done` / `response.function_call_arguments.done` / `response.mcp_call_arguments.done` / `response.custom_tool_call_input.done` / `response.code_interpreter_call_code.done` / `response.mcp_call.done` / 通用 `item_done` 完成时才 `json_aware walk` + `audit hold` 后一次性 flush；攒段期间不按 `\n` 切分。

#### Scenario: 跨行 arguments 不炸转义

- **WHEN** 行1 `arguments="{\"phone\":\"138"` 行2 `00138\"}"`
- **THEN** 单行不走 plain replace，攒整段后 `json_aware` 逐叶转义不抛 `Expecting ',' delimiter`

#### Scenario: 空 delta 与非字符串早退

- **WHEN** `partial_json` 为空字符串或非字符串
- **THEN** 当 `other` 透传或 `arg_buf` 空操作，不中断流

### Requirement: 多 choices 全量遍历

系统 SHALL 在流式场景遍历 `choices[]` 全量而非仅 `choices[0]`，任一 `choice` 的 `delta` 均按上述 `line_buf`/`arg_buf` 分流处理。

#### Scenario: 多 choices 遍历不漏还原

- **WHEN** 上游 `choices` 含 `n=2` 且 `choices[1].delta.content` 含 `__PII_1_ab12cd34__`
- **THEN** `choices[1]` 同样经 `line_buf` 还原

### Requirement: SSE 注释保活（keepalive）

系统 SHALL 在 `line_buf` 或 `arg_buf` 持有期间每 `KEEPALIVE_INTERVAL=10s` 以 SSE 注释 `": keepalive\n\n"` 保活（非 `data:` 事件，按 WHATWG `comment` 行客户端忽略，不计 `sse_event_count`），每次真数据 `_tracked_write` 后重置计时。

#### Scenario: 持有期间保活不超时

- **WHEN** `line_buf` 因无 `\n` 持有 25s 且无真数据写入
- **THEN** 第 10s 与第 20s 各发一次 `: keepalive\n\n`，`hermes inactivity 120s` 不触发 `SSE_CLIENT_GONE`

#### Scenario: 真数据重置保活计时

- **WHEN** 持有期间第 8s 写入真数据
- **THEN** 保活计时重置，下次保活在写入后 10s 而非流首后 10s

### Requirement: 超长逻辑行强制 flush

系统 SHALL 对单逻辑行累积超 `LINE_BUF_FLUSH=16KB` 或持有超 `LINE_BUF_MAX_AGE=30s` 即使无 `\n` 也按 `_split_safe_hold` 前缀候选感知（`_has_partial_pii_candidate`：`\b\d{1,3}\.(?:\d{1,3}\.){0,2}$` / `[A-Za-z0-9._%+-]+@$` / `fe80::[0-9a-f:]*$`）兜底强制 flush 并审计，`safe` 侧经 `_strip_partials` 清洗。

#### Scenario: 长无换行行 16KB 强制

- **WHEN** 正文 10KB 无 `\n` 持续持有
- **THEN** 累积达 16384 字节时触发前缀候选感知 `safe/pending` 切分后 `safe` 立刻转发，剩余 `pending` 继续持有

#### Scenario: 长持有 30s 强制

- **WHEN** 正文 2KB 无 `\n` 持有达 30s
- **THEN** 即使未达 16KB 也触发同上强制 flush 并审计

### Requirement: 流末截断合成与 seen_terminal 判定

系统 SHALL 在流末 `!seen_global_terminal && (byte_buf/line_buf/arg_buf/data_buffer 非空)` 时合成对应协议的终止事件并 `logger.warning`（chat 补 `finish_reason:stop + [DONE]`；anthropic 补 `message_stop`；responses 补 `response.failed id:truncated status:failed`），其中 `seen_global_terminal` 定义为已观测到任一全局终止：`data: [DONE]` / `finish_reason != None`（含 `stop/length/tool_calls/function_call/content_filter`） / Anthropic `message_stop` / Responses `response.completed` / `response.failed` / `response.incomplete`；`content_block_stop` / `response.output_item.done` / `response.content_part.done` / `response.output_text.done` / `response.function_call_arguments.done` / `response.mcp_call_arguments.done` / `response.custom_tool_call_input.done` / `response.code_interpreter_call_code.done` / `response.mcp_call.done` / 通用 `item_done` 仅为工具/块级完成（清 `arg_buf`）不计 `seen_global_terminal`；`error`/`ping` 不计终止，合成后合并审计 `hold` 并清空缓冲。

#### Scenario: 无 finish_reason 的流正常结束不丢 hold

- **WHEN** 上游流正常结束但无 `finish_reason`/`[DONE]` 仅连接关闭且 `line_buf` 非空
- **THEN** `line_buf` 中完整候选经还原后 flush，不丢，且不合成 `failed`（因已 `seen_terminal` 为假但 `byte_buf` 非空才合成；若 `line_buf` 为空则不合成）

#### Scenario: 截断合成不丢 arg_buf

- **WHEN** 上游因 `max_tokens` 截断且 `arg_buf` 非空且 `!seen_terminal`
- **THEN** 合成对应协议的 `tool_calls`/`output_item.done` 终止事件并审计 `tool_call(name, args)`，不静默丢弃，且 `logger.warning` 含 `truncated` 标识

#### Scenario: 已见终止不二次合成

- **WHEN** 已观测 `response.completed` 或 `message_stop` 且 `byte_buf` 残留空行
- **THEN** 不再合成 `failed`，仅清空缓冲

#### Scenario: 空流守门（永不透出 200 空体）
- **WHEN** 上游 `status==200` 但 `bytes_written==0` 且 `!seen_global_terminal`（0 `data` 事件即断流）
- **THEN** 仍合成最小可解析终止事件（`[DONE]`/`message_stop`/`response.failed`），不透出空体，`logger.warning` 含 `truncated/empty_stream`

#### Scenario: data_buffer 残留亦触发截断
- **WHEN** 上游以 `data: {"x":1}` 不带末空行直接断流（`data_buffer=["{...}"]` 非空但 `byte_buf` 已空）
- **THEN** 判 `data_buffer` 非空亦触发合成/审计，不因待 `dispatch` 而静默丢弃末事件

