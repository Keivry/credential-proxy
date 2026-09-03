## Context

见 `proposal.md` Why。现状：`_llm.py` SSE 主循环 slow/fast 双链 + 三协议事件处理（`_handle_anthropic_event` / `_handle_responses_event` / chat 主循环）+ 三层缓冲（`byte_buf` 分帧 / `content_buf,reasoning_buf` 行缓冲 / `arg_buf` 参数累积）。约束：token 格式不变、审计 verdict 语义不变、Python 3.10 兼容、ruff 必须过。

## Goals / Non-Goals

**Goals:**

- 事件重建保真：结构保留 + 序列化口径统一 + 多行块逐行还原。
- 工具参数完整：三协议统一攒整段，deny 丢弃残缺，不误杀文本。
- 跨片安全：残缺 hold + 候选感知全类型 + 快慢链对齐。

**Non-Goals:**

- 不改请求侧脱敏语义与 PII 检测正则（指 `_pii.py` 检测表达式本身；候选持有前缀族的扩展仅作用于流式持有等待，不改变检测命中语义）。
- 不改 token 格式与全局 LRU 语义。
- 不做性能重构（保持摊还 O(1) 缓冲语义）。

## Decisions

### D1. 结构保留重建替代裸最小事件

- 内容：`_mk_sse_event` / fast 流末合成 / `_flush` 改走 deepcopy 原解析对象仅替换 delta 字段（已有 `_fast_rebuild_chunk` 模式向全链推广）。逐路规则：按 `choices[i].index` 定位目标路，仅替换该路 `delta.content/delta.reasoning_content/delta.tool_calls`，禁止把同一 `content` 广播到所有路；`id/created/model/system_fingerprint/usage/finish_reason` 按原值原位保留，还原只改文本叶。
- 序列化口径：全链 SSE `data:` 重建统一走 `_jdumps（ensure_ascii=False、separators=(',',':')）`，其底层为 orjson 优先、缺失时回退标准库（`utils/json_walk.py` 与 `_llm.py/_token.py/_pii.py` 四处同口径：`_USE_ORJSON` 为真走 `orjson.dumps().decode()`，否则 `json.dumps(ensure_ascii=False, separators=(',',':'))`）；裸 `json.dumps` 按下表 7 处逐一替换；测试快照与白名单内阻断合成占位构造除外，且须经 `_jdumps` 等价性断言：
  1. `_mk_sse_event` 裸拼装最小 chat chunk；
  2. fast 链流末合成兜底 chunk；
  3. slow 链 `_build_block_event（chat）` 拒绝/兜底合成；
  4. `_build_block_event_responses` 合成；
  5. `_build_block_event_anthropic` 合成；
  6. `tool_calls_pending_events` 缓冲重放 `dumps`；
  7. `_flush_*_buf` 透传行与续行重建 `sanitized dumps`。
- 理由：下游 SDK 按 `id/model/choices` 校验，裸事件丢字段即破坏契约；deepcopy 成本每事件一次可接受；统一 `_jdumps` 消除空格/`\u` 转义漂移。
- 备选：维持裸事件 + 下游放宽校验 → 否决，无法约束所有下游。

### D2. 拼块逐行独立解析，event 行不进还原

- 内容：`_pii_process_sse_line` 多行块分支每 `data:` 行独立 `loads`，`parsed_obj` 不再跨行复用；`slow_event_pending` 的 `event:/id:` 行拼块后原样保留。
- 理由：单对象复用是错配根因；event 名无文本语义，进还原只增误删风险。
- 备选：整块单次 walk → 否决，多 `data:` 拼接必非法 JSON。

### D3. 缓冲事件单次还原

- 内容：`tool_calls_pending_events` 放行路径只还原一次，移除 verdict 后二次 `_pii_process_sse_line`；校验失败走 `_strip_partials` 清理而非回退原串。
- 理由：二次还原是漂移与泄漏回退的直接来源。
- 备选：保留二次但加幂等标记 → 复杂度更高，否决。

### D4. 参数攒整段 + 完成事件单次 flush

- 内容：Anthropic `partial_json` / Responses `function_call_arguments` / OpenAI `tool_calls.arguments` 统一 `arg_buf+=delta`，仅 `block_stop/item_done/finish_reason=tool_calls` 单次 `json_aware` + 审计 + flush；`tool_calls_blocked` 判定改结构化（`delta.tool_calls is not None`）替代子串匹配。通道对齐：Anthropic `thinking_delta/input_json_delta`、Responses `reasoning_text/function_call_arguments_delta`、OpenAI `reasoning_content/tool_calls.arguments` 三者同等走“攒整段 + 完成事件单次 flush”，中间分片零写出；未识别形态走整行透传不抑制。
- 理由：逐片 `json_aware` 在不完整 JSON 上必回退 plain 而泄漏；子串匹配误杀 content。
- 备选：逐片还原 + pending 补偿 → 已验证泄漏，否决。

### D5. 候选感知扩展 + 快慢对齐

- 内容：`_has_partial_pii_candidate` 扩展为内置全类型前缀族（`email/phone/id_card/bank_card/ipv4/ipv6/api_key`）+ `__VG_CRED__/__PII__` 保留前缀全覆盖；自定义规则仅 best-effort（仅对其已加载正则字面前缀做持有，未命中不阻塞主链，计 `custom_other` 候选未命中）；fast TTFB 快路（<64 直接透传）移除或与 slow 同阈值；`refusal` 通道（`delta.refusal` / Responses `refusal.delta`）纳入与 `content` 同一行缓冲（`LINE_BUF_FLUSH=16KB/LINE_BUF_MAX_AGE=30s`）；`reasoning_content/delta.reasoning` 按 `choices[i].index` 独立累积状态，但与 `content/refusal` 共用同一 `16KB/30s` 阈值常量（不另设阈值；缓冲实例按路独立，阈值语义共享）；`finish_reason` 按路独立归属，多路竞态先到先定、后到同路覆盖、异路不互斥（不得以后到异路覆盖先到，也不得因一路终止截断另一路 delta）。
- 分帧与截断：fast 链补 WHATWG `CRLF/CR` 切行与 slow 对齐（`:` 注释透传、`retry:` 仅 ASCII 数字、`data:` 单空格剥离同口径）；`SSE_MAX_BUF=1MB` 截断后经 `rfind` 定位安全边界并清理 `fast_data_buffer` 残留，残留不得与后续事件叠加（对应 tasks 3.2）。
- 理由：短分片跨 `data:` 是真实泄漏形态；双链不对称是旁路根因；自定义全量阻塞会引入无限持有，降级为 best-effort 保主链活性；reasoning/finish_reason 不对齐则三通道语义分裂。
- 备选：仅 slow 修、fast 保持 TTFB 优先 → 泄漏面保留，否决；自定义全阻塞 → 无限持有风险，否决。

## Risks / Trade-offs

- [Risk] deepcopy 全链增加每事件开销 → Mitigation：仅 chat/Responses/Anthropic 需重建路径使用，透传路径零拷贝保持。
- [Risk] 攒整段增大 `arg_buf` 内存（超大参数）→ Mitigation：复用现有 `SSE_MAX_BUF=1MB` 截断 + 审计 hold 上限，超限 fail-closed 丢弃。
- [Risk] 结构化 `tool_calls` 判定漏掉非标准网关形态 → Mitigation：保留 `finish_reason` 兜底 + 未识别走整行透传不抑制。

## Migration Plan

1. 按 `tasks.md` 分 D1~D5 落地，每步跑 `pytest -q` + `ruff check`。
2. 用 `tests/sse_stream_loop_test.py` + `api_spec_conformance_test.py` 回归三协议。
3. 回滚：单 change 内 revert `_llm.py` 相关 hunk，不涉及数据迁移。

## Open Questions

- 无。`refusal` 是否与 `content` 共用同一行缓冲阈值（16KB/30s）按现有常量复用，不另设阈值。
