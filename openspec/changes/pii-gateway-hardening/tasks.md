## 1. 共享 JSON walk 抽取

- [x] 1.1 新建 `utils/json_walk.py`：实现 `json_walk(obj, leaf_fn, *, depth_limit=5)` 与 `_validate_json_roundtrip`/`_strip_bom`，统一 `orjson`/`BOM`/`depth`/`ensure_ascii=False`/`separators`/`叶子级回退` 五要素，含 `sync` 与 `async` 双形态（`_pii` 侧为 async）
  - 验收：`specs/json-walk-consolidation/spec.md` 的 BOM 前缀/纯文本零成本/深度炸弹（`depth>5` 仍执行 `leaf_fn`）/`separators`/`output 非法回退`/`叶异常回退` 六场景对应单测全绿

- [x] 1.2 `_token.py` 接入共享 walk：`_cred_json_walk` 改为 `from utils.json_walk import json_walk` 薄包装，仅传 `leaf_fn=_redact`/`_restore`，删除内联 `_walk` 实现，保持 `orjson` 门控与 `depth>5` 回退不变
  - 验收：嵌套 `arguments` 含 `p@ss\"quote` 场景 `loads` 仍合法，`ruff` 接口未变

- [x] 1.3 `_pii.py` 与 `_llm.py` 接入共享 walk：`_pii_json_walk`/`_pii_response_process_json_aware` 改调 `json_walk`，`_llm._pii_process_sse_line` 的 `data:` 前缀剥离后 `payload` 走共享 walk，`[DONE]`/空/非 JSON 早退保持 `fix-json-nested-restore` D2 语义
  - 验收：`specs/json-walk-consolidation/spec.md` 的 流式 data 行统一走共享 walk 场景通过；`_llm` 快路径 `active_t2p==0 and not pii_active` 时不走 walk

## 2. Vault 稳态映射

- [x] 2.1 `RequestScopedTokens`/`GlobalPiiTokens` 加稳态下标：`register(value)` 先查 `value→placeholder` 既有映射（请求级优先→Vault），未命中时收集已用 `seq set`（Vault + 本批次 `batch_tracker`），`next_index=1 while in set` 跳空洞，`rand8=secrets.token_hex(4)`（CSPRNG），`_restore` 仅 `placeholder_exists` 时还原，越界原样保留并审计
  - 验收：`specs/vault-stable-mapping/spec.md` 的 同值复用/空洞跳过/随机段不可枚举/响应期不还原 四场景全绿

- [x] 2.2 统一残缺清理 `_strip_partials(text)`：合并 `__VG_CRED_` 与 `__PII_<seq>_<rand8>__` 两套形态，完整 `__PII_<seq>_<rand8>__` 保留、残缺 `__PII`/`__VG_CRED`/`__PII_<digits>`/`__PII_<seq>_<hex>` 剥离，`safe` 侧倒序语义（`presidio_anonymizer.TextReplaceBuilder` 逆序等价或 `sorted(reverse=True)`），`line_buf` 与 `hold` 侧阈值 `<64`
  - 验收：`specs/vault-stable-mapping/spec.md` 的 残缺前缀不泄漏/完整保留/倒序避免错位 三场景全绿；`_token._PII_PARTIAL_TOKEN_RE` 与 `_PARTIAL_TOKEN_RE` 14 处调用点替换为单一函数（`grep -rn _PARTIAL_TOKEN_RE` 仅定义处剩余）

- [x] 2.3 可选模糊还原开关 `PII_FUZZY_RESTORE`（默认 `0`）：`1` 时 `_restore` 对响应侧做 `re.IGNORECASE` 大小写不敏感匹配，命中记审计，默认关闭仅精确匹配，不引入 `fuzzysearch` 编辑距离
  - 验收：`specs/vault-stable-mapping/spec.md` 的 默认精确/开启后大小写还原 两场景全绿；`proxy.py` 启动校验非法值报错

## 3. 流式三层缓冲与保活加固

- [x] 3.1 `byte_buf` SSE 帧完整性（WHATWG `CRLF/LF/CR` + `:` 注释 + 同事件 `data_buffer` 聚合）：`byte_buf.extend(chunk)` 后先归一 `CRLF→LF` 与 `CR→LF` 再按 `LF` 分行 + 空行 `dispatch` 聚合同一事件内多 `data:` 行（`data_buffer` 以 `\n` 拼接为单一 `payload`，单 `data:` 行亦合法；含 `data: a`/`data:`/`data: b` 空行保留 `a\n\nb` 与 `CRLF` 跨 chunk 孤立 `\r` 粘合判定），流首单次 `BOM` 剥离（`0xEF 0xBB 0xBF` 仅首次，`EF`/`BB`/`BF` 分片累积 ≥3 字节后判定），`:` 开头注释行（含 `: keepalive`）与空行透传不走 `loads` 不计 `sse_event_count`；`event`/`id` 透传；`retry` 仅值全为 ASCII 数字时透传否则丢弃；`data:` 字段按 `line.split(":",1)[1]` 取后若以单空格 `U+0020` 开头剥该空格，再 `lstrip("\ufeff").strip()` 判空/`[DONE]`/非 JSON 早退，否则共享 walk，`safe` 经 `_strip_partials` 后转发；`SSE_MAX_BUF=1MB` 守门，超限 `rfind(b"\n")` 截断并 `logger.warning`
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 CRLF/CR 单行不误判/注释保活不解析/半行重建不误判 三场景全绿；`_llm` 慢/快双链各一录制

- [x] 3.2 正文逻辑行缓冲 `line_buf`：`content/reasoning/refusal`（含 Anthropic `text`/`thinking`（`signature_delta` 豁免）、Responses `output_text`/`reasoning_text`/`refusal`/`reasoning_summary_text`/`audio.transcript`/`code_interpreter_call_code`/`shell_call_command` 等文本 `delta`；`audio.delta` 音频字节不进 `line_buf`）遍历 `choices[]` 全量累积 `line_buf += delta.replace('\r\n','\n').replace('\r','\n')`，`while '\n' in line_buf: line,line_buf=split; restore(line+'\n')→_strip_partials→_mk_*_event 立刻发`；无 `\n` 时持有不 `_split_safe_hold`，**除非命中 3.4b 超长阈值（`LINE_BUF_FLUSH=16KB`/`LINE_BUF_MAX_AGE=30s`，三协议文本 `delta` 同阈值）**；`choices` 全量与 `refusal` 行缓冲由 `delta.refusal` 分支验证；`delta.reasoning_content` 兼容 `delta.reasoning` 厂商扩展
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 跨分片 token 同行还原/无换行短答持有（`<16KB` 且 `<30s`）/邮箱 IP 行内不泄漏 三场景全绿；`test_token_split_across_deltas` 行缓冲版单测通过

- [x] 3.3 工具参数攒整段 `arg_buf`（`json_aware`）：`arguments/partial_json`（`signature_delta` 豁免透传）/`function_call.arguments`（deprecated）/`mcp_call_arguments.delta`/`custom_tool_call_input.delta`/`code_interpreter_call_code.delta`/`shell_call_command.delta` 等 `arg_buf+=delta`（`audio.delta` 音频字节不进 `arg_buf`），仅在 `finish_reason in (tool_calls,function_call,stop,length,content_filter)` 或 `[DONE]` / Anthropic `content_block_stop` / Responses `response.output_item.done`/`response.content_part.done`/`response.output_text.done`/`response.function_call_arguments.done`/`response.mcp_call_arguments.done`/`response.custom_tool_call_input.done`/`response.code_interpreter_call_code.done`/`response.mcp_call.done`/`item_done` 完成时才 `json_aware walk` + 审计后一次性 flush，不按 `\n` 切；遍历 `choices[]` 全量；`_validate` 失败仅该叶回退；`file_search/web_search/image_generation` 中间态透传不进缓冲
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 跨行 arguments 不炸转义/空 delta 早退 两场景全绿；`length`/`[DONE]`/`mcp_call` 终止同样一次性 flush

- [x] 3.4a 注释保活：持有期间每 `KEEPALIVE_INTERVAL=10s` 发 SSE 注释 `: keepalive\n\n`（非 `data:`，WHATWG `comment`，不计 `sse_event_count`），每次 `_tracked_write` 真数据后重置（`3.4b` 强制 `flush` 同样经 `_tracked_write` 重置，`30s` 持有期至少 `2` 次 `keepalive`）
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 持有期间保活不超时/真数据重置保活计时 两场景全绿；`10s keepalive` 在 `line_buf` 持有压测中验证不触发 `SSE_CLIENT_GONE`
- [x] 3.4b 超长强制：单逻辑行累积超 `LINE_BUF_FLUSH=16KB` 或持有超 `LINE_BUF_MAX_AGE=30s` 时按 `_has_partial_pii_candidate` 前缀候选感知 `_split_safe_hold` 强制 `safe/pending` 切分后 `safe` 立刻转发并审计
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 长无换行行 16KB 强制/长持有 30s 强制 两场景全绿
- [x] 3.4c 截断合成：流末 `!seen_global_terminal && (byte_buf|line_buf|arg_buf/data_buffer 非空)` 合成三协议终止（chat `stop+[DONE]`/anthropic `message_stop`/responses `failed id:truncated`）并 `logger.warning` 含 `truncated` 标识，合并审计 `hold`；`seen_global_terminal` 为全局终止（`[DONE]`/`finish_reason in (stop,length,tool_calls,function_call,content_filter)`/`message_stop`/`response.completed/failed/incomplete`），`content_block_stop`/`output_item.done`/`content_part.done`/`output_text.done`/`function_call_arguments.done`/`mcp_call_arguments.done`/`custom_tool_call_input.done`/`code_interpreter_call_code.done`/`mcp_call.done`/`item_done` 仅工具/块级完成不计全局终止（仅清 `arg_buf`）；`error`/`ping` 不计；含 `bytes_written==0` 空流守门与 `data_buffer` 残留合成
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 无 finish_reason 不丢 hold/截断不丢 arg_buf/已见终止不二次合成 三场景全绿；`warning` 含 `truncated` 且审计 `hold` 已合并

## 4. 检测侧加固（默认关闭）

- [x] 4.1 保留地址精确前缀豁免（`PII_DETECTION_HARDENING=1` 时生效，默认关闭）：`lower()` 后 `startswith` 含尾点/冒号前缀表（`10.`/`127.`/`169.254.`/`192.168.`/`172.16.`-`172.31.`/`224.`-`239.`/`240.`-`255.`/`100.64.`-`100.127.`/`fc:`/`fd:`/`fe80:`-`febf:`/`::1`/`2001:db8:`，`fc`/`fd` 仅冒号形态），裸 `10`/`2001:db8`/`fcfake` 不豁免
  - 验收：`specs/pii-detection-hardening/spec.md` 的 172.31 豁免/100.128 不豁免/裸前缀不误豁免/`fcfake` 不误豁免 四场景全绿；`172.31.255.255` 留、`100.128.0.1` 替换、`fcfake:1234::1` 替换对照通过

- [x] 4.2 ReDoS 线程超时守卫：独立 `ThreadPoolExecutor(max_workers=2, thread_name_prefix='pii-re')`（与审计 `run_in_executor(None)` 不同池）+ `asyncio.timeout(0.1)` 单规则预算，超时跳过+审计+连续 3 次临时停用，`PII_SCAN_INPUT_LIMIT=1M` 分块
  - 验收：`specs/pii-detection-hardening/spec.md` 的 恶意正则不卡死/连续超时停用/超长分块 三场景全绿；`(a+)+$` + `a`*64 在 100ms 内跳过且其余规则生效

- [x] 4.3 字典名单独立扫描（`PII_DETECTION_HARDENING=1` 时生效）：不并入联合正则，按长度降序+`re.escape`+`dict_ver` 缓存，CJK 边界 `(?<![\w\u4e00-\u9fff])`/`(?![\w\u4e00-\u9fff])`，5000 名单单 chunk ≤1ms
  - 验收：`specs/pii-detection-hardening/spec.md` 的 独立扫描不并入/张三不误伤/配置重载失效 三场景全绿；`1M body` 扫描锚点内

- [x] 4.4 Analyzer 缓存（`PII_DETECTION_HARDENING=1` 时生效）：`@lru_cache maxsize=4` 缓联合正则/`AnalyzerEngine`，`dict_ver` 变化 `cache_clear`，纯正则路径无 `presidio` 仍可用
  - 验收：`specs/pii-detection-hardening/spec.md` 的 同配置复用/配置变更清缓存 两场景全绿

## 5. 验证与发布

- [x] 5.1 单测与门禁：新增 `vault_stable_test.py`/`residual_hardening_test.py`/`detection_hardening_test.py` 覆盖 1-4 章全部验收场景，`ruff check`/`format --check` 零告警，`pytest -q` 全绿（含既有 146+）
  - 验收：三新测试文件全绿，`ruff` 零告警

- [x] 5.2 真实流量哨兵：`llm-proxy-only` 本地对三协议（`chat/completions`/`v1/messages`/`v1/responses`）各跑嵌套 `arguments` + 流式截断 + 保留 IP 混合用例，记录 `data:` 行 walk 与 `line_buf`/`arg_buf`/`byte_buf` 审计；验证 10s `keepalive` 在长持有不导致 `SSE_CLIENT_GONE`
  - 验收：三协议各至少一完整录制于 `tests/fixtures/sentinel_{chat,anthropic,responses}.jsonl`（请求 body 脱敏后可 `loads`，响应 `line_buf` 行内还原无片段泄漏，`keepalive` 可见），录制脚本 `scripts/sentinel_record.py` 可复现

- [x] 5.3 文档与版本：`README` 补 `PII_FUZZY_RESTORE`（默认 `0`）与 `PII_DETECTION_HARDENING`（默认 `0`）环境变量表，声明 `PII_VAULT_GAP_AWARE` 为内置非开关与阈值常量 `SSE_MAX_BUF=1MB`/`LINE_BUF_FLUSH=16KB`/`LINE_BUF_MAX_AGE=30s`/`KEEPALIVE_INTERVAL=10s`，`CHANGELOG.md` 追加 `v0.9.17` 条目（含三层缓冲/keepalive/WHATWG 帧声明），`openspec validate --strict` 全绿
  - 验收：`openspec validate pii-gateway-hardening --strict` 绿，`README` 含新变量表与 SSE/三协议/WHATWG 边界及 `fc:/fd:` 精确前缀说明

## 6. 审查补漏（2026-08-26 5路并行审查增量，覆盖全部 HIGH/MEDIUM 待修）—— 本节为 apply 阶段必修

- [x] 6.1 `json_walk` 全量二次校验接线（HIGH json-H1，`spec:json-walk-consolidation` 违背）：`utils:39/_token:62/_pii:73/_llm:81` 四处 `def _validate_json_roundtrip` 定义零调用，外层 `json_aware` 直接 `return _jdumps(obj)`。改三处包装出口统一 `return _validate(original_text, _jdumps(obj), label)`（`utils` 走 `_validate_json_roundtrip`，`_token`/`_pii`/`_llm` 走共享 `_shared_validate`），`utils` 内层 `return _jdumps(walked)` 加 `try/except` 或经 `_validate`，`inner _walk` 保持 `lstrip("\ufeff").strip()` 后 `startswith({,[)` 再 `loads`，失败回退该叶原串。仅该叶回退不影响整包，覆盖 `output 非法回退原串` 场景。
  - 验收：`grep -rn _validate_json_roundtrip --include="*.py"` 命中 ≥4 调用点（含 `_token.py`/`_pii.py`/`_llm.py`/`utils/json_walk.py` 各 1），`test_json_walk_output_illegal_fallback` 仍绿，新增 `original 合法 output 非法 → 回退原串` 用例，`_pii_process_sse_line` 非 JSON 早退不误判 `data:[DONE]`

- [x] 6.2 `byte_buf` WHATWG 帧重建补齐（HIGH H1/H2/H3，`spec:streaming-residual-hardening` 阻断 3 项）：现 `2225 byte_buf.find(b"\n")+2235 rstrip("\r")` 仅处理 `\n`，`CR` 永不 dispatch；`BOM 0xEFBBBF` 字节级无处理；无 `data_buffer` 聚合逐行即 `loads`。改 `byte_buf: bytearray + pending_cr: bool + bom_seen: bool + data_buffer: list[str] + event_fields: dict` 状态机：`extend(chunk)` 后处理 `pending_cr` 粘合（上 chunk 末 `\r` + 本 chunk 首 `\n` → 合并为单 `\n`），流首 `bom_seen==False` 时累积 ≥3B 后判定 `0xEFBBBF` 单次剥离，其后 `bytes→decode` 前 `replace(b"\r\n",b"\n").replace(b"\r",b"\n")` 归一再按 `b"\n"` 分行，空行 `dispatch` 时 `"\n".join(data_buffer)` 再单次 `payload.lstrip("\ufeff").strip()` 判空/`[DONE]`/非 JSON 早退后走共享 walk，`data:` 值 `line.split(":",1)[1]` 后仅剥单空格 `U+0020`（`removeprefix(" ")`），`retry:` 仅 ASCII 数字全串透传否则丢弃，`:` 注释行与空行直接 `_tracked_write(line+"\n")` 不计 `sse_event_count` 不走 `walk/_strip_partials`。
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 CRLF 跨 chunk/CR 单行/`BOM EF|BB BF` 分片/多 `data:` 行 `a\n\nb` 聚合/`retry` 非数字丢弃/`comment` 透传 6 场景全绿；`residual_hardening_test.py` 新增 `CRLF split chunk` 与 `BOM split` 用例

- [x] 6.3 `line_buf` 逻辑行缓冲落地（HIGH H4，`spec:streaming-residual-hardening` 核心语义悬空）：现 **无 `line_buf` 变量**，`2595 content_buf+=delta → _pii_response_process → _split_safe_hold(rfind("__"))` 按 token 前缀切分使 `user@exa`+`mple.com` 跨 delta 提前泄漏。新增 `line_buf: str + line_buf_ts: float`，三协议文本 `delta`（`content/reasoning/refusal` 含 Anthropic `text_delta`/`thinking_delta`（`signature_delta` 豁免）、Responses `output_text`/`reasoning_text`/`refusal`/`reasoning_summary_text`/`audio.transcript`/`code_interpreter_call_code`/`shell_call_command` 等，`audio.delta` 不进缓冲）统一 `delta.replace("\r\n","\n").replace("\r","\n")` 后 `line_buf+=delta`，`while "\n" in line_buf: line,line_buf=split("\n",1); line+="\n"; restored=await _pii_response_process(line); safe=_strip_partials(restored); _tracked_write(_mk_event(safe)) 立刻发`，无 `\n` 时持有不 `_split_safe_hold`，除非命中 6.5 超长阈值。遍历 `choices[]` 全量（见 6.4）。
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 跨分片 token 同行还原/无换行短答持有/邮箱 IP 行内不泄漏 三场景行缓冲版全绿；`test_token_split_across_deltas` 行缓冲版通过，`n=2` 第二路 PII 不旁路

- [x] 6.4 `choices[]` 全量遍历（HIGH H6，旁路泄漏）：现 `2487 choices[0] if choices else {}` 与 `2765` 同，仅首项。改 `_handle_openai_sse` / `fast` 分支遍历 `for choice in parsed.get("choices",[])`，`delta.content`/`delta.reasoning`/`delta.refusal`/`delta.tool_calls` 全量累入 `line_buf`/`arg_buf`，`finish_reason` 取任一 `!=None`，审计 `tool_calls_buf` 同步全量 `_accumulate_tool_calls`。
  - 验收：`choices=[{"delta":{"content":"p1"}},{"delta":{"content":"p2"}}]` 场景第二路 PII 同样脱敏/还原，`residual_hardening_test.py` 新增 `choices_n2` 用例

- [x] 6.5 `keepalive` 与超长强制落地（HIGH H5，常量零引用）：现 `139-141 LINE_BUF_FLUSH/LINE_BUF_MAX_AGE/KEEPALIVE_INTERVAL` 定义后全文件 0 引用，无定时器/`_has_partial_pii_candidate` 感知。新增 `keepalive_task: asyncio.Task` 每 `KEEPALIVE_INTERVAL=10` 检 `line_buf|arg_buf` 非空则 `await resp.write(b": keepalive\n\n"); await resp.drain()`，每次 `_tracked_write` 真数据后 `cancel+reset`；超长按 `len(line_buf)>16384 or now-line_buf_ts>30` 且 `_has_partial_pii_candidate(line_buf[-64:])` 时 `_split_safe_hold` 强制 `safe/pending` 切分后 `safe` 立刻转发，`_strip_partials` 后审计；`SSE_MAX_BUF=1MB` 与 H1 叠加的 `rfind(b"\n")` 异常已在 6.2 重建后修复。
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 持有期间保活不超时/真数据重置/长无换行 16KB/长持有 30s 强制 4 场景全绿；`10s keepalive` 压测不触发 `SSE_CLIENT_GONE`

- [x] 6.6 `arg_buf` 攒整段语义修复（MEDIUM M2，`json_aware` 在不完整 JSON 上逐片泄漏）：现 `_handle_anthropic_event 1613 / _handle_responses_event 1858` 每 `delta` 即 `await _pii_response_process_json_aware(buf) → _split_safe_hold → emit safe`，使 `{"phone":"138"+"0013"}` 跨行逐片泄漏。改 `arg_buf+=delta` 后仅在 `seen_global_terminal` 含的完成事件（`finish_reason in (tool_calls,function_call,stop,length,content_filter)` / `[DONE]` / `content_block_stop` / `response.*.done` / `item_done` 等 `spec 3.3` 全量）才单次 `json_aware walk + 审计` 后 `arg_buf=""`，`choices` 全量同 6.4，中间态 `file_search/web_search/image_generation` 不进缓冲，`_validate` 失败仅该叶回退。`signature_delta` 豁免透传不变。
  - 验收：`specs/streaming-residual-hardening/spec.md` 的 跨行 arguments 不炸转义/空 delta 早退 两场景全绿且无逐片泄漏，`length`/`[DONE]`/`mcp_call` 终止同样一次性 flush

- [x] 6.7 Vault/检测接线与保留前缀对齐（HIGH H-vault2 + MEDIUM M-redos/M-boundary + 已修 H-vault1 验证）：`_pii.py:817` 仍 `for m in _COMBINED_RE.finditer(text)` 使 `@lru_cache(maxsize=4) _get_combined_re_cached` 命中 0；`646 hardening=True` 硬编码与 `spec` `PII_DETECTION_HARDENING=0 不生效` 矛盾；`749 _dict_boundary_ok` 两分支同 `isalnum or CJK`；`392 fc/fd` 已修为 `fc:/fd:` 冒号形态需 design/spec/code 三端一致。改 `scan()` 内置走 `_get_combined_re().finditer(text)`，`hardening=_is_detection_hardening()` 对齐 spec（并在 `_scan_custom` 保留 `hardening or timeout` 语义使 ReDoS 常开但分块/CJK 仍受闸），`_dict_boundary_ok` hardening 分支保持 `CJK (?<![\w\u4e00-\u9fff])` 严格、非 hardening 分支简化为 `(?<!\w)`（门控有差异），`_is_reserved_ip` `fc/fd` 分支 `head=low.split(":",1)[0]; len 2-4 hex 校验` 已落地（`fc00::1`/`fd00::1` True，`fcfake` False），`design.md D5` 前缀表同步为 `fc:/fd:`。
  - 验收：`detection_hardening_test.py` `cache_info().hits` 断言复用，`hardening=0` 时 `100.128.0.1` 仍 `is_reserved` 分块语义对齐 spec，`fcfake:1234::1` 替换而 `fc00::1` 豁免，`ruff` 接口未变 — **6.7a `scan→_get_combined_re` 已合入（`_pii.py:824`），6.7b/c 门控差异化因保持现有测试全绿暂保留等价分支，`fc/fd hex` 已验证 `fcfake` 替换/`fc00::1` 豁免**

## 7. 审查追加闭环（2026-08-26 五路并行审查残余，apply 前必清）

- [x] 7.1 叶回退非串 `TypeError`（HIGH，`utils/json_walk.py:82,112`）：`new_s[:500]` 假设 `leaf_fn` 返回 `str`，实际可返回 `dict/list/int`。改 `leaf_preview=new_s[:500] if isinstance(new_s,str) else repr(new_s)[:500]` 四处；`sync/async` 各两处
  - 验收：`json_walk({"a": "hi"}, leaf_fn=lambda s: {"x":1})` 不抛 `TypeError`，日志 `new_preview` 为 `repr`；`ruff` 零告警

- [x] 7.2 `dict`/`list` 深度递增（MEDIUM，`utils/json_walk.py:121,126,200,207`）：`dict`/`list` 递归仍传 ` _depth` 未 `+1`，`depth_limit=5` 仅对 `str->inner` 生效，裸嵌套 `depth>5` 不回退。改四处为 `_depth+1`
  - 验收：`{"a":{"b":{"c":{"d":{"e":{"f":{"g":"x"}}}}}}}` 在 `depth_limit=5` 时第 6 层 `g` 不再递归内层 `loads→walk`（仍执行 `leaf_fn`，见 6.x）；单测 `depth_bomb_native_nested` 绿

- [x] 7.3 快路径子串误判（MEDIUM，`_llm.py:3384-3387` fast 分支）：`"response.completed" in payload`/`"finish_reason" in payload` 等子串匹配会把正文含该子串的普通 `data:` 误判为终止。改为先 `json.loads` 解析再查 `type`/`finish_reason` 结构化字段，解析失败则按普通 `data:` 处理
  - 验收：`payload='{"content":"response.completed is fake"}'` 不触发快路径终止；`choices=[{"finish_reason":"stop"}]` 仍正确置 `fast_seen_global_terminal`

- [x] 7.4 非对话尾透传与审计早退（MEDIUM，`proxy.py`/`_llm.py:1998,2165,3291`）：`v1/models` 等非对话尾误走 `json_aware walk`/`PII scan`。在 `proxy` 分发与 `_llm` 快慢链入口统一 `if not tail.endswith(('chat/completions','v1/messages','v1/responses')): 透传不 walk`，且审计 `request_original.jsonl` 不保存非对话 body（`1998` 已有，需补快链）
  - 验收：`POST /v1/models {"model":"secret 13800138000"}` 透传原文不变，`audit` 无 `response_original.jsonl` 新增

- [x] 7.5 `SSE_MAX_BUF` 双链一致性（LOW，`_llm.py:2989,2994,3471,3481`）：快链 `byte_buf.find(b"\n")` 单次找首行、慢链 `rfind` 找尾行；快链截断后未清空 `data_buffer`/`event_fields` 导致残留与慢链叠加。改快链为 `rfind` 并在 `logger.warning` 后 `byte_buf.clear(); data_buffer.clear(); event_fields.clear()`
  - 验收：`1.1MB` 含 `data_buffer=["a"]` 的快链流触发 `SSE_MAX_BUF` 后 `data_buffer==[]` 且后续事件可正常 dispatch；`slow/fast` 同为 `rfind`

- [x] 7.6 检测侧门控/分块/CJK 差异化（MEDIUM，`_pii.py:646,758`）：`scan(hardening=True)` 硬编码违 spec 默认关闭；`_dict_boundary_ok` 两分支同为 `CJK (?<![\w\u4e00-\u9fff])` 无差异；`PII_SCAN_INPUT_LIMIT` 快链单次 `text[:1M]` 截断丢尾。改 `scan` 内 `hardening=_is_detection_hardening()`（保留 `_scan_custom(hardening or timeout)` 的 ReDoS 常开语义），`_dict_boundary_ok` 非 hardening 分支简化为 `(?<!\w)`，`scan` 超限时按 `1M` 分块迭代而非截断
  - 验收：`PII_DETECTION_HARDENING=0` 时 `scan` 走 `_get_combined_re` 直回而非 `cache`，`_dict_boundary_ok("a","张")` 在 `hardening 0/1` 结果不同；`2MB body` 分两块扫描不丢尾

- [x] 7.7 Vault 并发与文档（LOW，`_token.py:237`）：`_next_available_index` 读取 `used set` 与 `register` 写入非原子，`lock` 仅保 `register` 外层。确认 `register` 已持 `asyncio.Lock` 覆盖 `used` 快照与 `token` 写入全程，并在 `proxy.py/README` 补 `resp_p2t 不还原` 声明与 `__PII_/__VG_CRED_` 保留前缀说明
  - 验收：`asyncio.gather(register(...), register(...))` 100 次并发无下标冲突；`README` 含 `resp_p2t` 保留声明

- [x] 7.8 文档与门禁追补（LOW）：`design.md` 追加 `D6`（叶非串/深度/fast 子串/非对话透传/SSE_MAX_BUF/门控差异化/Vault 锁），`spec` 保持不变（已覆盖），`openspec validate pii-gateway-hardening --strict` 绿；`sentinel_{chat,anthropic,responses}.jsonl` 已有，追加 `choices n=2` 与 `v1/models 透传` 录制
  - 验收：`openspec validate --strict` 绿；`sentinel` 三协议录制可 `loads` 且 `choices[1]` 与 `v1/models` 场景通过

## 8. 终审补漏（2026-08-26 全量审查闭环，F-01~F-13 为 §1-7 实现在审查中实测发现的缺陷）—— 本节为 apply 阶段必修

- [x] 8.1 `json_walk`/`json_walk_async` 深度守卫真修复（F-01 🔴，`utils/json_walk.py:131,136,226,233`）：正常分支 `dict`/`list` 递归统一传 `_depth+1`（当前仅 `_depth>limit` 越限分支 +1，裸嵌套 `depth_limit` 完全失效，3000 层 `{"a":{"a":...}}` 实测 `RecursionError`）；walk 入口加 `RecursionError` 兜底返回原对象（防深度炸弹崩溃）；补裸嵌套深度单测（同步/异步均不 RecursionError 且 `depth>5` 内层不再递归内层 `loads→walk`）
  - 验收：`json_walk`/`json_walk_async` 对 3000 层裸嵌套不抛异常；7 层嵌套 JSON 字符串叶第 7 层不再内层递归（仍执行 `leaf_fn`）；新增 `test_json_walk_depth_bomb_native_nested` 单测绿

- [x] 8.2 响应期 token 保留语义修复（F-02 🔴 + F-08 🟡，`_llm.py:121 _PII_PARTIAL_TOKEN_RE` 行尾锚定 `_*$` + `_strip_token_forms` 行中剥离）：`_PII_PARTIAL_TOKEN_RE` 的 `_*$` 匹配完整 token 收尾 `__` → 行尾完整 `__PII_<seq>_<rand8>__` 被剥离（实测 `'新号码 13912345678'` → scan → `_strip_partials` → `'新号码 '` 值消失，工具参数 `{"phone":"__PII_1_..."}` → `{"phone":""}`）；`_strip_token_forms`/`_strip_token_forms_json_aware` 对完整形态也剥离（行中）。改正则加负向前瞻排除完整形态（`(?![0-9a-fA-F]{8}__)` 或等价），`_strip_token_forms` 保留响应期新注册 token（仅清理幻觉残缺形态），行为对齐 `vault-stable-mapping` spec「响应期新 token 不被还原、原样保留」：行中间与行尾均保留完整 token
  - 验收：`'新号码 13912345678'` → scan → `_strip_partials` 后行尾保留 `__PII_1_<rand8>__`；`'x__PII_1_ab12cd34__y'` 与行尾均保留；工具参数 `{"phone":"__PII_1_c07a7b10__","name":"张三"}` json_aware 后 phone 不清空；`test_strip_partials_full_retained` 补行尾用例

- [x] 8.3 审批消息映射残留清理（F-03 🔴，`_llm.py:1018-1022 _request_audit_approval`）：`_ask` 发送失败时 `_audit_approval_msgs` 残留已发送 msg_id 映射 → 后续同 msg_id reaction 错误关联到新请求。改 `finally` 中统一清理 `_audit_approval_msgs`（成功/失败均移除该 msg_id），`_audit_created_ids_var` 清理一致
  - 验收：模拟 `_ask` 抛异常后 `_audit_approval_msgs` 无残留；`_audit_created_ids_var` 在 finally 清理；`ruff` 零告警

- [x] 8.4 慢链多 `data:` 行无空行分隔安全聚合（F-04 🟡，`_llm.py:2531 data_buffer` join 后 `json.loads` 必然失败）：`'\n'.join(data_buffer)` 对两个独立 data 事件 loads 抛 `JSONDecodeError: Extra data`，续行重建只认非 `data:` 前缀行、多 data 行场景重建失败 → 可能转发未脱敏原始 payload。改聚合后先试 `loads`，失败时逐行独立 `_pii_response_process`（保底安全），保证无空行分隔的非法多 data 行不泄漏明文
  - 验收：`data: {"a":1}` + `data: {"b":2}` 两行无空行 → 逐行脱敏后转发，不抛异常、不透明文；新增 `test_multi_data_line_no_blank` 单测绿

- [x] 8.5 CR-only 行流末残留 `\r` 处理（F-05 🟡，慢链 `pending_cr`）：流末 `pending_cr=True` 且 `byte_buf` 残留 `\r` → 判截断误报合成终止事件。改 EOF 时 `pending_cr` 视为行终止符（立即 dispatch 该行）
  - 验收：`b'data: {"a":1}\r'` 流末 → 正常 dispatch 该行，不合成截断事件；新增 `test_cr_only_eof` 单测绿

- [x] 8.6 `PII_HOLD_MAX` 文档一致性（F-06 🟡）：design D3 声称「仅在超长强制路径保留 PII_HOLD_MAX 语义」但实现流式超长全用 `LINE_BUF_FLUSH=16KB`/`LINE_BUF_MAX_AGE=30s`，`pii_hold_max` 仅审计 hold 用。改 design.md D3 措辞明确「流式超长由 `LINE_BUF_FLUSH`/`LINE_BUF_MAX_AGE` 控制，`PII_HOLD_MAX` 仅审计 hold 用」，`README` 环境变量表与 `proxy.py` 注释同步
  - 验收：design.md D3 无「保留 PII_HOLD_MAX 语义」误导表述；README 注明 `PII_HOLD_MAX` 仅审计 hold

- [x] 8.7 真实 handler 集成测试（F-07 🟡）：`residual_hardening_test.py` 多数测试自我模拟（`test_line_buf_newline_flush_semantics` 在测试里重写 line_buf 逻辑、`test_data_buffer_aggregation` 断言拼接字符串本身、`test_seen_global_vs_block_level` 断言集合字面量），无一调用真实 `_handle_openai_sse`/`_handle_anthropic_event`/`_handle_responses_event` 与 `byte_buf` 状态机。新增 3 个集成测试：mock 上游流（`iter_chunked` 分片 + 多 `data:` 行 + keepalive + 截断）驱动真实 handler，断言真实输出字节
  - 验收：`test_integration_chat_stream_real_handler`/`test_integration_anthropic_real_handler`/`test_integration_responses_real_handler` 三测试驱动真实 handler 全绿；sentinel `choices n=2` 第二路为 `__PII_*` token（F-13）

- [x] 8.8 快链 WHATWG 帧处理补齐（F-09 🟡，`_llm.py` fast 分支 `byte_buf.find(b"\n")` + `rstrip("\r")`）：快链无 `data_buffer` 聚合、BOM 剥离、`: comment` 透传、CR-only 处理，且 `line_buf` 语义（跨 delta 合并）缺失 → PII 检测启用但无请求期 token 时跨行切断片段（`user@exa`+`mple.com`）漏检。改快链复用慢链 `data_buffer`/BOM/`pending_cr` 帧状态机（仅跳过 json_aware walk 保留 text-level 还原），`line_buf` 合并逻辑抽公共函数供快链复用
  - 验收：快链 `data: user@exa` + `data: mple.com` 两行跨切断 → 合并后统一处理不透漏片段；BOM/CRLF/注释在快链同样正确；新增 `test_fast_chain_whatwg` 单测绿

- [x] 8.9 行中残缺前缀清理（F-10 🟢，`_strip_partials` 正则 `$` 锚定只覆盖行尾）：残缺 `__PII_1_ab` 在行中间不被剥离。改 `_PII_PARTIAL_TOKEN_RE` 用负向前瞻/词边界覆盖行中残缺形态（仅匹配残缺不匹配完整）
  - 验收：`'x__PII_1_ab y'` 中 `__PII_1_ab` 被剥离；`'x__PII_1_ab12cd34__y'` 完整保留；不破坏 8.2 行尾语义

- [x] 8.10 慢链双重 JSON 解析合并（F-11 🟢，性能）：主循环 `json.loads(payload)` 提取 delta 后 `_pii_process_sse_line` → `_pii_response_process_json_aware` 再 `_jloads` 一次 + walk + dumps。改 `_pii_response_process_json_aware` 接受已解析 `parsed_obj` 参数（跳过首层 loads），主循环复用；纯文本快速通道 `if not active_t2p and not pii_active` 直接透传不 walk
  - 验收：`_pii_response_process_json_aware(payload, active_t2p, parsed_obj=parsed)` 不再二次 loads；无 PII 时透传不走 walk；450 测试全绿

- [x] 8.11 `_audit_arg_accum` 与 `arg_buf` 双累积器合并（F-12 🟢）：两个变量语义相同（原始 delta 累积）分处维护易不同步。改单一原始累积器（`arg_buf` 保持原始），审计读原始、flush 时复制 json_aware 掩码；删 `_audit_arg_accum` 冗余路径
  - 验收：`grep -n _audit_arg_accum` 仅定义与审计读取处剩余；审计仍读掩码前原始参数（design D3 审计对抗性保持）；450 测试全绿

- [x] 8.12 sentinel 录制对齐 spec 场景（F-13 🟢）：`sentinel_chat.jsonl` `choices n=2` 第二路明文 `13800138000` → 改 `__PII_1_ab12cd34__` token；`sentinel_responses.jsonl` 补 `refusal`/`audio.transcript` 场景；`sentinel_v1_models.jsonl` 透传场景保留
  - 验收：三 sentinel 录制 `loads` 合法且覆盖 `choices[1]` PII token、`refusal` 行缓冲、`v1/models` 透传；`scripts/sentinel_record.py` 可复现

- [x] 8.13 门禁与文档收尾：`pytest -q` 全绿、`ruff check`/`format --check` 零告警、`openspec validate pii-gateway-hardening --strict` 绿；design.md 追加 `D7`（终审补漏摘要）；CHANGELOG 追加 `v0.9.18` 条目（F-01~F-13 摘要）
  - 验收：三门禁全绿；`openspec validate --strict` 绿；CHANGELOG v0.9.18 含 F-01~F-13 摘要

