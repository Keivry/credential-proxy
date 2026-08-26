## Context

见 `proposal.md - Why`。当前代码在 `v0.9.16` 已闭环嵌套 JSON 与截断合成终端，但仍分散在 `_token._cred_json_walk` / `_pii._pii_json_walk` / `_llm._pii_response_process_json_aware` 三处 walk，实现口径（`orjson`/`BOM`/`depth=5`/`ensure_ascii=False`/`separators`）与残缺清理（`_PARTIAL_TOKEN_RE` 单套）易漂移。横向对比：`llm-guard` 的 `Vault + TextReplaceBuilder` 倒序语义与空洞跳过、`NeMo-Guardrails` 的 `@lru_cache AnalyzerEngine` 与 `input/output/retrieval` 分源配置，均为可移植硬化。

## Goals / Non-Goals

**Goals:**
- 单一共享 walk 消除三处分叉，统一 `orjson`/`BOM`/`depth`/`separators`/`叶子级回退` 五要素
- Vault 稳态：同值同 token、空洞跳过下标、可选模糊还原、残缺前缀统一清理
- 流式三层缓冲 `byte_buf`/`line_buf`/`arg_buf` 统一倒序+候选感知与保活，不泄漏 `__PII_`/`__VG_CRED_` 片段（`line_buf` 按 `\n` 行缓冲，`arg_buf` 攒整段 `json_aware`，`byte_buf` 按 WHATWG 帧重建）
- 检测侧默认关闭硬化：保留地址精确前缀、ReDoS 线程守卫、字典独立扫描、Analyzer 缓存

**Non-Goals:**
- 不新增 `presidio`/`spacy` 强依赖，不引入 `GLiNER` 服务调用（NeMo 那路保留为可选外置）
- 不改变现有三对话尾与 `v1/models` 透传、不改变 `ensure_ascii=False`/`separators` 字节口径（`json-leaf-fallback-orjson` 已声明）
- 不对非对话尾启用脱敏，不做 PII 全局跨请求持久化（由 `GlobalPiiTokens` 另案）

## Decisions

**D1 共享 walk：`utils/json_walk.py::json_walk(obj, leaf_fn, *, depth_limit=5)` + `json_walk_async` 而非各文件各写一遍 `def _walk`**

- 选用：抽 `._jloads`/`._jdumps`/`._validate`+`._strip_bom`+`depth` 守卫+`str` 叶内 `loads→walk→dumps` 嵌套分支为通用函数，`_token._cred_json_walk` 用 `json_walk`（sync `leaf_fn`），`_pii._pii_json_walk` 与 `_llm._pii_response_process_json_aware` 用 `json_walk_async`（async `leaf_fn`），其余 `dict`/`list` 分支共用。备选：保留三套 `_walk` → 口径分歧已在 `v0.9.9-0.9.16` 产生 5 次修复，成本更高。
- `lstrip("\ufeff")` 先于 `strip()` 与 `startswith(("{","["))`，与 `fix-json-nested-restore` D1 一致；`depth>5` 时叶字符串仍做 `leaf_fn` 但不递归（防炸弹 JSON）。
- 叶子级最小回退：仅叶 `leaf_fn` 抛异常或 `_validate` 失败回退该叶原串，不回退整包；`_validate` 失败回退仅影响该叶，避免整包 PII 因单叶转义失败全部回退明文（见 Risks）。

**D2 Vault 稳态：`__PII_<seq>_<rand8>__` 同值复用 + `next_available_index` 跳空洞（抄 `llm-guard anonymize.py:271-330`）**

- 选用：`RequestScopedTokens`/`GlobalPiiTokens` 在 `register(value)` 时先查 `value→placeholder` 既有映射（请求级优先→全局 Vault），命中复用；未命中则收集 `vault_entities` 已用下标 `set`（含本批次 `batch_tracker`），`next_index=1 while in set: next+=1`。备选：`len(vault)+1` → 删除中间下标后复用歧义，`llm-guard` 已踩坑。
- `rand8`= `secrets.token_hex(4)`，`CSPRNG` 非 `random`；`_restore` 仅还原请求期实注册 token（精确 `placeholder_exists`），不做全局兜底（已在 `llm-pii-cache-concurrency` 明确）。
- 可选模糊还原：`PII_FUZZY_RESTORE=0/1` 默认关闭；开启时对响应中的占位符做大小写不敏感匹配（`re.IGNORECASE`），不做 `fuzzysearch` 的编辑距离 3（`llm-guard FUZZY`）以控依赖与误还原。

**D3 残缺统一清理：`_strip_partials(text)` 合并凭据+PII 两套 `_PARTIAL_TOKEN_RE`（`fix-json-nested-restore` 已补 `_PII_PARTIAL_TOKEN_RE` 但部分 flush 未接）**

- 选用：单一函数内合并 `__VG_CRED_` 与 `__PII_` 的 `_[0-9]*(_[0-9a-f]*)?$` 前缀 + 完整 `__PII_<seq>_<rand8>__` 形态判定，`safe` 侧完整保留、残缺剥离；`line_buf` 行首/行末与 `safe` 侧阈值 `<64` 持有均走此函数。备选：各处散落 `_PARTIAL_TOKEN_RE.sub` → 已漏接 `v0.9.16 F-02`。
- 倒序语义：`safe` 侧 `str.replace` 改 `TextReplaceBuilder` 倒序（`presidio_anonymizer` 模式的逆序 `sorted(reverse=True)` 等价，避免长文本重叠错位），`line_buf` 行内替换同样倒序。**`byte_buf`（SSE 字节级帧重建，WHATWG `CRLF/LF/CR` + `:` 注释透传 + `BOM` 单次剥离 + 同事件多 `data:` 行 `data_buffer` 以 `\n` 聚合）/`line_buf`（正文本逻辑行，按 `\n` 切分，`\r\n`/`\r` 预归一，遍历 `choices[]` 全量）/`arg_buf`（工具参数 stringified JSON 攒整段，覆盖 `function_call` 废弃形态与 `mcp`/`custom_tool`/`code_interpreter` 等）为三套独立缓冲，前者负责帧完整性，中者负责行边界，后者负责参数完整性，不互相覆盖（见 Risks）。**

**D4 流式三层缓冲：正文行缓冲 + 工具攒整段 + 候选感知兜底与保活**

- 选用：正文本 `content/reasoning/refusal`（含 Anthropic `text`/`thinking` 的 `text_delta`/`thinking_delta`（`signature_delta` 仅签名不进 `line_buf` 透传）、Responses `output_text`/`reasoning_text`/`refusal`/`reasoning_summary_text`/`audio.transcript` 的 `delta` 以及 `code_interpreter_call_code.delta`/`shell_call_command.delta` 等文本载荷；`audio.delta` 音频字节不进 `line_buf`/`arg_buf`）走 `line_buf` 逻辑行缓冲（应急食品讨论收敛）：`delta_text.replace('\r\n','\n').replace('\r','\n')` 归一后 `line_buf += delta_text; while '\n' in line_buf: line,line_buf = split('\n',1); line+='\n'; restore(line)→_strip_partials→_mk_*_event` 立刻发；无 `\n` 时整行持有，不做 `_split_safe_hold` 前缀判断。`choices` 维度遍历全量；字节层 `byte_buf` 按 WHATWG 先聚合同一事件内多 `data:` 行（`data_buffer` 以 `\n` 拼接）再单次 `loads`。备选：按 token 前缀 `rfind('__')` 切分 → 代码复杂且 `8.8.` 易切断（原 D4 已证）；行缓冲以 TTFT（平均 +80-150 字符延迟，延迟不敏感可接受）换简洁。
- 工具参数（`chat: tool_calls[].function.arguments` / `function_call.arguments`（deprecated） / Anthropic `partial_json` / Responses `function_call_arguments.delta`/`mcp_call_arguments.delta`/`custom_tool_call_input.delta`/`code_interpreter_call_code.delta`/`shell_call_command.delta` 等 stringified JSON/参数）为字符串载荷，无 `\n`，保持 `arg_buf += delta` 攒到 `finish_reason in (tool_calls,function_call,stop,length,content_filter)` / Anthropic `content_block_stop` / Responses `response.output_item.done`/`response.content_part.done`/`response.output_text.done`/`response.function_call_arguments.done`/`response.mcp_call_arguments.done`/`response.custom_tool_call_input.done`/`response.code_interpreter_call_code.done`/`item_done` 才 `json_aware walk` + 审计 hold，再一次性 flush，不按 `\n` 切分；`choices` 维度遍历全量而非仅 `choices[0]`。
- 兜底与保活：单行累积超 16KB 或持有超 30s 即使无 `\n` 也按 `_split_safe_hold(_has_partial_pii_candidate)` 前缀兜底强制 flush（候选正则：`\b\d{1,3}\.(?:\d{1,3}\.){0,2}$` / `[A-Za-z0-9._%+-]+@$` / `fe80::[0-9a-f:]*$`），防无换行长流憋死；持有期间每 10s 发 SSE 注释保活 `: keepalive\n\n`（WHATWG `comment` 行，客户端按空操作忽略，非 `data:` 事件），避免 hermes `inactivity 120s` 断连；每次真数据 `_tracked_write` 后重置保活计时。
- 字节窗口 64B 已由行缓冲吸收，流式超长强制统一由 `LINE_BUF_FLUSH=16KB`/`LINE_BUF_MAX_AGE=30s` 控制；`PII_HOLD_MAX` 仅用于审计 hold 缓冲（`AUDIT_HOLD_MAX_BYTES`），不再参与流式正文行缓冲语义。阈值 `16KB(=16384)`/`30s`/`10s`/`1MB` 为硬编码常量（`LINE_BUF_FLUSH`/`LINE_BUF_MAX_AGE`/`KEEPALIVE_INTERVAL`/`SSE_MAX_BUF`）非环境变量，与 spec 量化一致。

**D5 检测侧加固：`lru_cache` Analyzer + 保留地址精确前缀（含尾点/冒号）+ ReDoS 线程池守卫 + 字典独立扫描**

- 缓存：`@lru_cache(maxsize=4)` 缓 `re.compile` 的联合正则与 `presidio AnalyzerEngine` 实例（NeMo `_get_analyzer`），避免每请求编译，`dict_ver` 变化 `cache_clear`。备选：每请求 `re.compile` → 1MB body 90ms 锚点超标。
- 保留地址：前缀表 `{"10.", "127.", "169.254.", "192.168.", "172.16."..("172.31."), "224.".."239.", "240.".."255.", "100.64.".."100.127.", "fc:", "fd:", "fe8:".."feb:", "fc00::/7 hex head 校验", "::1", "2001:db8:"}` 均含尾点/冒号（`fc`/`fd` 仅冒号形态 `fc00::1`/`fd00::1` 豁免，`fcfake` 不豁免，`_is_reserved_ip` 中 `head=low.split(":",1)[0]; 2<=len<=4 hex` 校验；`spec: pii-detection-hardening` 已同步冒号形态），`startswith` 前 `text.lower()`（NeMo 大小写坑）。备选：`ipaddress.ip_network` 构造 → 每候选一次对象开销，1MB 9021 候选过滤 <5ms 目标不达。`Analyzer` 缓存 `@lru_cache(maxsize=4)` 必须经 `_get_combined_re()` 接线（`scan()` 禁直用 `_COMBINED_RE`），`_dict_boundary_ok` hardening 分支 `CJK (?<![\w\u4e00-\u9fff])`、非 hardening 分支简化为 `(?<!\w)` 使门控有差异，`ReDoS` 守卫 `hardening=_is_detection_hardening()` 对齐 spec（超时仍常开但分块/CJK 仍受闸）。
- ReDoS：`ThreadPoolExecutor(max_workers=2, thread_name_prefix='pii-re')` 独立池（与审计文件 I/O 的 `run_in_executor(None)` 不同池）+ `asyncio.timeout(0.1)` 单规则预算（非 `wait_for`，因 `executor Future` 不可取消、`wait_for` 在 3.12 不可靠见 `_pii.py:530` 注释），超时跳过+审计+连续 3 次停用（`llm-privacy-gateway` D1 已定）。输入上限 `PII_SCAN_INPUT_LIMIT=1M` 分块。
- 字典：独立扫描不并入联合正则（防 `a|b|c` 分支爆炸，`llm-privacy-gateway` D1）、按长度降序+`re.escape`+`dict_ver` 缓存，CJK 边界 `(?<![\w\u4e00-\u9fff])name(?![\w\u4e00-\u9fff])`。

**D6 审查追加闭环（2026-08-26 五路并行审查残余，§7 对应）**

- 选用 7.1：`leaf_fn` 返回非 `str` 时 `new_s[:500]` 改 `isinstance(new_s,str) and new_s[:500] or repr(new_s)[:500]`，四处统一，防 `TypeError: 'dict' object is not subscriptable` 掩盖 `leaf broke` 审计。备选：强制 `leaf_fn` 返回 `str` → 约束调用方，不如 walk 侧容错。
- 选用 7.2：`dict`/`list` 递归传 `_depth+1`，使 `depth_limit=5` 对裸嵌套同样生效（`str->inner` 已 `+1`，裸嵌套需同口径）。备选：保留 `_depth` → 炸弹 JSON `{"a":{"a":...}}` 可绕过 `leaf_fn` 仍执行。
- 选用 7.3：快路径终止判定由子串 `in payload` 改为 `json.loads` 结构化 `parsed.get("type")`/`parsed.get("choices",[])[i].get("finish_reason")`，解析失败按普通 `data:` 透传。备选：正则子串 → 正文含 `response.completed` 误触发。
- 选用 7.4：非对话尾（`v1/models` 等）统一 `tail.endswith(...)` 守门透传，不走 `json_aware walk` 与 `request_original.jsonl` 保存（`_llm 1998` 已有，需补快链 `3291` 与 `proxy` 分发）。备选：全量 walk → 误脱敏+审计泄漏。
- 选用 7.5：`SSE_MAX_BUF` 快链 `find` 改 `rfind` 与慢链一致，快链截断后 `data_buffer.clear(); event_fields.clear()` 防残留串事件。备选：保留 `find` → 1MB 截断丢尾行可解析前缀。
- 选用 7.6：检测侧 `scan(hardening=_is_detection_hardening())` 对齐 spec，`_dict_boundary_ok` 非 hardening 分支简化 `(?<!\w)` 形成差异化，超长输入按 `1M` 分块迭代而非 `text[:1M]` 截断（`_scan_custom` 仍 `hardening or timeout` 使 ReDoS 常开）。备选：保留截断 → 尾部 PII 丢检。
- 选用 7.7：Vault `register` 已持 `asyncio.Lock` 覆盖 `used set` 快照与 `token` 写入全程，确认原子性；文档补 `resp_p2t 不还原` 与 `__PII_/__VG_CRED_` 保留前缀（`vault-stable-mapping` 已声明 token 形态，本文档化）。

**D7 终审补漏（2026-08-26 全量审查闭环，§8 对应）**

- 选用 8.1（F-01 🔴）：`json_walk`/`json_walk_async` 正常分支 `dict`/`list` 递归统一传 `_depth+1`，使 `depth_limit=5` 对裸嵌套生效（§7.2 修复不彻底：仅越限分支 +1，3000 层裸嵌套实测 `RecursionError`）；walk 入口加 `RecursionError` 兜底返回原对象（防深度炸弹崩溃）。备选：依赖 `depth_limit` 单层防护 → 裸嵌套可绕过直接崩溃。
- 选用 8.2（F-02 🔴 + F-08 🟡）：`_PII_PARTIAL_TOKEN_RE` 行尾锚定 `_*$` 误剥完整 token 收尾 `__`（行尾完整 token 值消失，工具参数 `phone` 被清空），`_strip_token_forms` 对行中完整形态也剥离。改正则加负向前瞻排除完整形态 `(?![0-9a-fA-F]{8}__)`，`_strip_token_forms` 保留响应期新注册 token 仅清理幻觉残缺，行为对齐 `vault-stable-mapping`「响应期新 token 不被还原、原样保留」。备选：响应期 token 一律剥离 → 保守但破坏语义（spec 违背）。
- 选用 8.3（F-03 🔴）：`_request_audit_approval` 的 `_audit_approval_msgs` 在 `_ask` 失败时不清理 → 同 msg_id reaction 错误关联新请求。`finally` 统一清理。备选：依赖 `_ask` 成功返回 → 发送失败残留映射。
- 选用 8.4（F-04 🟡）：`data_buffer` join 后 `json.loads` 对多独立 data 行必然 `JSONDecodeError: Extra data`，续行重建不覆盖多 data 行场景 → 可能转发未脱敏原始行。聚合后先试 `loads`，失败逐行独立 `_pii_response_process` 保底安全。备选：依赖续行重建 → 多 data 行场景泄漏明文。
- 选用 8.5（F-05 🟡）：流末 `pending_cr=True` 且 `byte_buf` 残留 `\r` → 判截断误报合成。EOF 时 `pending_cr` 视为行终止符立即 dispatch。备选：残留 `\r` 判截断 → 正常流误报截断合成。
- 选用 8.6（F-06 🟡）：design D3「仅在超长强制路径保留 PII_HOLD_MAX 语义」措辞误导——实现流式超长全用 `LINE_BUF_FLUSH=16KB`/`LINE_BUF_MAX_AGE=30s`，`pii_hold_max` 仅审计 hold 用。文档明确「流式超长由 `LINE_BUF_FLUSH`/`LINE_BUF_MAX_AGE` 控制，`PII_HOLD_MAX` 仅审计 hold 用」，README/proxy.py 注释同步。
- 选用 8.7（F-07 🟡）：`residual_hardening_test.py` 多数测试自我模拟（重写 line_buf 逻辑/断言字面量），无一驱动真实 handler。新增 3 个集成测试（mock 上游流驱动真实 `_handle_openai_sse`/`_handle_anthropic_event`/`_handle_responses_event`）断言真实输出字节。备选：保留自我模拟 → 覆盖假象。
- 选用 8.8（F-09 🟡）：快链 `byte_buf.find(b"\n")` + `rstrip("\r")` 无 `data_buffer` 聚合/BOM/注释/CR-only 处理，且无 `line_buf` 跨 delta 合并 → PII 检测启用无请求 token 时跨行片段漏检。快链复用慢链 WHATWG 帧状态机（仅跳过 json_aware walk），`line_buf` 合并逻辑抽公共函数。备选：保留快链简化 → 帧完整性缺口。
- 选用 8.9（F-10 🟢）：`_strip_partials` 正则 `$` 锚定只覆盖行尾，行中残缺 `__PII_1_ab` 不剥离。负向前瞻/词边界覆盖行中残缺形态。备选：保留行尾锚定 → 行中残缺泄漏。
- 选用 8.10（F-11 🟢）：慢链主循环 `json.loads(payload)` 后 `_pii_process_sse_line` 再 `_jloads` 一次（双重解析）。`_pii_response_process_json_aware` 加 `parsed_obj` 参数跳过首层 loads，纯文本快速通道直接透传。备选：保留双重解析 → 高 RPS 每行 2-3 次 loads。
- 选用 8.11（F-12 🟢）：`_audit_arg_accum` 与 `arg_buf` 双累积器语义相同易不同步。合并为单一原始累积器（`arg_buf` 保持原始），审计读原始、flush 时复制 json_aware 掩码。备选：保留双累积器 → 维护负担。
- 选用 8.13（F-13 🟢）：sentinel 录制对齐 spec 场景（`choices[1]` 改 token、补 `refusal`/`audio.transcript`）。备选：保留明文录制 → 场景不对齐。

**D8 传输层终审闭环（2026-08-26 主代理实测 + 3 子任务并行审查，§9 对应）**

- 选用 9.1（F-01 🔴🔴🔴）：慢链 `del byte_buf[:pos]` 在 §7 重构（c4750dc）时被误缩进进 `while True` 循环体内（缩进 40/44，AST + git blame 双重证实），体内 5 分支全 `continue/break` → 不可达死代码，`byte_buf` 单调增长致正常流误判截断 + 合成重复 `[DONE]`。修复：回移至 indent36 紧贴 while 后（与快链 3889 对称），补 `test_byte_buf_trim`。备选：依赖既有 `rfind` 截断 → 正常流恒被污染。
- 选用 9.2（F-02 🔴）：截断判定 `if byte_buf or data_buffer...`（3492）过敏感 + 合成事件自带 `data: [DONE]`（1172）与透传重复。修复：仅 `!seen_global_terminal` 且确有未消费 data 内容时合成；合成前检查已发 `[DONE]` 去重；合成事件不再自带 `[DONE]`。备选：保留现状 → 正常流误报截断。
- 选用 9.3（F-03 🔴）：慢链 `choices[0]` 只取首路（2677/3094），`n=2` 第二路内容/PII/finish_reason 全丢。修复：`for choice in parsed.get('choices',[])` 全量 + `finish_reason = next(...)`。备选：仅首路 → 旁路泄漏。
- 选用 9.4（F-04 🔴）：慢链 CR-only 行 append 到 `data_buffer` 后从不 dispatch（3532 直接 clear 丢弃），快链正确、双链不对称。修复：流末 CR-only 行立即正常分发。备选：依赖截断合成兜底 → 内容丢失。
- 选用 9.5（F-05 🟡）：快链 `_fast_emit_data@3790` 缺 line_buf 行缓冲，跨 `data:` 分片切断 `user@exa`+`mple.com` 前段提前 safe 发出致邮箱片段泄漏；tasks 8.8 声称「line_buf 抽公共函数供快链复用」未兑现。修复：抽公共行缓冲函数（`_emit_line_buf`）供快慢链复用，或退化 tasks 措辞并评估泄漏接受度。备选：保留快链简化 → 片段泄漏。
- 选用 9.6（F-06 🟡）：共享 walk 路径（1302）与 fallback（1371）未包装 `_shared_validate`，叶级非法 JSON 不回退原串；tasks 6.1 声称三处统一但 `_llm` 响应侧漏接（对比 `_token`/`_pii` 已正确）。修复：共享路径 `out=_jdumps(walked); return _shared_validate(text,out)` 包装。备选：保留裸 `_jdumps` → 违反 spec「output 非法回退原串」。
- 选用 9.7（F-07 🟡）：慢链每行 `restore→scan` 全链 + `active_t2p` 每行重编 `re`（`_restore_cache_pat` 仅缓存全局）。修复：`_restore_cache` 分 `global_ver`/`active_id` 两级缓存 + scan 批量化。备选：保留每行重编 → 高 RPS 性能债。
- 选用 9.8（F-08 🟡）：`_pii_response_scan` 用 `norm_value == re_sub_seps(plain)` 值级等价（896-901）不看位置，模型独立输出同值明文被误跳过掩码，与 docstring 矛盾。修复：改位置区间重叠比较。备选：保留值级 → 语义违背。
- 选用 9.9（F-09 🟡）：`_strip_token_forms_json_aware`（497-567）为第四处独立 walk，与共享语义漂移。修复：改薄包装 `json_walk`。备选：保留第四处 → 维护漂移。
- 选用 9.10（F-11 🟡）：Anthropic/Responses 超长条件缺 `now-line_buf_ts>30`（LINE_BUF_MAX_AGE），三协议不一致。修复：两 handler 补 30s age 分支。备选：保留 chat 独有 → 语义分裂。
- 选用 9.11（F-12 🟡）：`parsed_obj` 仅非 dict 分支传递（2548），主 dict 路径/续行/快链仍二次 loads。修复：主路径传 `parsed_obj=parsed`。备选：保留双重解析 → 30% CPU 浪费。
- 选用 9.12（F-14 🟡）：`_ka` 闭包在审批挂起（`_request_audit_approval` await 90s）期间不可见 → 不保活临界 hermes inactivity 120s。修复：`_ka` 检查 `_audit_approval_pending` 非空即保活。备选：保留现状 → 审计挂起可能断连。
- 选用 9.13（F-13/F-15/F-16/F-17/F-18）：文档/测试对齐——tasks 勾选不实标注、sentinel 入测试、集成断言补强（`raw.count('data: [DONE]')==1`/`'truncated' not in raw`）、自模拟用例改造为真实 handler 驱动。备选：保留空心断言 → 回归无法捕获。
- 选用 9.14：门禁与文档收尾——三门禁 + design D8 + CHANGELOG v0.9.19。

**D9 复审闭环（2026-08-27 四子任务并行复审 §9 后逐条甄别，§10 对应）**

- 选用 10.1（R-01 🔴 本次引入）：续行重建路径（JSONDecodeError → accumulated 续行）聚合循环未赋值 `delta`，`elif 'reasoning_content' not in delta:` 直接引用 → 首次走续行 NameError / 复用陈旧 delta 误判分支。修复：续行路径补 `_agg_delta`（首个非空 delta）+ `delta = _agg_delta or {}`；主路径 `_agg_delta` 初始化改 None 哨兵（R-04 耦合债务同修）。备选：保留 → 续行场景崩溃/语义错乱。
- 选用 10.2（F-04 🔴 本次引入）：`_pii_response_scan_cache` 单槽 key 缺 `pii_scope` 维度，并发请求同 text 命中他 scope 缓存 → register 副作用被跳过（跨会话 PII token 串扰/漏掩）。修复：key 加 `id(pii_scope) + _seq` 指纹。备选：删除缓存 → 每行重 scan。
- 选用 10.3（F-05/F-SEC-01 🔴 本次引入）：位置区间过滤按 value 级去重，任一出现重叠即整值跳过 → 同块两处同值（一还原一独立）独立处漏掩。修复：按出现位置逐段判定 + 位置感知替换（仅替换不在 span 内的出现）。备选：保留 value 级 → D2 语义违背（PII 泄漏）。
- 选用 10.4（F-SEC-02 🔴 本次引入）：`_repl_pii` 用原串 `m.start()` 记录 span，替换后长度变化（token 18 vs plain 11）→ 多 token 时后续 span 在最终文本错位（还原区被二次掩码/边界误放行）。修复：`_offset_delta` 累计偏移差把原串坐标映射到最终文本坐标。备选：保留 → 多 token 响应错位。
- 选用 10.5（F-01/R-03 🟡 本次引入）：CR-only `data: [DONE]` 慢链过滤不入 data_buffer（finish_reason 未先行时流末误判截断合成）、快链静默丢弃 + fast_data_buffer 未清理。修复：双链 `[DONE]` 单独透传 + 原子置位 `_done_sent`/`seen_global_terminal`。备选：保留 → 低频双发/截断误判。
- 选用 10.6（F-03/R-05 🟡 本次引入）：聚合后任一 choice 含 tool_calls 且 audit 启用 → 整行 continue，同行其他 choice 的 content/reasoning 被丢弃（安全保守但时序变化）。修复：仅纯 tool_calls 行（无 content/reasoning）continue，混合行 content 正常处理。备选：保留整行抑制 → 混合行 content 延迟/丢失。
- 选用 10.7（F-07 🟡 本次引入）：`_reset_keepalive` 创建任务条件漏 `_audit_approval_pending`，tool_calls 审批窗口（缓冲区空）无 keepalive → hermes 120s 断流。修复：创建条件补 `_audit_approval_pending` + `_request_audit_approval` 独立保活协程（`_audit_keepalive_resp`）。备选：保留 → 审批期断连。
- 选用 10.8（F-08 🟡 本次引入）：CR-only join 后一次 `json.loads` 对多 data 行必失败 → 终止漏置位误判截断；chat 流 `_proto_text_ts` 不更新，超 30s 后每 chunk 多余 flush。修复：逐条目解析 + 30s 检查限定非 chat 协议。备选：保留 → 截断误判/碎片化。
- 选用 10.9（R-02 🟡 本次引入，设计权衡）：快链 line_buf 无换行 content 持有至 30s/流末 → TTFB 显著增加（逐字渲染卡顿）。修复：短 content（<64B 且无 PII 候选）直接透传不入缓冲。备选：保留持有 → 首字延迟 30s。
- 选用 10.10（P-02~P-05 🟢）：单槽缓存 scope 指纹（随 10.2）、str+= 与位置过滤经评估为可接受（n==1 无拷贝、spans ≤3 排序、finditer 是安全修复必要代价）。备选：list join/二分 → 复杂度不抵收益。
- 选用 10.11（F-SEC-03/F-TEST-01/F-TEST-02/F-QUAL-01 🟡）：截断 warning preview 双重脱敏（`_strip_partials` + `redact_summary`）；sentinel 第二路改独立明文「独立第二路」解耦 tool_calls 断言（mutation 验证锁住）；截断正向断言补 caplog + `finish_reason` + `[DONE]==1`；`_mk_sse_event` 统一 `_jdumps` 口径。备选：保留 → 日志 PII 泄漏/断言空心。
- 选用 10.12：门禁收尾 + design D9 + CHANGELOG v0.9.20。

## Risks / Trade-offs

- [Risk] 共享 walk 抽取后 `_token`/`_pii`/`_llm` 三处行为短期不一致 → Mitigation：`json_walk` 单测覆盖 `BOM`/嵌套/深度/非 JSON 早退四象限，`_token`/`_pii` 各保留薄包装做转发；`byte_buf` 与 `hold` 时序在 D3/D4 明确分离
- [Risk] 模糊还原误还原（大小写不同值被还原） → Mitigation：默认关闭，仅 `re.IGNORECASE` 不做编辑距离，审计记录每次模糊命中
- [Risk] 候选感知/行缓冲导致尾部长期不 flush（恶意无换行长流，三协议文本 `delta` 均适用 `16KB/30s` 同阈值，`_handle_responses_event`/`_handle_anthropic_event` 同路径） → Mitigation：逻辑行超 16KB 或 30s 强制按前缀兜底 flush，SSE 注释保活 `: keepalive\n\n` 10s 一次（`_tracked_write` 真数据重置，强制 flush 同样重置，`30s` 内至少 `2` 次 `keepalive`），`hold_max` 超限同样强制并审计
- [Risk] `lru_cache` Analyzer 占用内存 → Mitigation：`maxsize=4`，`dict_ver` 变化时 `cache_clear`
- [Risk] 保留地址前缀扩大导致公网 `100.128.0.1` 被误豁免 → Mitigation：前缀表单测含 `100.127.255.255` 留、`100.128.0.1` 替换对照，`fc`/`fd` 前缀后补 `:` 或 `ip_network` 回退避免 `fcfake` 误判
- [Risk] `orjson` 与 `json` 的 `ensure_ascii` 差异 → Mitigation：与 `json-leaf-fallback-orjson` 一致 `ensure_ascii=False` 单口径，不新增 `indent`
- [Risk] 叶子级 `_validate` 失败回退原 PII 明文 → Mitigation：仅该叶回退，概率极低（仅转义破坏时），且原 PII 本就在上游请求侧已脱敏路径外，回退前后均为上游可见明文，不扩大泄漏面；后续可加 `strict` 模式转 502
- [Risk] 全局 `GlobalPiiTokens` 跨请求可见导致 token 枚举 → Mitigation：`_restore` 仅读请求级快照 `active_t2p=dict(GlobalPiiTokens)`（`_llm.py:581` 快照语义），不直读全局；`rand8` `secrets.token_hex(4)` 使枚举概率可忽略，越界/格式不符审计

- [Risk] SSE 帧/三协议终止误判导致合成错误 → Mitigation：`byte_buf` 按 WHATWG `CRLF/LF/CR` 分行 + `:` 注释透传，`chat:[DONE]`/`finish_reason`、`anthropic:message_stop`/`content_block_stop`、Responses `response.completed/failed/incomplete` + `item_done` 全量判定，已在 v0.9.16 验证 `byte_buf 54/264` 孤行合成

## Migration Plan

- 部署：随 `v0.9.17` 发布，无配置迁移；回滚 `git revert 4 文件 + 删除 credential-proxy/utils/json_walk.py + 删除 tests/vault_stable_test.py、tests/residual_hardening_test.py、tests/detection_hardening_test.py`
- 验证：`pytest -q` 全绿、`ruff check/format` 零告警；真实流量验证 `chat/completions` 嵌套 `arguments` + `v1/messages` `content[].tool_use` + Responses `output[]` 三协议（含 `byte_buf` 半行与 `hold` 分离验证）
- 开关：`PII_FUZZY_RESTORE` 默认 `0`，开启需显式 `1`，关闭时行为与 `v0.9.16` 字节级一致；`next_available_index` 空洞跳过为内置行为非开关

## Open Questions

- 无。`presidio`/`GLiNER` 是否作为可选 `PII_ENGINE=regex|presidio` 形态引入，留待后续 `PII_REDACTION_TYPES` 细化案，不影响本 change 任务分解。
