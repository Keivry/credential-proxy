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
- 字节窗口 64B 已由行缓冲吸收，仅在超长强制路径保留 `PII_HOLD_MAX` 语义；阈值 `16KB(=16384)`/`30s`/`10s`/`1MB` 为硬编码常量（`LINE_BUF_FLUSH`/`LINE_BUF_MAX_AGE`/`KEEPALIVE_INTERVAL`/`SSE_MAX_BUF`）非环境变量，与 spec 量化一致。

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
