## 1. 事件重建保真（D1/D2/D3）

- [x] 1.1 推广结构保留重建：`_mk_sse_event` / `_flush` / fast 流末合成改 deepcopy 原对象按 `index` 逐路替换 delta 字段，`id/created/model/system_fingerprint/usage` 原位保留，全链 SSE 重建走 `_jdumps`
  - Verify: 行为断言：含 `id/created/model/system_fingerprint/usage` 的上游 chunk 经还原后，下游每行 `data:` 均 `json.loads` 成功且 `id/created/model/system_fingerprint/usage` 与上游一致（`sse_stream_loop_test` 新增断言通过）
  - Verify: 行为断言：`n=2` 双路 chunk 经还原后两路 `delta.content` 各自还原且 `finish_reason` 按 `index` 保留，无广播串扰（新增逐路用例通过）
  - Verify: 白名单 grep：转发路径裸 `json.dumps` 仅剩白名单（测试快照/阻断合成占位构造），`_llm.py` 转发路径 `grep -n "json.dumps" _llm.py` 输出为空或全命中白名单注释；非法输入（`parsed` 非 dict）走透传不抛 `AttributeError`

- [x] 1.2 修复拼块逐行还原：`_pii_process_sse_line` 多行块每 `data:` 行独立解析，移除跨行 `parsed_obj` 复用，`event:/id:` 行原样保留
  - Verify: 行为断言：`event: content_block_delta` 行经处理后与输入逐字节一致，且同块 `data:` 行下游 `json.loads` 成功（不被 `_strip_partials` 改写）
  - Verify: 行为断言：含 `event:` + 多 `data:` 同块的流经还原后下游 SDK 可解析且无 `__PII__/__VG_CRED__` 零残留（占位符全还原或进残缺清理，`api_spec_conformance_test` 通过）
  - Verify: `[DONE]`/空行早退仍按单行语义，不误判整块

- [x] 1.3 收敛缓冲事件为单次还原：`tool_calls_pending_events` 放行只还原一次，校验失败走残缺清理而非回退原串
  - Verify: 白名单 grep：缓冲放行路径中 `_pii_process_sse_line(ev)` 调用点唯一（`grep tool_calls_pending_events` 审计仅一处还原调用，其余为累积/放行注释白名单）
  - Verify: 行为断言：占位符文本经缓冲放行后下游 `json.loads` 成功且全文无 `__PII__/__VG_CRED__` 残留
  - Verify: 行为断言：`orjson` 与标准库序列化输出在测试快照中等价（`_jdumps` 口径断言通过）

## 2. 工具调用完整性（D4）

- [x] 2.1 三协议参数统一攒整段：`partial_json` / `function_call_arguments` / `tool_calls.arguments` 仅完成事件单次 `json-aware` + 审计 + flush，`reasoning_content/delta.reasoning/refusal` 同等按路累积
  - Verify: 门控断言：中间分片到达时无网络写出（`bytes_written` 不增，直到完成事件才增；新增门控用例通过）
  - Verify: 行为断言：`p@ss"quote` 含引号参数经还原后下游 `json.loads` 成功且参数语义与上游一致
  - Verify: 行为断言：纯文本非 JSON 参数不抛异常，回退 plain 可转发且下游 `json.loads` 成功

- [x] 2.2 结构化阻断判定替代子串匹配：`tool_calls_blocked` 改 `delta.tool_calls is not None` / `finish_reason` 判定，`finish_reason` 按路独立归属
  - Verify: 行为断言：content 含 `tool_calls` 子串的正常行下游 `json.loads` 成功且正常转发（新增用例通过，白名单 grep：`grep -n "tool_calls" _llm.py` 仅剩结构化判定与测试注释）
  - Verify: 行为断言：`finish_reason=tool_calls` 终止行在 deny 时不透传残缺参数，且后续 content 说明仍可转发；多路竞态（`choices[0]=stop` + `choices[1]=tool_calls`）各路保留不互斥
  - Verify: `index` 非 int / `function` 为 None 的畸形分片被跳过不崩溃
  - Verify: 行为断言：未识别形态事件整行透传不抑制（`sse_stream_loop_test` 新增用例）：无占位符时除 WHATWG 规范化（`data:` 冒号后单空格剥离）外语义一致；含 `__PII__/__VG_CRED__` 时还原后下游 `json.loads` 成功且零残留（不要求逐字节一致）

## 3. 跨片 token 安全（D5）

- [x] 3.1 扩展候选感知并对齐快慢链：`_has_partial_pii_candidate` 覆盖内置全类型 + `__VG_CRED__/__PII__` 前缀，自定义按已加载前缀持有、未命中透传并计数，移除 fast <64 直接透传快路，`reasoning/refusal` 纳入同行缓冲
  - Verify: 行为断言：`user@exa` + `mple.com` 跨 `data:` 切分时前段 `bytes_written` 不增（不提前发出），重组后下游 `json.loads` 成功（新增跨片用例通过）
  - Verify: 行为断言：完整响应期 token 尾不被 `_strip_partials` 误删，下游零 `__PII__` 残留（保留语义用例通过）
  - Verify: 行为断言：`__VG_CRED_000` + `001__` 跨包重组后整体还原，下游 `json.loads` 成功
  - Verify: 行为断言：自定义前缀未命中透传时 `pii_by_type["custom_other"]` 计数加一（`sanitize_kind` 归一口径，与 `/_admin/metrics` 一致）

- [x] 3.2 对齐分帧语义：fast 链补 WHATWG `CRLF/CR` 切行（与 slow 一致），截断 `rfind` 后清理 `fast_data_buffer`
  - Verify: 行为断言：`\r` 分隔流在快慢链切出行数一致且每行下游 `json.loads` 成功
  - Verify: 门控断言：截断后残留不与后续事件叠加（连续两流 `bytes_written` 独立计数无串扰）
  - Verify: `pos==0` 时 `byte_buf` 不单调增长误判截断
  - Verify: 行为断言（`sse_stream_loop_test` 新增用例，三个独立 assert）：`:` 注释透传、`retry:` 仅 ASCII 数字、`data:` 冒号后单空格剥离三语义与 slow 链一致

## 4. 回归验证

- [x] 4.1 三协议回归 + 规范检查：跑全量相关测试与 lint（实测：707 passed / 9 env-missing(openai/anthropic可选依赖) + 1 flaky(0.1s连续超时时序抖动，同树一挂一过)）
  <!-- 备注（仅参考，不作验收依据）：历史某次全量约 699 passed / 9 env-missing(openai/anthropic可选依赖) + 1 flaky(test_redos_consecutive_disable负载抖动) -->
  - Verify: `PYTHONPATH="." pytest -q tests/sse_stream_loop_test.py tests/llm_test.py tests/pii_stream_integration_test.py tests/api_spec_conformance_test.py` 全绿
  - Verify: `ruff check` 与 `ruff format --check` 通过
  - Verify: `openspec validate --change llm-streaming-restore-fix` 通过（无 zero-delta 报错）

## 5. 返工收尾（D6）

- [x] 5.1 死代码 `_release_pending_once` 删除或接线：二选一收敛，`tasks.md` 1.3 描述与代码调用关系一致
  - Verify: 白名单 grep：`grep -rn "_release_pending_once" _llm.py` 输出为空（已删除），或放行路径唯一经由它做单次还原（`grep tool_calls_pending_events` 审计还原调用点唯一且与其接线）
  - Verify: 行为断言：`tasks.md` 1.3 的任务描述与 `_llm.py` 实际调用关系一致（删除则不描述经由它还原，接线则描述其为唯一还原点），占位符缓冲放行后下游 `json.loads` 成功且零残留

- [x] 5.2 补齐三个最小断言：`id/usage` 一致、`n=2` 独立（用例落 `tests/sse_stream_loop_test.py`）、`p@ss"quote` 整段还原（用例落 `tests/pii_llm_test.py` 整段语义等价）
  - Verify: 行为断言：含 `id/created/model/usage` 的上游 chunk 经还原后下游同事件 `id/created/model` 逐字节一致且 `usage` 数值不变（新增用例通过）
  - Verify: 行为断言：`n=2` 双路不同占位符文本经还原后各路为各自明文且 `finish_reason` 按 `index` 保留（新增逐路用例通过）；`p@ss"quote` 参数经攒整段 flush 后下游 `json.loads` 成功且语义一致（新增用例通过）

- [x] 5.3 收敛回退语义为透传原行：`_single_mapped_index` 为 None 时透传原行或带回 `id/model`
  - Verify: 行为断言：`index` 缺失的畸形 chunk 经处理后下游收到的 `id/model/choices` 与上游一致（透传分支），下游 `json.loads` 成功
  - Verify: 行为断言：若走重建分支，重建出的 `data:` 含上游 `id/model` 字段；白名单 grep：回退路径无裸最小事件拼装（`grep -n "_mk_sse_event\|_build_block_event" _llm.py` 回退分支零命中或全带 `id/model` 回填）

- [x] 5.4 明确 refusal 独立字段语义：独立重建不并入 `content`，或维持合并则写明下游契约变更
  - Verify: 行为断言：`delta.refusal` 含占位符的分片经还原后下游 `delta.refusal` 独立存在且为还原文本，同期 `delta.content` 不混入 refusal 文本（新增用例通过）
  - Verify: 若维持合并实现：`specs/rework-followup/spec.md` 内 refusal Requirement 已同步写明合并语义与下游契约变更，且对应用例按合并语义断言（无独立 `delta.refusal` 断言残留）

- [x] 5.5 多 data 行逐条解析 + 慢链截断补 `\r`：与快链 `max(\n,\r)` 对齐
  - Verify: 行为断言：同事件多行 `data:` 各行含占位符时逐行还原按原序输出，下游每行 `json.loads` 成功且零残留（新增用例通过）；白名单 grep：`data_buffer` 聚合路径无 `\n` 拼接后整体 `loads`（`grep -n "join" _llm.py` 聚合分支零命中）
  - Verify: 行为断言：`\r` / `\r\n` 分隔流触发 `SSE_MAX_BUF` 截断后快慢链切出行数一致，残留不与后续事件叠加（连续两流 `bytes_written` 独立计数无串扰）
