## Why

LLM 脱敏/还原审计（`_llm.py` 7892行 / `_pii.py` 1942行）发现 18 项残留风险：流式帧前缀误送 plain、非 dict 透传无校验、请求侧值等价跳过与纯中文自定义漏检、响应侧纯 PII 无校验与审计先于还原、三通道注入/提取/阻断不对等、4 套 walk 重复与死校验、文档测试三方互斥。需一次性收敛，防止破结构、漏脱敏、工具调用误拦截持续扩大。

## What Changes

- 流式保真：`_pii_process_sse_line` plain 回退一律只送 payload（单行/多行/异常全路径）；`_mk_sse_event` 非 dict 透传保证不抛 AttributeError 且原文保留；`_sanitize_json` 补映射表（`CRLF->LF`，`TAB` 保留）；`re_sub_seps` 内联改名移 P2；`event:/id:/retry:/:` 原样透传。
- 请求侧脱敏：新增 `scan_spans()->[(kind,value,start,end)]` 位置契约，`detect_and_redact` 按 span 位置替换（长跨度优先+重叠仲裁）；保护区间统一到 `_pii.py:1472` 语义并抽 `utils` 共享常量；custom 独立走豁免分支（内置仍早退）；`PII_SCAN_INPUT_LIMIT` 块间 overlap 取 `max(256,最长pattern字面前缀)`。
- 响应侧还原：补 `has_pii` 校验分支；审计二分（判定用还原后明文、落盘/上Matrix用脱敏摘要）；阻断合成与 Anthropic `1241` 冻结为 `_jdumps`（同通道字节一致）；阻断仅透传上游 `model`；非流式超限 fail-closed 返回 `502`；注入后做 schema 校验（非 roundtrip），失败回退不注入+计数。
- 三通道对齐：Anthropic tool 提取冻结为 `_jdumps` 归一化；阻断事件仅透传上游 `model`（无值则缺省，不伪造 id/usage）；`refusal/thinking/input_json_delta` 快慢双路径补单测锁定；pending 事件单次还原标记。
- 清理与文实同步：fallback 保留但标 deprecated + 薄转发（不把 `utils` 变硬依赖）；合一 3 套 `[REDACTED:*]`；修 `mask_pii_value` 双形态 doc、`README` 结构、`pii-gateway-hardening` 勾选；收紧 `api_key` 或断言、补三包装出口用例、去重 `is_chat_tail` 用例。

## Capabilities

### New Capabilities

- `stream-fidelity`: 流式 SSE 帧结构保真（前缀隔离、透传校验、缓冲阈值对齐）。
- `request-redaction`: 请求侧脱敏正确性（位置化跳过、正则统一、粗筛豁免、块间 overlap）。
- `response-restore`: 响应侧还原与审计正确性（has_pii 校验、审计后移、_jdumps 统一、长度守门、三通道阻断对等）。
- `cleanup-docs`: 死码重复清理与文档测试一致性（walk 合一、doc 双形态、README、用例补齐）。

### Modified Capabilities

- 无（`openspec/specs/` 为空，无既有 spec 可改）。

## Impact

- 影响 `_llm.py`（SSE 行处理、事件合成、非流式出口、阻断合成）、`_pii.py`（scan/redact/inject/COARSE_FILTER/分块）、`_token.py`（walk 包装）、`utils/json_walk.py`（正本）、`_metrics.py/_audit.py`（redact 合一）、`tests/*`（用例补齐去重）、`README.md`、`openspec/changes/pii-gateway-hardening/tasks.md` 勾选重标。
- 无新增依赖，无 API 破坏（脱敏口径收紧属行为修正，非 **BREAKING** 接口变更）。
