## Context

见 `proposal.md` Why。现状：`_llm.py:2044` 多行块已 D2 独立解析但单行 plain 回退仍送整行；`583` D1 已保留字段但非 dict 透传无校验；`_pii.py:1405/1532` 值等价跳过 vs 响应侧区间化；`692` 粗筛误杀 custom；`utils/json_walk.py` 正本已收敛但三包装 fallback 未删。约束：orjson 优先、`ensure_ascii=False,separators=(',',':')`、`depth` 仅计 str→inner、ruff+pytest 必过、public repo 禁内网信息。

## Goals / Non-Goals

**Goals:**

- 前缀隔离 + 透传校验 + 三通道阻断对等，消灭破结构透传坏 JSON。
- 位置化跳过 + 口径统一 + 粗筛豁免 + overlap，消灭漏脱敏与误伤。
- 审计后移 + has_pii 校验 + `_jdumps` 统一，审计看到明文。
- 4 套 walk 合一 + 文实同步，零死函数。

**Non-Goals:**

- 不改占位符格式（`__PII_<seq>_<hex8>__`/`__VG_CRED_<digits>__` 不变）。
- 不调阈值（1M/16K/30s/10s 不变，仅抽常量）。
- 不做编辑距离模糊还原（`PII_FUZZY_RESTORE` 语义不变）。
- 本次不修：`data_buffer \n-join` 改逐行 walk、`tool_calls` 子串误匹配收紧、截断对称、TTFB 快路径持有、`depth>5` 超深、`signature_delta/code_interpreter` 新通道（留后续 change）。

## Decisions

- **位置区间优于值等价**：新增 `scan_spans()->[(kind,value,start,end)]`，`detect_and_redact` 按 span 位置替换（长跨度优先+重叠仲裁）。替代：保留值判（同值多处必漏）。选前者对齐响应侧。
- **保护区间常量以 `_pii.py:1472` 为准**：抽 `utils` 共享常量，`_llm.py:149/1098` 改引用。替代：统一到 `_llm` 窄口径（漏检）。选前者。
- **共享正本+fallback 保留 deprecated**：`_llm:82` 等保留但标 deprecated + 薄转发锁定行为一致，不把 `utils` 变硬依赖（保 `llm-proxy-only.py` 极简部署）。替代：硬删（breaking）。选保留。
- **审计二分优于整体后移**：判定用还原后明文、落盘/上 Matrix 用脱敏摘要（`_audit.py:836`+`redact_summary` 同步复审）。替代：全量明文落盘（隐私倒退）/全量占位符判定（漏拦）。选二分。
- **Overlap 动态优于固定 256**：`max(256,最长pattern字面前缀)`，custom 独立豁免分支（内置仍早退）。替代：固定值/全量重扫（保证不足/性能回退）。选动态+独立分支。
- **审计归一冻结为 `_jdumps`**：`_extract_tool_calls_non_stream:1241` 改 `_jdumps`，同通道字节一致（跨协议 schema 不同不要求 hash 可比）。替代：保留原始空白（与统一矛盾）。选冻结。
- **阻断仅透传 model**：无值则缺省，不伪造 id/usage（严格 SDK 校验前缀/类型）。替代：补全三字段（污染客户端/审计）。选透传。
- **非流式超限 fail-closed 取 502**：与现有空体 502 约定兼容，不新增 413 客户端分支。替代：413（新增分支）。选 502。

## Risks / Trade-offs

- [位置化替换性能] → 逐段替换 O(n·m)，1M 包多 ~ms 级，守门+分块兜底；先在分块路径压测。
- [审计二分多一次 loads] → 非流式多 2-3ms，接受（正确性优先）；落盘面不扩大。
- [保留 fallback] → 重复代码暂留，仅薄转发+deprecated，避免极简部署 breaking。
- [阻断仅透传 model] → 无值缺省，需 hermes/网关兼容性验证后再全量。
- [`_sanitize_json` 映射] → `CRLF->LF`、`TAB` 保留，`<0x20` 其余按映射表，不全压 `\n`。

## Migration Plan

- 按 tasks 依赖重排实施：2.1 位置 API → 2.2 替换/分块 → 3.1 审计二分 → 1.x 流式 → 4.x 清理；每阶段 `pytest -q + ruff` 门禁；任一阶段红灯回滚该阶段单文件。
- `pii-gateway-hardening/tasks.md` 6.1/9.6 勾选在 cleanup 阶段同步重标。

## Open Questions

- overlap 取 256 是否覆盖最长自定义前缀？可在实现期按最长 pattern 动态计算，不改 spec。
