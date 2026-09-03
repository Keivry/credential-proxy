## 1. 请求侧位置契约 P0（依赖起点）

- [x] 1.1 新增 `scan_spans` 并改位置化替换
  - Verify: 同值多处用例通过：凭据区间保凭据 token、独立 PII 处出 PII 占位符
  - Verify: 保护区间同值用例通过：已保护区间内同值不二次替换，无双 token 串扰
  - Verify: `PYTHONPATH=. pytest -q tests/pii_*` 通过且 ruff clean

- [x] 1.2 保护区间常量统一 + custom 独立豁免 + 动态 overlap
  - Verify: 全链路保护区间与 `_pii.py:1472` 同义（`utils` 共享常量），短序号/大小写变体单测一致
  - Verify: 纯中文自定义用例通过（`绝密文件`类命中出占位符），内置粗筛行为不变
  - Verify: 跨块手机号用例检出（overlap=`max(256,最长pattern字面前缀)`），大包无漏过

## 2. 响应审计二分与归一 P0

- [x] 2.1 has_pii 校验 + 审计二分 + _jdumps 归一 + 长度守门
  - Verify: 纯 PII 还原破坏用例回退原文，不透传坏 JSON（下游 200 合法包）
  - Verify: 危险参数占位符用例正确阻断，且审计日志仅存脱敏摘要（无明文落盘）
  - Verify: 同一参数同通道两次提取字节一致；非流式超限 fail-closed（状态码按 design）

- [x] 2.2 注入 schema 校验 + 提取口径冻结 + 阻断透传 model
  - Verify: 注入破坏结构用例回退不注入并计数，不静默转发坏包
  - Verify: 三协议注入位置单测通过（OpenAI 头插/Anthropic 追加/Responses 头插）
  - Verify: 阻断三形态解析回归通过：含上游 `model` 透传、无值缺省，不伪造 id/usage

## 3. 流式保真 P1

- [x] 3.1 SSE 回退全路径 payload 隔离 + 非 dict 保留 + 映射表
  - Verify: `data: hello` 非 JSON 行输出仍 `data: ` 开头单行；`event:/id:/retry:/:`/`data:[DONE]` 原样透传单测通过
  - Verify: 数组/字符串载荷透传用例通过（不抛 AttributeError，下游可解析）
  - Verify: `CRLF->LF`、`TAB` 保留映射用例通过；`pytest -q tests/sse_*` 通过

- [x] 3.2 通道累积回归锁定 + pending 单次还原
  - Verify: `delta.refusal` 分片累积还原输出可解析 SSE
  - Verify: Anthropic `thinking_delta` 与 Responses `input_json_delta` 快慢双路径用例通过
  - Verify: pending 事件单次还原用例通过（无双还原漂移）；`SSE_MAX_BUF/LINE_BUF_*` 抽 `_sse.py` 常量行为不变

## 4. 清理与文实同步 P2

- [x] 4.1 fallback 标 deprecated 薄转发 + redact 合一
  - Verify: 旧包装与正本 walk 同一嵌套载荷输出字节一致（行为一致性用例通过）
  - Verify: 三套 `[REDACTED:*]` 合一，`_strip_bom` 统一调用；`re_sub_seps` 内联改名
  - Verify: 极简入口（`llm-proxy-only.py`）导入可用，无硬依赖 breaking

- [x] 4.2 文档测试一致性
  - Verify: `mask_pii_value` doc 区分真实值 vs 占位符，与 `pii_value_samples_test` 双断言一致，无 `or '****'` 恒真
  - Verify: `README` 列出 `_pii/_audit/_metrics/_admin/utils` 且 `tests/*_test.py` 口径正确；`vault_stable_test` 覆盖三包装出口；`pii-gateway-hardening/tasks.md` 6.1/9.6 勾选同步重标
  - Verify: `is_chat_tail` 重复用例去重，旧“剥离完整token”措辞清零；`openspec validate fix-llm-redact-restore --strict` 通过
