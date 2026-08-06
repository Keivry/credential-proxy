## 1. PII 请求级 token 机制

- [ ] 1.1 扩展 `_token.py`：新增请求级映射容器（`RequestScopedTokens`），支持独立于全局 `pwd_to_token` 的 `pii_p2t`/`pii_t2p`、`__PII_*__` token 前缀生成、`_restore` 时请求级优先全局兜底
- [ ] 1.2 单元测试：请求级映射生命周期（创建/还原/清理）、与全局凭据映射互不串扰、token 前缀不冲突

## 2. PII 检测器（`_pii.py`）

- [ ] 2.1 实现 `PiiDetector` 接口与 recognizer 注册表（正则 + 校验位/上下文强化）：大陆身份证（含校验位验证）、手机号（前缀段验证）、邮箱、银行卡（Luhn 校验）、IPv4、常见 API key 格式（sk-、ghp_ 等）
- [ ] 2.2 实现 `PiiMixin`：`detect_and_redact(text)`（检测→注册请求级 token→替换）、`restore(text)`（请求级还原）、请求级映射生命周期管理
- [ ] 2.3 单元测试：每种 recognizer 的命中/漏报/边界（误报如纯数字订单号、连续数字串）、还原正确性

## 3. PII 脱敏接入 `_llm.py`

- [ ] 3.1 请求侧：`_llm.py` handler 中在现有 `_redact` 前插入 PII 检测（`PII_REDACTION_ENABLED` 时），统一输出脱敏 body；`used_tokens` 收集同时覆盖凭据与 PII token
- [ ] 3.2 响应侧：`_restore` 后追加响应侧 PII 检测（默认开启），对未脱敏的 PII 回显替换为占位符；非流式与流式（SSE 各协议路径）都要覆盖
- [ ] 3.3 集成测试：请求含 PII + 凭据混合、流式响应还原、响应回显 PII 拦截

## 4. 输出审计钩子（tool call 检测）

- [ ] 4.1 新增 OpenAI chat/completions `delta.tool_calls` 分片累积（按 index 分组 name + arguments），复用 `_split_safe_hold`/`_PARTIAL_TOKEN_RE` 模式，在 `finish_reason == 'tool_calls'` 或流末触发审计点；注意跨分片伪还原与 null 值防御
- [ ] 4.2 审计触发点对齐已有完成事件：Anthropic `block_stop`、Responses `item_done`（读取 arg_buf 完整参数）
- [ ] 4.3 集成测试：三种协议流式 tool call 分片累积 + 审计触发（真实 aiohttp，参考 `test_sse_stream_loop.py` 模式）

## 5. 策略引擎与阻断模式（`_audit.py`）

- [ ] 5.1 实现 `AuditMixin`：`audit_tool_call(name, args_json) -> AuditVerdict`（allow/deny 名单 + 危险模式规则：危险 shell 命令、敏感路径写入、网络外传）
- [ ] 5.2 内置默认策略 + `AUDIT_POLICY_FILE` 可选 YAML/JSON 加载（schema 精简）
- [ ] 5.3 阻断处置：危险 tool call 替换为「无 tool_calls 的 assistant 拒绝消息」（`finish_reason: stop`），后续流正常；非流式整包响应同样支持
- [ ] 5.4 单元测试：策略匹配（allow/deny/危险模式/边界）、阻断注入的协议结构合法性

## 6. 审批模式

- [ ] 6.1 复用 `_matrix.py` `_ask`/pending/超时机制：危险 tool call 挂起 → Matrix ✅/❎ 审批消息（含工具名与参数摘要）→ 批准后补发原格式事件 / 拒绝后注入拒绝消息 / 超时默认拒绝
- [ ] 6.2 流式挂起细节：挂起期间缓冲后续事件，审批完成统一放行/替换，不破坏 SSE 流结构
- [ ] 6.3 集成测试：审批通过/拒绝/超时三种路径 + 流式完整性

## 7. 审计日志

- [ ] 7.1 追加写 `DATA_DIR/audit.log`（JSON Lines）：时间、检测类型、规则匹配、参数摘要（截断+脱敏）、处置结果
- [ ] 7.2 单元测试：日志格式、敏感值不落盘、追加写与并发安全

## 8. 配置与入口集成

- [ ] 8.1 `proxy.py`：解析新环境变量（`PII_REDACTION_ENABLED`、`PII_RESPONSE_SIDE`、`AUDIT_MODE`、`AUDIT_TIMEOUT`、`AUDIT_POLICY_FILE`），组合 `PiiMixin` + `AuditMixin`
- [ ] 8.2 轻量入口（llm-proxy-only / credential-proxy-only）按需引入 Mixin；Docker entrypoint/compose 增加环境变量透传与文档
- [ ] 8.3 默认关闭回归验证：不配置新变量时全量测试通过、行为与现状一致

## 9. 验证与发布

- [ ] 9.1 ruff check + ruff format --check + 全量 pytest 全绿（132 + 新增）
- [ ] 9.2 真实流量验证（llm-proxy-only 本地）：PII 请求/响应脱敏、危险 tool call 阻断、审批流程；验证 design.md Open Questions（`finish_reason` 可靠性、拒绝消息兼容性）
- [ ] 9.3 版本 bump（v0.9.x）+ README changelog + Docker 镜像 tag + 打 tag 触发 CI 全量构建（Docker + Go 二进制）
