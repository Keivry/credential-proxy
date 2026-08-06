## Why

当前 credential-proxy 的 LLM 脱敏是**被动式**的：只有通过 `/credential` API 注册过的秘密（`pwd_to_token` 映射）才会被 `_redact`/`_restore` 替换。对话中直接出现的身份证号、手机号、地址、硬编码在 prompt/memory 中的 API key 等敏感信息，proxy 无法识别，原样发送给 LLM 提供商；同时，LLM 返回的内容（危险脚本、危险工具调用）完全没有安全审计，等于「入口有保险箱、出口无安检」。目标是把 credential-proxy 升级为通用的 LLM 隐私保护与安全审计中间层。

## What Changes

- **主动 PII 检测与脱敏（双向）**：在现有凭据 token 替换基础上，新增 PII 检测层——请求 body 检测身份证号、手机号、邮箱、银行卡、IP、常见 API key 等模式，值注册进 token 映射后替换为占位符；响应侧同样检测，防止 LLM 回显/复述用户 PII，并还原请求侧脱敏产生的占位符
- **PII token 请求级作用域**：检测出的 PII 值使用带 TTL 的请求级 token 映射，不永久注册，避免内存膨胀与跨请求串扰
- **输出 tool call 安全审计**：在 LLM 响应（含流式）的 tool call 完成事件处挂 post-call 审计钩子，检查工具名称与参数
- **策略引擎**：工具 allow/deny 名单 + 危险模式库（危险 shell 命令、敏感路径写入、网络外传等）+ 可配置策略
- **两种处置模式**：
  - 阻断模式（默认）：检测到危险调用 → 注入「被安全策略拒绝」的响应给客户端，不阻塞
  - 审批模式（可选）：复用 Matrix reactions 审批，危险操作挂起等待 ✅/❎，与现有凭据审批体验一致
- **审计日志**：记录每次检测/阻断/审批事件（时间、请求方、检测类型、处置结果）
- 所有新功能**默认关闭**（环境变量/配置文件 feature flag 开启），不改变现有行为，不破坏现有 132 个测试

## Capabilities

### New Capabilities

- `pii-redaction`: 主动 PII 检测与可逆脱敏——请求/响应双向检测，占位符替换与还原，请求级 token 生命周期
- `output-security-audit`: LLM 输出安全审计——tool call 策略检查、危险模式检测、阻断/审批两种处置、审计日志

### Modified Capabilities

（无——本项目尚无 openspec/specs/ 基线，全部为新增能力）

## Impact

- **新增文件**：`_pii.py`（PII 检测/替换）、`_audit.py`（输出审计策略引擎）、`_audit_store.py` 或复用 `_registry.py` 持久化审计日志
- **修改文件**：`_llm.py`（请求 redact 前插 PII 检测、tool call 完成事件挂审计钩子、审批等待/注入拒绝响应的流式处理）、`_token.py`（PII token 注册与 TTL 支持）、`_matrix.py`（审批消息类型扩展）、`proxy.py`（feature flag 配置解析）、`docker-entrypoint.sh` / `docker-compose.yml`（新环境变量）
- **API**：无对外 API 变更；新增配置环境变量（如 `PII_REDACTION_ENABLED`、`AUDIT_MODE`、`AUDIT_POLICY_FILE`）
- **依赖**：Phase 1 零新增依赖（正则/规则引擎）；Phase 3 可选 Presidio（feature flag，不进默认镜像）
- **测试**：新增 `test_pii.py`、`test_audit.py`、SSE 流式审计集成测试；全量 pytest + ruff 必须保持通过
- **部署**：Docker 镜像 tag 升级；Hermes 侧 custom provider 配置不变
