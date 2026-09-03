## Purpose

确保响应侧还原不破坏 JSON、审计判定基于明文而落盘保持脱敏、阻断形态三通道对等。

## ADDED Requirements

### Requirement: 纯 PII 破坏可校验回退

系统 SHALL 在纯 PII（无凭据）还原破坏 JSON 时回退原文，MUST NOT 透传坏 JSON。

#### Scenario: 纯 PII 还原破坏回退

- **WHEN** 仅 PII 还原因特殊字符导致非法 JSON
- **THEN** 下游收到上游原文或合法 JSON，而非 500 坏包

### Requirement: 审计判定与落盘二分

系统 SHALL 用还原后明文做审计判定，用脱敏摘要做落盘与上 Matrix 内容，判定 MUST 看到明文、落盘 MUST NOT 含明文。

#### Scenario: 占位符掩盖危险参数被识破

- **WHEN** 工具参数含占位符包裹的危险命令
- **THEN** 审计基于还原后明文判定阻断，且日志仅存脱敏摘要

### Requirement: 审计归一化口径冻结

系统 SHALL 在审计提取前用 `_jdumps` 归一化，同一参数经同一通道两次提取 MUST 字节一致。

#### Scenario: 同通道提取一致

- **WHEN** 同一工具参数经同一通道两次提取
- **THEN** 审计看到的归一化字节一致，不因空白转义分叉

### Requirement: 阻断事件仅透传 model

系统 SHALL 在阻断合成事件中仅透传上游 `model` 值，无值时缺省该字段，MUST NOT 伪造 `id/usage`。

#### Scenario: 含上游 model 透传

- **WHEN** 上游响应含 `model` 且工具调用被阻断
- **THEN** 阻断事件含同一 `model` 值且无伪造 `id/usage`，客户端可解析

#### Scenario: 无 model 缺省兼容

- **WHEN** 上游无 `model` 且工具调用被阻断
- **THEN** 阻断事件缺省 `model` 字段，客户端不因缺字段崩溃

### Requirement: 注入 schema 校验与长度守门

系统 SHALL 在占位符说明注入后断言 messages/input/system 结构仍符合协议分支，失败 MUST 回退不注入并计数；非流式超限 SHALL fail-closed 返回 `502`（与现有空体 502 约定兼容）并计数。

#### Scenario: 注入破坏结构回退不注入

- **WHEN** 注入导致请求结构不符合协议分支
- **THEN** 系统回退不注入并计数，不静默转发坏包

#### Scenario: 非流式超限 fail-closed

- **WHEN** 非流式包体超 1M 长度守门
- **THEN** 系统返回 `502` 并计数，不做全量 walk 透传
