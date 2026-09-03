## Purpose

确保请求侧脱敏不漏检、不误伤，占位符口径统一，大包分块不丢跨界敏感信息。

## ADDED Requirements

### Requirement: 位置化扫描与替换契约

系统 SHALL 提供 `scan_spans()->[(kind,value,start,end)]` 位置契约，`detect_and_redact` SHALL 按 span 位置替换（长跨度优先+重叠仲裁），MUST NOT 用 `text.replace` 全量替换。

#### Scenario: 同值多处分别处理

- **WHEN** 同一字符串一处为凭据区间、一处为独立 PII
- **THEN** 凭据处保留凭据 token，独立处生成 PII 占位符

#### Scenario: 保护区间同值不二次替换

- **WHEN** 已保护区间内出现同值文本
- **THEN** 系统不做二次替换，不产生双 token 串扰

### Requirement: 占位符口径统一到 pii 语义

系统 SHALL 全链路使用与 `_pii.py:1472` 同义的保护区间常量（抽 `utils` 共享），短序号与大小写变体 MUST 按同一规则处理。

#### Scenario: 残缺 token 不串扰

- **WHEN** 输入含残缺或变体占位符形态
- **THEN** 系统不将其误判为保护区间，也不产生双 token 串扰

### Requirement: 自定义规则独立豁免粗筛

系统 SHALL 对 custom 扫描独立走豁免分支（内置仍可用粗筛早退），纯中文正则 MUST 被扫描。

#### Scenario: 纯中文规则命中

- **WHEN** 自定义规则为纯中文且输入命中
- **THEN** 系统生成 PII 占位符而非透传原文

### Requirement: 大包分块跨界不丢

系统 SHALL 在 1M 分块扫描时加 `max(256,最长pattern字面前缀)` overlap 窗口，边界窗口内模式 MUST 被检出。

#### Scenario: 跨块手机号检出

- **WHEN** 手机号前后缀分居两块边界 overlap 窗口内
- **THEN** 系统仍检出并脱敏，不漏过
