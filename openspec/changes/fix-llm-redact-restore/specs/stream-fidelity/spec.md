## Purpose

保证流式 SSE 在脱敏/还原后帧结构与上游语义等价，客户端可正常解析事件、工具调用与推理通道。

## ADDED Requirements

### Requirement: SSE data 行前缀隔离

系统 SHALL 在 JSON-aware 失败回退 plain 时仅对 payload 做还原，MUST NOT 把 `data:` 前缀送入还原函数；`event:/id:/retry:/:` 行 MUST 原样透传。

#### Scenario: 非 JSON 载荷回退不破帧

- **WHEN** 收到 `data: hello` 非 JSON 行且还原失败回退
- **THEN** 输出仍以 `data: ` 开头且为单行合法 SSE，事件名不被改写

#### Scenario: 控制行原样透传

- **WHEN** 收到 `event:`/`id:`/`retry:`/`:` 注释行或 `data:[DONE]`
- **THEN** 系统原样透传，不做任何 token 还原改写

### Requirement: 非字典载荷原文保留

系统 SHALL 对非 dict 解析结果整包透传且 MUST NOT 抛 AttributeError，透传 MUST 保留原文可解析性。

#### Scenario: 数组载荷透传

- **WHEN** 上游载荷为 JSON 数组或字符串
- **THEN** 系统透传原文且下游可解析，不抛异常

### Requirement: 缓冲阈值与通道覆盖可验证

系统 SHALL 对 `refusal/thinking/input_json_delta` 通道与快慢双路径累积行为提供回归用例覆盖，pending 事件 MUST 单次还原。

#### Scenario: 拒答通道不断流

- **WHEN** 上游以 `delta.refusal` 分片返回
- **THEN** 下游收到完整可解析 SSE 且内容语义等价

#### Scenario: 控制字符映射明确

- **WHEN** 载荷含 `CRLF/TAB` 控制字符
- **THEN** 系统按映射表处理（`CRLF->LF`、`TAB` 保留），不全压为 `\n`
