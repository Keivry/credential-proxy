## Purpose

消除重复 walk 漂移并保留兼容，统一文档注释与测试断言，使实现、文档、用例三方一致。

## ADDED Requirements

### Requirement: 单一 JSON walk 正本加 deprecated 薄转发

系统 SHALL 以 `utils/json_walk.py` 为正本，旧私有 walk SHALL 保留为 deprecated 薄转发且行为 MUST 与正本一致。

#### Scenario: 行为一致性锁定

- **WHEN** 经旧包装与正本分别 walk 同一嵌套载荷
- **THEN** 两者输出字节一致，无零引用硬删导致的极简部署 breaking

### Requirement: 文档双形态一致

系统 SHALL 明确区分真实值掩码与占位符掩码形态，文档、spec、用例 MUST 三方一致。

#### Scenario: phone 掩码用例与文档一致

- **WHEN** 查阅 mask 文档并运行用例
- **THEN** 真实值与占位符各自断言唯一确定，无或恒真断言

### Requirement: 测试覆盖三包装出口

系统 SHALL 为 token/pii/llm 三包装校验出口提供用例，README 结构 MUST 与实际文件一致。

#### Scenario: 响应侧破坏用例存在

- **WHEN** 运行回归套件
- **THEN** 三包装出口的合法变非法回退行为均被断言，README 列出全部服务端文件
