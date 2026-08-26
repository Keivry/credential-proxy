## Purpose

细化 PII 检测侧的健壮性与性能，在默认关闭（`PII_DETECTION_HARDENING=0` 时不生效）前提下补齐保留地址精确判定、ReDoS 防护与字典独立扫描等生产级边界，使检测在中文/长文本/并发下可测可靠。

## ADDED Requirements

### Requirement: 保留地址精确前缀豁免（当 `PII_DETECTION_HARDENING=1` 时生效，默认关闭不改现有行为）

系统 SHALL 在启用硬化时对命中 IPv4/IPv6 的候选值做保留段二次判定：命中且 `lower()` 后 `startswith` 保留前缀表（含尾点/冒号）时豁免不替换；前缀表含 `10.`/`127.`/`169.254.`/`192.168.`/`172.16.`-`172.31.`/`224.`-`239.`/`240.`-`255.`/`100.64.`-`100.127.`/`fc:`/`fd:`/`fe80:`-`febf:`/`::1`/`2001:db8:` 等全段（`fc`/`fd` 仅 `fc:`/`fd:` 形态豁免，`fcfake` 不豁免），裸 `10`/`2001:db8` 不豁免。

#### Scenario: 私网 172.31 段豁免
- **WHEN** 文本含 `172.31.255.255`
- **THEN** 原样保留，不替换

#### Scenario: 100.128 非保留不豁免
- **WHEN** 文本含 `100.128.0.1`
- **THEN** 被替换为占位符，非豁免

#### Scenario: 裸前缀不误豁免 100.x
- **WHEN** 文本含 `100.1.2.3` 且判定含尾点
- **THEN** 不因裸 `10` 误豁免，`100.*` 仅 `100.64.`-`100.127.` 豁免

### Requirement: ReDoS 线程超时守卫与输入上限（当 `PII_DETECTION_HARDENING=1` 时生效）

系统 SHALL 对可配置自定义正则的每条规则用独立 `ThreadPoolExecutor(max_workers=2, thread_name_prefix='pii-re')`（与审计 `run_in_executor(None)` 不同池）+ `asyncio.timeout(0.1)` 单规则预算守卫，超时/异常跳过该规则并记审计告警，连续超时 3 次临时停用，且单次扫描输入限 `PII_SCAN_INPUT_LIMIT=1M` 分块。**ReDoS 超时守卫在实现中为常开（`_scan_custom` 以 `hardening or timeout` 语义保留），`PII_DETECTION_HARDENING` 仅门控分块/CJK 严格度等增量语义；spec 此节「当 `PII_DETECTION_HARDENING=1` 时生效」仅指增量门控，ReDoS 防护本身常开（design D5 已声明）。**

#### Scenario: 恶意正则不卡死
- **WHEN** 配置 `(a+)+$` 且输入 `a`*64
- **THEN** 100ms 内超时跳过该规则，审计告警，其余规则仍生效

#### Scenario: 连续超时停用
- **WHEN** 某规则连续 3 次超时
- **THEN** 该规则临时停用，后续请求不再尝试

#### Scenario: 超长输入分块
- **WHEN** 请求 body 2MB
- **THEN** 按 1M 分块扫描，不单次全量跑联合正则

### Requirement: 字典名单独立扫描与 CJK 边界（当 `PII_DETECTION_HARDENING=1` 时生效）

系统 SHALL 对敏感名称名单做独立扫描（不并入联合正则），按长度降序+`re.escape`+`dict_ver` 缓存，CJK 边界 `(?<![\w\u4e00-\u9fff])`/`(?![\w\u4e00-\u9fff])` 精确命中，5000 名单单 chunk ≤1ms。

#### Scenario: 独立扫描不并入联合
- **WHEN** 启用 5000 名单与联合正则
- **THEN** 联合正则扫描耗时不含字典分支，字典扫描独立≤1ms

#### Scenario: 张三不误伤张三丰
- **WHEN** 名单含 `张三` 且文本为 `张三丰`
- **THEN** `张三` 不命中（CJK 边界）

#### Scenario: 配置重载缓存失效
- **WHEN** 名称名单配置重载 `dict_ver` 自增
- **THEN** 旧 `re.compile` 缓存失效重编译

### Requirement: Analyzer 缓存与看词表无关（当 `PII_DETECTION_HARDENING=1` 时生效）

系统 SHALL 对 PII 检测的编译态（联合正则/`AnalyzerEngine`）做缓存（`lru_cache maxsize=4` / `dict_ver`），同配置复用实例，配置变更 `cache_clear`，且不引入 `spacy`/`presidio` 强依赖时仍可用（纯正则路径独立）。

#### Scenario: 同配置复用编译结果
- **WHEN** 两次扫描同 `PII_REDACTION_TYPES` 与名单版本
- **THEN** 第二次命中缓存，不重编译

#### Scenario: 配置变更清缓存
- **WHEN** `dict_ver` 变化
- **THEN** `cache_clear` 后重建
