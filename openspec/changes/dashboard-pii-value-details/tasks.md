> 依赖图：`1.1→2.1→2.2→3.1→3.2→3.3→3.4→3.5→4.1→5.1/5.2→5.3/5.4→6.x→7.x`；`6.1`在`2.1`后即跑（TDD），`1.1`首位完成再启`3.x`。

## 1. 配置与契约

- [ ] 1.1 新增 `PII_VALUE_SAMPLE_ENABLED` / `PII_VALUE_SAMPLE_PERSIST` 环境变量解析（`parse_pii_env_config` 扩展），默认 `0`，`PERSIST=1` 时隐含 `ENABLED=1`，非法值记 `errors` 并告警回退 `0`
  - 验收：`PII_VALUE_SAMPLE_ENABLED=1` 时 `_is_pii_value_sample_enabled()` 为真；默认 `0` 时不产采样；`PERSIST=1` 自动启用 `ENABLED`；非法值 `errors` 含提示
- [ ] 1.2 `openapi` 文档/`.env.example`/`docker-compose.yml` 补充两开关说明（默认关闭、掩码形态、`hash` 截断、TopN=5、7 天滚动）
  - 验收：`grep PII_VALUE_SAMPLE .env.example docker-compose.yml` 命中且标注“仅掩码不存明文”

## 2. 掩码生成（_pii.py）

- [ ] 2.1 新增 `mask_pii_value(kind: str, value: str) -> str`（phone→`138****8000`、email→`a***@b.com`（`***@***.com`消歧可选）、bank_card→`**** **** **** 6789` 仅后4（BIN不保留）、ipv4→`192.168.**.**`、ipv6/api_key→`前4****后4`、其他→`前3****后3` 且 `<6` 时 `前1****后1`；`masked_sample` 长度上限64超长截断，`value_hash`落盘键为`hash` 16 hex）
  - 验收：`mask_pii_value('phone','__PII_7_6716b652__')=='138****8000'`；`mask_pii_value('email','__PII_10_fbfda189__')=='a***@b.com'`；单测覆盖各 kind
- [ ] 2.2 `ContextVar _req_pii_var` 扩展 `pii_value_samples: dict[str, dict[str, dict]]`（`masked -> {count, hash}`，`recent_events`精简为`{masked:count}`），命中回调内当场 `value_hash=sha256(value).hexdigest()[:16]`（键为`hash`）+ `masked=mask_pii_value(kind,value)` 按`kind`累加`pii_value_samples[kind][masked].count+=1`；仅 `ENABLED=1 && is_chat_tail` 时产采样，`incr_event` 锁外拷贝`delta`后立即`clear()`并`handler finally reset_req_pii_ctx()` 防跨请求叠加
  - 验收：`PiiDetector.scan("__PII_7_6716b652__")`（对话路径）后 `_req_pii_var.get()['pii_value_samples']['phone']['138****8000']['count']==1` 且 `hash`为16 hex；非对话`scan()`后`pii_value_samples`仍空；`ENABLED=0` 时空；`asyncio.gather`双请求并发计数互不干扰
- [ ] 2.3 `sanitize_kind` 复用约束掩码 key，`masked_sample` 长度上限 64（含 `*`），超长截断；`value_hash` 仅 hex 16 位
  - 验收：超长 `masked_sample` 被截断；`hash` 恒 16 hex

## 3. 聚合与持久化（_metrics.py）

- [ ] 3.1 `_DailyAgg/_HourlyAgg` 各加 `pii_value_samples: dict[str, dict[str, dict]]`（`masked -> {count, hash}`），`incr_event` 内按 `delta_pii_value_samples` 合并，kind 内按 `count` 降序截 Top5，kind 总数 ≤8
  - 验收：连续命中 10 个不同 `138****0000..0009` 后 `d.pii_value_samples['phone']` 仅 5 条且按 count 降序
- [ ] 3.2 `recent_events` 入队时存 `pii_value_samples` 快照（`{masked: count}` 精简，不存 hash 减体积），`events()` 透出不受影响
  - 验收：`recent_events[0]['pii_value_samples']['phone']['138****8000']==1`
- [ ] 3.3 `query_range` 扩展：`1h` 从 `recent_events` 现场聚合 `pii_value_samples`（精确，Top5聚合展示取前3），`24h/7d/30d` 若 `PERSIST=0` 返回 `{}` 且 `pii_value_samples_is_precise=false` 不读盘，`PERSIST=1` 时从`pii_value_agg`日级归并；`ENABLED/PERSIST`热切换原子（每次即读，`PERSIST 1→0`后`24h`立即空），`model/upstream`过滤联动（`1h`精确按事件筛，其余近似）
  - 验收：`query_range('1h', ENABLED=1)` 含 Top5且展示前3；`query_range('24h', PERSIST=0)` 为 `{}` 且 `pii_value_samples_is_precise==false` 不触发磁盘读；`PERSIST 1→0`热切后立即空；`upstream_filter='8878'` 时仅该上游
- [ ] 3.4 可选表 `pii_value_agg(day TEXT, upstream TEXT, kind TEXT, hash TEXT, masked_sample TEXT, count INT, PRIMARY KEY(day, upstream, kind, hash))` 仅 `PERSIST=1` 时 `CREATE TABLE IF NOT EXISTS`，按日覆盖式 UPSERT（`count=excluded.count`），7 天滚动 `DELETE WHERE day < ?`，`0600` 权限
  - 验收：`PERSIST=1` 首次 flush 后 `SELECT count(*) FROM pii_value_agg` 有行；`PERSIST=0` 不建表；`day < today-7d` 行被清
- [ ] 3.5 `_snapshot` 深拷贝扩展 `pii_value_samples`，`_write_flush` 批量 UPSERT `pii_value_agg`（日级 ≤40 行），`_trim_old` 按 `day` 清理 7天 `DELETE WHERE day < ?` 并重 `chmod 0600`（含 -wal/-shm，`umask 0o077`紧邻建库）
  - 验收：`_snapshot` 含 `pii_value_samples`；`queue.Queue(maxsize=512)` 单写者串行满队`dropped_snapshots++`；跨天`day`切换单测 `mock UTC 23:59→00:01` TopN各自独立

## 4. 管理 API（_admin.py）

- [ ] 4.1 `GET /_admin/metrics?range=&model=&upstream=` 透出 `pii_value_samples` 与 `pii_value_samples_is_precise`（向后兼容缺省 `{}/false`），鉴权/限流/`no-store` 不变，未鉴权 `401` 不泄露采样
  - 验收：`curl -H "X-Admin-Token: t" /_admin/metrics?range=1h` 含 `pii_value_samples`；无 token `401` 且无该字段明文
- [ ] 4.2 `health` 补充 `pii_value_sample_enabled/persist` 标志（可选）
  - 验收：`/_admin/health` 含 `pii_value_sample_enabled` 布尔

## 5. 前端（admin.html）

- [ ] 5.1 `renderBar('pii')` Chart.js `tooltip.callbacks.afterBody` 扩展：有采样时追加 `Top 3: 138****8000 x5, ...`（取Top5前3，`count`经`toLocaleString()`精确非`fmtNum`缩写，SVG `<title>` 多行 `kind: count\nmasked x count` 与Chart.js一致）；`rect<title>`与`text title`分置不同元素；无采样时仅计数
  - 验收：悬停 `phone` 柱时 tooltip 含 `138****8000 x5`（精确）；`ENABLED=0`时仅`phone: 12,345`；SVG降级`<rect><title>`含掩码多行且`text`长标签不遮掩
- [ ] 5.2 SVG 降级 `<title>` 扩展：`kind: count\nmasked x count\n...` 多行，数值与 Chart.js 一致
  - 验收：禁用 Chart.js 后悬停 `<rect>` 的 `<title>` 含掩码行
- [ ] 5.3 全部渲染经 `textContent`/`title` 文本通道（pii分支`textContent/title` 0 innerHTML），`masked_sample` 含 `* @ .` 原样保留；`_handle_sse` 补 `Cache-Control: no-store`
  - 验收：`grep -n innerHTML admin.html` 在`renderBar('pii') afterBody/<title>`分支0命中（全量`innerHTML`仍2处KPI且均经`esc()`）；`masked_sample='<img onerror=alert(1)>'` 经`textContent`原样透传；SSE响应头含`no-store`
- [ ] 5.4 无采样/截断态 UI：`pii_value_samples_truncated[ kind ]==true` 且 `ENABLED=1 && 非空 && 超Top5` 时 tooltip 尾加 `…长尾仅计 pii_by_type`，否则不提示；`PERSIST=0 && range!=1h` 时灰显`仅1h精确，24h/7d需开启持久化`
  - 验收：`truncated=true`时显示 `…`；`pii_value_samples:{}`或`ENABLED=0`时无掩码行亦无`…`；`pii_value_samples_truncated`键名全量一致

## 6. 测试与验证

- [ ] 6.1 新增 `tests/test_pii_value_samples.py`：掩码形态（各 kind）、TopN 截断（>5 截断）、开关（ENABLED/PERSIST）、hash 16hex、sanitize 边界
  - 验收：pytest 通过；`hash` 稳定；`Top5` 断言成立
- [ ] 6.2 新增 `tests/observability_pii_value_test.py`：`query_range('1h')` 精确、`query_range('24h', PERSIST=0)` 空、`pii_value_agg` 建表/滚动/0600、`metrics` API 401 不泄露
  - 验收：pytest 通过；`metrics.sqlite` 权限 `0600`；未鉴权不含采样
- [ ] 6.3 前端回归：`admin.html` Chart.js/SVG 双路径 hover 含掩码，`fmtNum` 缩写与精确值共存，`ruff check/format --check` 必过
  - 验收：`ruff check .` 0 错误；`ruff format --check .` 通过
- [ ] 6.4 全量回归：`pytest` 全绿（含既有 `132+` 用例），`PII_VALUE_SAMPLE_ENABLED=0` 时旧行为完全一致
  - 验收：`ENABLED=0` 时 `pii_value_samples` 缺省且 dashboard 仅计数

## 7. 文档与发布

- [ ] 7.1 `README.md` 补充 PII 值级悬停说明（默认仅计数、开启掩码 TopN、开关含义、不存明文、SQLite 可选表）
  - 验收：README 含 `PII_VALUE_SAMPLE_*` 说明与掩码示例
- [ ] 7.2 `CHANGELOG.md` 记录本 change（`pii-value-samples` 新能力、`observability-metrics/dashboard` 增强）
  - 验收：CHANGELOG 有 `dashboard-pii-value-details` 条目
- [ ] 7.3 版本 bump（`pyproject.toml` + `docker-compose.yml` image tag + `uv.lock`）+ `git commit -m "feat(dashboard): pii value samples"` + tag + push 触发 CI
  - 验收：`git tag v0.9.4x` 推送后 GitHub Actions 构建成功
