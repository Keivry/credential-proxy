# proxy.py 优化实施计划

## 🟠 P1 — 高优先级（安全/性能/稳定性）

### 1. 提取常量（#26-33）
- `CREDENTIAL_API_PORT = 8877`
- `UNLOCK_TIMEOUT = 300`, `APPROVAL_TIMEOUT = 300`
- `SYNC_TIMEOUT = 30000`, `UPSTREAM_TOTAL_TIMEOUT = 600`, `UPSTREAM_CONNECT_TIMEOUT = 30`
- `MAX_RETRY_DELAY = 60`, `RATE_LIMIT_INTERVAL = 2.0`
- `REACTION_APPROVE = "✅"`, `REACTION_REJECT = "❎"`
- `CMD_LOCK = "lock proxy"`, `CMD_STATUS = "status"`, `CMD_FORGET = "forget secrets"`
- `SSE_CHUNK_SIZE = 4096`, `SSE_MAX_BUF = 1_048_576`
- `KP_FIELDS = ["password", "username", "url", "title"]`

### 2. 消除重复代码（#21-24）
- 提取 `_filter_hop_headers(headers)` 方法
- 提取 `SSE_CLIENT_GONE` 异常元组常量
- 提取 `_cleanup_request(req_id)` 清理方法
- 统一 `_ask` 失败处理逻辑

### 3. `_redact`/`_restore` 性能优化（#6）
- 改为 `re.sub` 单次编译模式替代多次 `str.replace()`
- 5000 条密码时从 O(n×m) → O(n)

### 4. 真正共享 ClientSession（#7）
- 移到 `CredentialProxy.__init__` 或 `start_llm_proxies`
- 所有端口共用一个 session + 连接池

### 5. 杂项修复（#15, #17, #18, #34, #36）
- 快照加锁保护
- `add_done_callback` 改日志记录
- 双重 shutdown 加固
- `approved` 三态判断显式化

## 🟢 P3 — 低优先级（后续迭代）

- 类拆分（#1-5）
- SSE 微优化（#8-9）
- 类型注解（#36）

---
实施顺序: 1→2→3→4→5
