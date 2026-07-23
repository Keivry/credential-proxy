# Credential Proxy — Performance Review

Reviewed: 6 files, 971 lines total. Focus: `_redact`/`_restore`, SSE, `async with`, `OrderedDict`, locks.

---

## Findings (Ranked by ROI)

### 🔴 [HIGH] 1. `_redact` re-compiles regex on every LLM request — cache missed entirely

**File:** `_token.py:63-66`

```python
items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
pattern = _re.compile("|".join(_re.escape(pwd) for pwd, _ in items))
repl = {pwd: token for pwd, token in items}
```

**Problem:** Every LLM API call with a request body triggers a full `sorted()` (O(N log N)) + `_re.compile("|".join(...))` (O(N)). With `MAX_TOKEN_ENTRIES=5000`, the compiled regex can be **50,000+ characters** long. Compiling this fresh per-request is wasted work because the mapping rarely changes between requests.

Moreover, in `_llm.py:46`, a snapshot dict is passed *instead of* the live `self.pwd_to_token`, so even if `_redact` attempted internal caching, the snapshot dict is a different object every time — cache always misses.

**Evidence of impact:** Each LLM request:
1. `sorted()` iterates all entries — O(N log N)
2. `_re.escape()` on every password — O(N) with per-password O(L) overhead
3. `_re.compile()` on a multi-KB alternation string — Python regex compilation is not cheap
4. `pattern.sub(lambda m: repl[m.group(0)], text)` — correct but lambda dispatch per match

**Fix:** Cache the sorted items, compiled pattern, and repl dict inside `TokenMixin`. Invalid on mutation (`_register_secret`, `CMD_FORGET`).

```python
# In __init__:
self._redact_cache_version = 0
self._cached_pattern = None
self._cached_repl = {}

# In _redact:
if mapping is self.pwd_to_token:
    if self._redact_cache_version != self._mapping_version:
        items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
        self._cached_pattern = _re.compile("|".join(_re.escape(p) for p, _ in items))
        self._cached_repl = {p: t for p, t in items}
        self._redact_cache_version = self._mapping_version
    pattern, repl = self._cached_pattern, self._cached_repl
else:
    # Fallback for snapshot dicts
    items = sorted(...)
    pattern, repl = _re.compile(...), {...}
```

---

### 🔴 [HIGH] 2. Snapshots taken without lock — race condition between p2t and t2p

**File:** `_llm.py:46-47`

```python
snapshot_p2t = dict(self.pwd_to_token)
snapshot_t2p = dict(self.token_to_pwd)
```

**Problem:** `PLAN.md` claims "快照加锁保护", but the actual code takes both snapshots **outside** `async with self._lock:`. If `CMD_FORGET` or `_register_secret` runs concurrently between these two lines, `snapshot_p2t` and `snapshot_t2p` can be inconsistent:

| Time | Thread A (handler) | Thread B (CMD_FORGET) |
|------|-------------------|----------------------|
| T1   | `snapshot_p2t = dict(self.pwd_to_token)` → has "abc" | |
| T2   | | `self.pwd_to_token.clear()` + `self.token_to_pwd.clear()` |
| T3   | `snapshot_t2p = dict(self.token_to_pwd)` → **empty** | |

**Result:** `active_t2p` is empty, so upstream responses containing tokens won't get restored. User sees `__VG_CRED_000001__` in plaintext. Not a direct security leak (the plaintext secret stays hidden behind the token), but broken UX.

Can also happen with `_register_secret` between the two lines — token exists in `snapshot_t2p` but not `snapshot_p2t`, meaning the token is generated but its password wasn't redacted from the request.

**Fix:** Wrap both copies in the lock:

```python
async with self._lock:
    snapshot_p2t = dict(self.pwd_to_token)
    snapshot_t2p = dict(self.token_to_pwd)
```

(~2µs hold time, negligible contention.)

---

### 🟡 [MEDIUM] 3. `handle_credential` acquires lock 5-8 times per request — mergeable regions

**File:** `_credential.py:54-176`

**Happy-path lock acquisitions:**
1. Rate-limit check (L54) → release
2. Unlock status check (L74) → release
3. Set unlock msg_id (L103) → release *(conditional, first unlock only)*
4. Post-unlock: mp + pending request (L113) → release
5. Approval mapping set (L131) → release
6. Timeout edge-case check (L137) → release *(conditional, timeout only)*
7. Approval result + cleanup (L146) → release
8. KP cache read (L166) → release

**Issue:** Regions 1-2 are adjacent with no `await` between them:

```python
# L54-60 (region 1):
async with self._lock:
    now = time.monotonic()
    if now - self._last_credential_request < RATE_LIMIT_INTERVAL:
        return ...
    self._last_credential_request = now
# released

# L74-89 (region 2):
async with self._lock:
    if not self.master_password:
        ...
    unlock_evt = self.unlock_event
# released
```

These two can be merged into a single lock region. Similarly, after the approval `wait_for` (region 6 is conditional but region 7 always runs and could hold the lock just a bit longer to merge).

**Impact:** Each lock acquire/release is cheap (~1µs for uncontested `asyncio.Lock`), so 5-8 is not disastrous. But merging regions 1+2 and 7+8 reduces round-trips, which adds up under concurrent requests.

**Fix:** Merge regions 1-2:

```python
async with self._lock:
    now = time.monotonic()
    if now - self._last_credential_request < RATE_LIMIT_INTERVAL:
        return web.json_response(...)
    self._last_credential_request = now

    if not self.master_password:
        if not self.unlock_event:
            self.unlock_event = asyncio.Event()
            need_ask = True
        ...
    unlock_evt = self.unlock_event
```

---

### 🟡 [MEDIUM] 4. SSE stream discards partial lines on buffer overflow

**File:** `_llm.py:114-118`

```python
if len(byte_buf) > SSE_MAX_BUF:
    logger.warning("SSE 缓冲区超过 1MB 上限，丢弃残余数据")
    byte_buf = b""    # ⚠️ discards data
```

**Problem:** When the 1MB buffer is exceeded, the code sets `byte_buf = b""`, **silently discarding a partial SSE line**. If the upstream sends a "data:" line fragment in the discarded portion, that SSE event is lost downstream.

The `SSE_MAX_BUF = 1_048_576` threshold is generous (most SSE lines are <1KB), but when hit, losing data silently is worse than truncating. A line fragment that survives should be flushed to the client before clearing.

**Impact:** Under normal operation — very low. Under pathological upstream (e.g. streaming a 2MB base64-encoded image per SSE chunk) — data loss.

**Fix:** Instead of `byte_buf = b""`, flush the buffered data to the client before clearing, or use a sliding window:

```python
if len(byte_buf) > SSE_MAX_BUF:
    # Flush even incomplete data to client before discarding
    try:
        await resp.write(byte_buf)
    except SSE_CLIENT_GONE:
        pass
    byte_buf = b""
```

---

### 🟢 [LOW] 5. `_restore` uses O(N·M) `str.replace` loop — fine for active_t2p, wasteful for full mapping

**File:** `_token.py:73-74`

```python
for token, pwd in mapping.items():
    text = text.replace(token, pwd)
```

**Problem:** If `_restore` were ever called with the full `self.token_to_pwd` (max 5000 entries) on a large response body, this is O(N��M) — each token triggers a full scan-and-replace of the text. But in practice `_restore` is called with `active_t2p` (typically 1-20 tokens found in the request body), so the actual impact is negligible.

**Verdict:** Correct as-is. The `active_t2p` optimization (building a token subset per request in `_llm.py:52-58`) is the right strategy. No action needed.

---

### 🟢 [LOW] 6. `hasattr(entry, "get_custom_property")` in hot path — could be cached

**File:** `_credential.py:194,205`

```python
if val is None and hasattr(entry, "get_custom_property"):
    val = entry.get_custom_property(field)
```

**Problem:** `hasattr` is checked redundantly in the field lookup (L194) and custom_properties loop (L205). PyKeePass entries always have `get_custom_property` if they have `custom_properties`, so this is always True or always False per entry type. Could check once and reuse.

**Impact:** Negligible — `hasattr` is a fast attribute lookup. Only notable if the same entry is queried thousands of times.

---

### 🟢 [LOW] 7. `async with session.request()` — correct for both streaming and non-streaming

**File:** `_llm.py:68-71`

```python
async with session.request(
    request.method, target_url,
    headers=headers, data=out_body,
) as upstream_resp:
```

**Verdict: No issue.** The `async with` ensures proper connection lifecycle:
- **Non-streaming:** `upstream_resp.read()` consumes the full response, then context exit releases the connection. Correct.
- **SSE:** The context stays open for the stream duration (required for streaming). The upstream connection is released after the SSE loop ends. Correct.

One subtle concern: the **shared session** means one long-running SSE stream occupies a connection from the shared pool. If many SSE clients connect simultaneously, the pool may starve. Mitigation: increase `connector_limit` on `ClientSession`, or use per-proxy sessions for high-traffic deployments.

---

### 🟢 [LOW] 8. `OrderedDict` + `move_to_end` — correct for LRU, zero concern

**File:** `proxy.py:96`, `_token.py:36`

```python
self.pwd_to_token = OrderedDict()          # proxy.py:96
self.pwd_to_token.move_to_end(value)      # _token.py:36
```

**Verdict: No issue.** `OrderedDict.move_to_end()` is O(1). LRU eviction via `next(iter(...))` + `pop()` is O(1). The combination of `OrderedDict` for LRU + `re.sub` for replacement is correct and well-suited. No optimization needed.

---

## Summary Table

| # | Issue | Severity | Effort | Category |
|---|-------|----------|--------|----------|
| 1 | `_redact` re-compiles regex per request | 🔴 High | ~20 LoC | Performance |
| 2 | Snapshots without lock → inconsistent | 🔴 High | ~2 LoC | Correctness |
| 3 | Lock acquired 5-8× per request, can merge | 🟡 Medium | ~10 LoC | Latency |
| 4 | SSE buffer overflow discards data | 🟡 Medium | ~4 LoC | Reliability |
| 5 | `_restore` O(N·M) unused path | 🟢 Low | — | Cosmetic |
| 6 | `hasattr` repeated in hot path | 🟢 Low | ~2 LoC | Micro-opt |
| 7 | `async with session.request()` | ✅ None | — | — |
| 8 | OrderedDict LRU | ✅ None | — | — |

**Top recommendation:** Fix #1 (cache compiled regex) and #2 (lock snapshot) — ~22 lines of code, eliminates per-request O(N log N) sorting + O(N) compilation, and closes a correctness gap with non-trivial UX impact.
