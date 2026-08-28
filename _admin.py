"""Admin API（llm-observability-dashboard change）。

- `/_admin/metrics?range=1h|24h|7d|30d` / `events?limit&kind&upstream&verdict` /
  `events/stream` SSE / `health` — 全部只读 GET
- 鉴权三选一严格优先级：`X-Admin-Token` 头 > `Cookie: __Host-admin_token`
  > `?access_token`（仅 SSE 回退）
- `OBSERVABILITY_ADMIN_TOKEN` 必填（未设 SystemExit），`hmac.compare_digest`
  时序安全比较，与其它 Token 独立（空值短路交叉检查）
- 管理接口 `10/min/IP` 限流 + SSE `5/IP` + `60s :ping` + `5min` 强制断开
- `trust_proxy_headers=false` 不读代理头；`_is_loopback` 精确回环判定
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import time as _time
from collections import deque

from aiohttp import web

logger = logging.getLogger('credential-proxy.admin')

_ADMIN_PATH_PREFIX = '/_admin/'

# 响应头（API 侧 no-store；静态 admin.html 单独 public+ETag）
_NO_STORE_HEADERS = {
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}

# 管理接口限流：10/min/IP
_RATE_LIMIT_MIN = 10
_RATE_WINDOW_S = 60
# SSE 限流：5 concurrent/IP + 60s ping + 5min 强制断开
_SSE_MAX_CONCURRENT = 5
_SSE_PING_S = 60
_SSE_MAX_S = 300


def validate_observability_token() -> None:
    """启动校验：OBSERVABILITY_ADMIN_TOKEN 必填（未设/空值 SystemExit）。

    与 CREDENTIAL_ADMIN_TOKEN / MATRIX_ACCESS_TOKEN / DATA_DIR/admin_token
    文件值任一相等（空值短路）→ SystemExit。
    OBSERVABILITY_DISABLE=1 时跳过（过渡逃生开关）。
    """
    if os.environ.get('OBSERVABILITY_DISABLE') == '1':
        return
    tok = os.environ.get('OBSERVABILITY_ADMIN_TOKEN', '')
    if not tok:
        logger.critical(
            'OBSERVABILITY_ADMIN_TOKEN 未设置（/_admin 大盘需要），拒绝启动。'
            '设置后重启，或 OBSERVABILITY_DISABLE=1 显式禁用。'
        )
        raise SystemExit('OBSERVABILITY_ADMIN_TOKEN 未设置')
    if len(tok) < 32:
        logger.warning('OBSERVABILITY_ADMIN_TOKEN 长度 <32，建议 ≥32 字符')
    # 交叉检查：与其它 Token 独立（空值短路）
    others = [
        os.environ.get('CREDENTIAL_ADMIN_TOKEN', ''),
        os.environ.get('MATRIX_ACCESS_TOKEN', ''),
    ]
    # DATA_DIR/admin_token 文件值
    data_dir = os.environ.get('DATA_DIR', '')
    if data_dir:
        try:
            with open(os.path.join(data_dir, 'admin_token'), 'r') as f:
                others.append(f.read().strip())
        except OSError:
            pass
    for other in others:
        if other and hmac.compare_digest(
            hashlib.sha256(tok.encode()).hexdigest(),
            hashlib.sha256(other.encode()).hexdigest(),
        ):
            logger.critical(
                'OBSERVABILITY_ADMIN_TOKEN 与其它 Token 相同，拒绝启动（须独立）'
            )
            raise SystemExit('OBSERVABILITY_ADMIN_TOKEN 与其他 Token 相同')


def _obs_token() -> str:
    return os.environ.get('OBSERVABILITY_ADMIN_TOKEN', '')


def _unauthorized() -> web.Response:
    """401 body 固定 `{"error":"unauthorized"}`，不含任何指标。"""
    resp = web.Response(
        body=json.dumps({'error': 'unauthorized'}, ensure_ascii=False).encode('utf-8'),
        status=401,
        content_type='application/json',
        charset='utf-8',
    )
    for k, v in _NO_STORE_HEADERS.items():
        resp.headers[k] = v
    return resp


def _too_many(retry_after: int) -> web.Response:
    resp = web.Response(
        body=json.dumps({'error': 'rate_limited'}, ensure_ascii=False).encode('utf-8'),
        status=429,
        content_type='application/json',
        charset='utf-8',
    )
    resp.headers['Retry-After'] = str(retry_after)
    for k, v in _NO_STORE_HEADERS.items():
        resp.headers[k] = v
    return resp


def _method_not_allowed() -> web.Response:
    resp = web.Response(
        body=json.dumps({'error': 'method_not_allowed'}, ensure_ascii=False).encode(
            'utf-8'
        ),
        status=405,
        content_type='application/json',
        charset='utf-8',
    )
    resp.headers['Allow'] = 'GET'
    for k, v in _NO_STORE_HEADERS.items():
        resp.headers[k] = v
    return resp


def _is_loopback(remote: str) -> bool:
    """精确回环判定：127.0.0.0/8 | ::1 | ::ffff:127.0.0.1。

    用 ipaddress.ip_address 精确判定（显式 ipv4_mapped 转换，不自动归一），
    不复用 _credential.py 的 172 网段过宽前缀。
    """
    try:
        ip = ipaddress.ip_address(remote)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


class _RateLimiter:
    """滑动窗口限流（10/min/IP）。on_disconnect 清理计数器防泄漏。"""

    def __init__(self, limit: int = _RATE_LIMIT_MIN, window_s: int = _RATE_WINDOW_S):
        self.limit = limit
        self.window_s = window_s
        self._hits: dict[str, list[float]] = {}
        self._calls = 0

    def allow(self, key: str) -> tuple[bool, int]:
        now = _time.time()
        # 惰性清扫：每 1000 次调用清一次过期 key，防 IP 轮转/扫描器撑爆字典（防御性）
        self._calls += 1
        if self._calls % 1000 == 0:
            cutoff = now - self.window_s
            for k in [k for k, v in self._hits.items() if not v or v[-1] < cutoff]:
                self._hits.pop(k, None)
        had = key in self._hits
        lst = [t for t in self._hits.get(key, []) if now - t < self.window_s]
        if had and not lst:
            # 已有 key 但窗口内无记录 → 清空防残留 + 首请求计数（防每分钟多放 1 个）
            self._hits.pop(key, None)
            lst = [now]
            self._hits[key] = lst
            return True, 0
        if len(lst) >= self.limit:
            retry = int(self.window_s - (now - lst[0])) + 1
            self._hits[key] = lst
            return False, max(retry, 1)
        lst.append(now)
        self._hits[key] = lst
        return True, 0

    def cleanup(self, key: str) -> None:
        self._hits.pop(key, None)


class _SseRegistry:
    """SSE 并发限流（5/IP）。on_disconnect 清理。"""

    def __init__(self, max_concurrent: int = _SSE_MAX_CONCURRENT):
        self.max_concurrent = max_concurrent
        self._conns: dict[str, int] = {}

    def try_acquire(self, key: str) -> bool:
        cur = self._conns.get(key, 0)
        if cur >= self.max_concurrent:
            return False
        self._conns[key] = cur + 1
        return True

    def release(self, key: str) -> None:
        cur = self._conns.get(key, 0)
        if cur <= 1:
            self._conns.pop(key, None)
        else:
            self._conns[key] = cur - 1


def init_observability(app: web.Application, collector) -> None:
    """挂载 /_admin/* 路由到 aiohttp app（多 runner 共享同一 collector 单例）。

    - 在通配 `*` 路由之前调用（先注册长路由，aiohttp 按注册顺序匹配）
    - `/_admin/` 静态壳免鉴权（本身无数据，Cache-Control: public 佐证）
    - `/_admin/metrics|events|events/stream|health` 全量鉴权
    - 首版不注册 `metrics/prometheus`（404）
    """
    from pathlib import Path

    admin_html_path = Path(__file__).parent / 'admin.html'
    admin_html_bytes = None
    if admin_html_path.exists():
        admin_html_bytes = admin_html_path.read_bytes()
    html_etag = None
    if admin_html_bytes is not None:
        import hashlib as _hl

        html_etag = f'"{_hl.md5(admin_html_bytes).hexdigest()[:16]}"'

    rate = _RateLimiter()
    sse_reg = _SseRegistry()

    async def _admin_handler(
        request: web.Request,
    ) -> web.Response | web.StreamResponse:
        """统一 /_admin/* 处理（GET 只读 + 鉴权）。"""
        method = request.method
        path = request.path

        # 静态壳（无数据）免鉴权
        if path == '/_admin/' or path == '/_admin':
            if method != 'GET':
                return _method_not_allowed()
            if admin_html_bytes is not None:
                resp = web.Response(
                    body=admin_html_bytes,
                    status=200,
                    content_type='text/html',
                    charset='utf-8',
                )
                resp.headers['Cache-Control'] = 'public, max-age=3600'
                if html_etag:
                    resp.headers['ETag'] = html_etag
                return resp
            return web.Response(
                body=b'admin dashboard unavailable',
                status=404,
                content_type='text/plain',
            )

        # 非 /_admin/* 放行（本 handler 只处理 /_admin 前缀，其它由通配处理）
        if not path.startswith(_ADMIN_PATH_PREFIX):
            return web.Response(status=404)

        # 401 优先于 405：未鉴权直接 401 不触 DB（含 POST 无 token）
        # 管理接口 10/min/IP 限流（IP 维度，鉴权前计数——防坏 token 爆破）
        # 空/None remote 归一为 'unknown' 单列桶，防全局坍缩
        remote = request.remote or 'unknown'
        if path != '/_admin/events/stream':
            ok, retry = rate.allow(remote)
            if not ok:
                return _too_many(retry_after=retry)
        # ④ 回环免 token（仅 ENV==dev && ALLOW_LOOPBACK_NO_TOKEN==1 && GET）
        # spec：Docker/反代下回环不可靠，仅 dev 调试时精确回环放行 + warning
        tok = ''
        if (
            os.environ.get('ENV', 'prod') == 'dev'
            and os.environ.get('ALLOW_LOOPBACK_NO_TOKEN') == '1'
            and method == 'GET'
            and _is_loopback(remote)
        ):
            logger.warning('回环免 token 放行（dev 调试）: remote=%s', remote)
        else:
            # ① 非 SSE 带 ?access_token 恒 401（不评估 header/cookie）
            q = request.query.get('access_token', '')
            if q and path != '/_admin/events/stream':
                return _unauthorized()
            # ② 三路凭证：header > cookie > query（query 仅 SSE）
            tok = request.headers.get('X-Admin-Token', '')
            if not tok:
                tok = _cookie_token(request)
            if not tok and path == '/_admin/events/stream':
                tok = q
            if not tok:
                return _unauthorized()
            # ③ 时序安全比较（等长 sha256 摘要）
            expected = _obs_token()
            if not expected or not hmac.compare_digest(
                hashlib.sha256(tok.encode('utf-8')).hexdigest(),
                hashlib.sha256(expected.encode('utf-8')).hexdigest(),
            ):
                return _unauthorized()

        # ⑤ 鉴权通过后：非法方法 405
        if method != 'GET':
            return _method_not_allowed()

        # ⑥ 凭证来自 header（非 cookie）时签发登录 Cookie（HttpOnly/SameSite=Strict）
        # 仅非 SSE 路径签发——SSE 保持 header/query，避免每帧 Set-Cookie
        # tok 非空才签（回环免 token 放行时 tok='' 不签空 Cookie）
        cookie_src = (
            'header' if (request.headers.get('X-Admin-Token', '') and tok) else ''
        )
        set_cookie = ''
        if cookie_src and path != '/_admin/events/stream':
            # tok 收紧为 RFC6265 cookie-octet 安全子集（排除 ; , = 空格等分隔符，
            # 防 Set-Cookie 属性注入；比前轮的 [^\x21-\x7E] 更严）
            cookie_val = re.sub(r'[^A-Za-z0-9._~+/=-]', '', tok)
            # __Host- 前缀要求 Secure + Path=/（且仅 HTTPS 可用）；回退 admin_token 兼容 http
            scheme = request.scheme
            if scheme == 'https':
                set_cookie = (
                    '__Host-admin_token='
                    + cookie_val
                    + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600'
                )
            else:
                # http 下 SameSite=Strict 防 CSRF（顶级 GET 不再携带）
                set_cookie = (
                    'admin_token='
                    + cookie_val
                    + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600'
                )

        # ⑦ 管理接口 10/min/IP 限流（已在鉴权前计数；此处仅 SSE 并发限流）
        if path == '/_admin/events/stream':
            if not sse_reg.try_acquire(remote):
                return _too_many(retry_after=60)
            try:
                return await _handle_sse(request, collector)
            finally:
                sse_reg.release(remote)
        else:
            if path == '/_admin/metrics':
                resp = _handle_metrics(request, collector)
            elif path == '/_admin/events':
                resp = _handle_events(request, collector)
            elif path == '/_admin/health':
                resp = _handle_health(request, collector)
            else:
                # 其余（含 metrics/prometheus）404
                return web.Response(status=404)
            if cookie_src:
                resp.headers['Set-Cookie'] = set_cookie
            return resp

    app.router.add_route('*', '/_admin/{tail:.*}', _admin_handler)
    app.router.add_route('*', '/_admin', _admin_handler)


def _cookie_token(request: web.Request) -> str:
    """从 Cookie 提取 admin token（__Host-admin_token 优先，回退 admin_token）。"""
    cookies = request.cookies
    for name in ('__Host-admin_token', 'admin_token'):
        v = cookies.get(name, '')
        if v:
            return v
    return ''


def _handle_metrics(request: web.Request, collector) -> web.Response:
    """GET /_admin/metrics?range=1h|24h|7d|30d。"""
    range_ = request.query.get('range', '1h')
    if range_ not in ('1h', '24h', '7d', '30d'):
        range_ = '1h'
    model_filter = request.query.get('model') or None
    try:
        data = collector.query_range(range_, model_filter=model_filter)
    except Exception as e:  # pragma: no cover — 防御
        logger.warning('metrics 查询异常: %s', e)
        data = {'error': 'metrics_unavailable', 'range': range_}
    resp = web.json_response(data, dumps=json.dumps)
    for k, v in _NO_STORE_HEADERS.items():
        resp.headers[k] = v
    return resp


def _handle_events(request: web.Request, collector) -> web.Response:
    """GET /_admin/events?limit&kind&upstream&verdict。"""
    try:
        limit = int(request.query.get('limit', '50'))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))
    kind = request.query.get('kind') or None
    upstream = request.query.get('upstream') or None
    verdict = request.query.get('verdict') or None
    if verdict not in (None, 'allow', 'deny'):
        verdict = None
    events = collector.events(
        limit=limit, kind=kind, upstream=upstream, verdict=verdict
    )
    resp = web.json_response({'events': events}, dumps=json.dumps)
    for k, v in _NO_STORE_HEADERS.items():
        resp.headers[k] = v
    return resp


def _handle_health(request: web.Request, collector) -> web.Response:
    """GET /_admin/health。"""
    try:
        data = collector.health()
    except Exception as e:  # pragma: no cover — 防御
        logger.warning('health 查询异常: %s', e)
        data = {'error': 'health_unavailable'}
    resp = web.json_response(data, dumps=json.dumps)
    for k, v in _NO_STORE_HEADERS.items():
        resp.headers[k] = v
    return resp


async def _handle_sse(request: web.Request, collector) -> web.StreamResponse:
    """GET /_admin/events/stream — SSE 实时推送。

    - 60s :ping 心跳 + 5min 服务端 retry 强制断开
    - 新事件推送到前端表首（2 秒内可见）
    """
    resp = web.StreamResponse(
        status=200,
        headers={
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        },
    )
    await resp.prepare(request)
    last_push_ts = _time.time()
    last_ping_ts = _time.time()
    start = _time.time()
    # 已推送事件去重游标：同秒多请求（同 ts）也能全部推送，防 `> last_ts` 丢同 ts 事件
    sent_ids: deque[str] = deque(maxlen=2000)
    try:
        while True:
            # 推送新事件（自上次推送以来，按 request_id 去重）
            # 取数窗口 200：2s 轮询间隔内 QPS≤100 不丢（50 在 >25 rps 时截断丢事件）
            evs = collector.events(limit=200)
            new_evs = [
                e
                for e in evs
                if e.get('ts', 0) >= last_push_ts
                and e.get('request_id', '') not in sent_ids
            ]
            for e in reversed(new_evs):
                _rid = e.get('request_id', '')
                if _rid:
                    sent_ids.append(_rid)
                await resp.write(
                    f'event: event\ndata: {json.dumps(e, ensure_ascii=False)}\n\n'.encode()
                )
            if new_evs:
                last_push_ts = max(e.get('ts', 0) for e in new_evs)
            # 5min 强制断开
            if _time.time() - start >= _SSE_MAX_S:
                await resp.write(b'event: done\ndata: {}\n\n')
                await resp.write_eof()
                return resp
            await asyncio.sleep(2)
            # 60s ping（独立游标，不重置 last_push_ts 防漏推）
            if _time.time() - last_ping_ts >= _SSE_PING_S:
                await resp.write(b': ping\n\n')
                last_ping_ts = _time.time()
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    except Exception:
        logger.debug('SSE 流异常', exc_info=True)
    try:
        await resp.write_eof()
    except Exception:
        pass
    return resp
