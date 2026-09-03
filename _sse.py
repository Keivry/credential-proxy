"""SSE 流处理共享常量 — 不依赖 nio 等 Matrix 包。

与 _matrix.py 中的定义保持一致，供 _llm.py 在不加载 Matrix 模块时使用。
"""

import asyncio

from aiohttp.client_exceptions import ClientConnectionResetError

# SSE 客户端断连异常元组（所有路径中都捕获同一组异常）
SSE_CLIENT_GONE = (
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    asyncio.TimeoutError,
    ClientConnectionResetError,
)

# 透传时需剥离的逐跳头
HOP_HEADERS = frozenset(
    {
        'host',
        'transfer-encoding',
        'content-length',
        'content-encoding',
        'connection',
        'keep-alive',
        'te',
    }
)

# WHATWG 三层缓冲阈值（与 README 流式阈值声明一致，_llm.py 复用此处唯一源）
SSE_MAX_BUF = 1_048_576
LINE_BUF_FLUSH = 16384
LINE_BUF_MAX_AGE = 30
KEEPALIVE_INTERVAL = 10

# Matrix reaction 常量（与 _matrix.py 保持一致，供 _credential.py 在不引入 nio 时使用）
REACTION_APPROVE = '\u2705'
REACTION_REJECT = '\u274e'
REACTION_AUTO_UNLOCK = '\U0001f513'
REACTIONS = (REACTION_APPROVE, REACTION_REJECT)
ALL_REACTIONS = (REACTION_APPROVE, REACTION_REJECT, REACTION_AUTO_UNLOCK)


def filter_hop_headers(headers: dict) -> dict:
    """过滤逐跳头，返回可安全透传的 headers。"""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_HEADERS}
