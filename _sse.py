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


def filter_hop_headers(headers: dict) -> dict:
    """过滤逐跳头，返回可安全透传的 headers。"""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_HEADERS}
