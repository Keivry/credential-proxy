"""pii_concurrency_test.py — 并发隔离回归（tasks 2.3）

验证 D2 要求的 ContextVar 隔离：两协程并发 pii_redact + audit_hold 悬挂互不串扰。
"""

import asyncio

import pytest

from _pii import PiiMixin


class DummyProxy(PiiMixin):
    def __init__(self):
        self._init_pii()
        self.pii_enabled = True


@pytest.mark.asyncio
async def test_concurrency_pii_register_isolation():
    """两协程并发 register 不同值，返回不同 token 且全局 seq 递增不丢号。"""
    proxy = DummyProxy()
    # 清空全局以保证起点
    scope = proxy._pii_request_scope()
    scope.clear()
    # 并发 10 个不同 PII
    values = [f'13800138{i:03d}' for i in range(10)] + [
        f'user{i}@example.com' for i in range(10)
    ]

    async def register_one(v):
        return await scope.register(v)

    results = await asyncio.gather(*(register_one(v) for v in values))
    # 20 个 token 互不相同
    assert len(set(results)) == 20
    # 每个值都能通过 pii_p2t / resp_p2p 找到（视类型分表）
    for v, tok in zip(values, results):
        # 手机号走 pii 表，邮箱走 pii 表（都是请求期）
        assert tok in scope.pii_t2p or tok in scope.resp_t2p
    # seq 全局递增 20
    assert scope._seq == 20
    scope.clear()


@pytest.mark.asyncio
async def test_concurrency_pii_register_duplicate_reuse():
    """同一值并发 register 命中复用，返回同一 token。"""
    proxy = DummyProxy()
    scope = proxy._pii_request_scope()
    scope.clear()

    async def register_same():
        return await scope.register('13812345678')

    results = await asyncio.gather(*(register_same() for _ in range(10)))
    assert len(set(results)) == 1
    assert scope._seq == 1
    scope.clear()


@pytest.mark.asyncio
async def test_concurrency_contextvar_audit_hold_isolation():
    """两请求并发进入 audit_hold，ContextVar 隔离互不覆盖。"""
    from _llm import LlmMixin
    from _audit import AuditMixin

    class HoldProxy(PiiMixin, LlmMixin, AuditMixin):
        def __init__(self):
            import asyncio

            self._lock = asyncio.Lock()
            self.token_to_pwd = {}
            self._token_seq = 0
            self.pwd_to_token = {}
            self._init_pii()
            self.pii_enabled = False
            # AuditMixin 初始化
            self._audit_approval_pending = {}
            self._audit_approval_msgs = {}
            self._audit_pending_seq = 0
            self._audit_log_ring = []
            self._audit_log_ring_max = 100
            self.audit_log_path = ''
            self._audit_hold_active = False
            self._audit_hold_buf = []
            self._audit_hold_bytes = 0
            self._audit_arg_accum = ''

    # 模拟两并发 handler 任务，各自设置 ContextVar

    from _llm import _audit_hold_active_var, _audit_hold_buf_var, _audit_arg_accum_var

    async def task_a():
        # 模拟 handler A 进入 hold
        tok_a = _audit_hold_active_var.set(True)
        buf_a = _audit_hold_buf_var.set(['event_a'])
        acc_a = _audit_arg_accum_var.set('{"cmd":"rm -rf /"}')
        await asyncio.sleep(0.05)
        # 检查自己的 ContextVar 未被 B 覆盖
        assert _audit_hold_active_var.get() is True
        assert _audit_hold_buf_var.get() == ['event_a']
        assert _audit_arg_accum_var.get() == '{"cmd":"rm -rf /"}'
        _audit_hold_active_var.reset(tok_a)
        _audit_hold_buf_var.reset(buf_a)
        _audit_arg_accum_var.reset(acc_a)

    async def task_b():
        await asyncio.sleep(0.01)
        tok_b = _audit_hold_active_var.set(False)
        buf_b = _audit_hold_buf_var.set(['event_b'])
        acc_b = _audit_arg_accum_var.set('{"cmd":"echo safe"}')
        await asyncio.sleep(0.05)
        assert _audit_hold_active_var.get() is False
        assert _audit_hold_buf_var.get() == ['event_b']
        assert _audit_arg_accum_var.get() == '{"cmd":"echo safe"}'
        _audit_hold_active_var.reset(tok_b)
        _audit_hold_buf_var.reset(buf_b)
        _audit_arg_accum_var.reset(acc_b)

    await asyncio.gather(task_a(), task_b())
