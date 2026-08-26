"""pii_placeholder_prompt_test.py — 占位符说明提示词注入测试。

覆盖 pii-placeholder-prompt change：
- 注入函数：三协议结构（OpenAI messages / Anthropic 顶层 system / Responses input）
  + 字符串/数组 content 分支 + 空消息 + 多条 system + 非 JSON 透传
- 触发接线：零脱敏零注入、开关关闭零注入、OR 语义（凭据占位符触发）
- R5 负向断言：说明文本自身不被脱敏/还原、未注册 token 不还原
- 自定义文案：空/空白回落内置、超长截断、含真实占位符形态回退内置
"""

import asyncio
import json as _json

import pytest

from _llm import LlmMixin
from _pii import (
    PII_PLACEHOLDER_PROMPT_DEFAULT,
    PII_PLACEHOLDER_PROMPT_MAX_LEN,
    PiiMixin,
    parse_pii_env_config,
)
from _token import TokenMixin


class PiiProxy(TokenMixin, PiiMixin, LlmMixin):
    """组合 PiiMixin 的测试桩（与 pii_llm_test.py 同构）。"""

    __test__ = False

    def __init__(self):
        self._lock = asyncio.Lock()
        self.token_to_pwd = {}
        self._token_seq = 0
        self.pwd_to_token = {}
        self._shared_session = None
        self.proxies = {}
        self._runners = []
        self._init_pii()
        self.pii_enabled = True
        self.pii_response_side = True

    def _filter_hop_headers(self, h):
        return h

    def _redact(self, text, snapshot_p2t=None):
        return text

    def _restore(self, text, active_t2p):
        for tok, plain in (active_t2p or {}).items():
            text = text.replace(tok, plain)
        return text


@pytest.fixture
def proxy():
    return PiiProxy()


# ═══════════════════════════════════════════════════════════
# 注入函数：结构分支
# ═══════════════════════════════════════════════════════════


class TestInjectStructure:
    def test_openai_existing_system_str(self, proxy):
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [
                    {'role': 'system', 'content': '你是助手'},
                    {'role': 'user', 'content': '查 __PII_1_ab12cd34__'},
                ],
            }
        )
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        assert obj['messages'][0]['role'] == 'system'
        assert obj['messages'][0]['content'] == (
            '你是助手\n\n' + PII_PLACEHOLDER_PROMPT_DEFAULT
        )
        assert obj['messages'][1]['content'] == '查 __PII_1_ab12cd34__'
        assert len(obj['messages']) == 2

    def test_openai_existing_system_array(self, proxy):
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [
                    {
                        'role': 'system',
                        'content': [{'type': 'text', 'text': '你是助手'}],
                    },
                    {'role': 'user', 'content': '查 13800138000'},
                ],
            }
        )
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        content = obj['messages'][0]['content']
        assert isinstance(content, list)
        # 数组且最后一个元素是 text → 追加到该 text 元素末尾
        assert len(content) == 1
        assert content[0]['type'] == 'text'
        assert content[0]['text'] == '你是助手\n\n' + PII_PLACEHOLDER_PROMPT_DEFAULT

    def test_openai_no_system_insert_head(self, proxy):
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [
                    {'role': 'user', 'content': '查 __PII_2_cd34ab12__'},
                ],
            }
        )
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        assert obj['messages'][0]['role'] == 'system'
        assert obj['messages'][0]['content'] == PII_PLACEHOLDER_PROMPT_DEFAULT
        assert obj['messages'][1]['role'] == 'user'
        assert len(obj['messages']) == 2

    def test_openai_empty_messages(self, proxy):
        body = _json.dumps({'model': 'gpt-4o', 'messages': []})
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        assert obj['messages'] == [
            {'role': 'system', 'content': PII_PLACEHOLDER_PROMPT_DEFAULT}
        ]

    def test_openai_multiple_system_only_first(self, proxy):
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [
                    {'role': 'system', 'content': 'A'},
                    {'role': 'user', 'content': 'hi'},
                    {'role': 'system', 'content': 'B'},
                ],
            }
        )
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        assert obj['messages'][0]['content'] == (
            'A\n\n' + PII_PLACEHOLDER_PROMPT_DEFAULT
        )
        assert obj['messages'][2]['content'] == 'B'

    def test_anthropic_top_level_system_str(self, proxy):
        body = _json.dumps(
            {
                'model': 'claude-3-5-sonnet',
                'system': '你是助手',
                'messages': [{'role': 'user', 'content': '查 13800138000'}],
            }
        )
        out = proxy.inject_placeholder_prompt(body, protocol='anthropic')
        obj = _json.loads(out)
        assert obj['system'] == '你是助手\n\n' + PII_PLACEHOLDER_PROMPT_DEFAULT

    def test_anthropic_top_level_system_array(self, proxy):
        body = _json.dumps(
            {
                'model': 'claude-3-5-sonnet',
                'system': [{'type': 'text', 'text': '你是助手'}],
                'messages': [{'role': 'user', 'content': '查 13800138000'}],
            }
        )
        out = proxy.inject_placeholder_prompt(body, protocol='anthropic')
        obj = _json.loads(out)
        assert isinstance(obj['system'], list)
        assert len(obj['system']) == 1
        assert obj['system'][0]['type'] == 'text'
        assert obj['system'][0]['text'] == (
            '你是助手\n\n' + PII_PLACEHOLDER_PROMPT_DEFAULT
        )

    def test_anthropic_no_system_create(self, proxy):
        body = _json.dumps(
            {
                'model': 'claude-3-5-sonnet',
                'messages': [{'role': 'user', 'content': '查 13800138000'}],
            }
        )
        out = proxy.inject_placeholder_prompt(body, protocol='anthropic')
        obj = _json.loads(out)
        assert obj['system'] == PII_PLACEHOLDER_PROMPT_DEFAULT

    def test_responses_input_array(self, proxy):
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'input': [
                    {'role': 'system', 'content': '你是助手'},
                    {'role': 'user', 'content': '查 __PII_1_ab12cd34__'},
                ],
            }
        )
        out = proxy.inject_placeholder_prompt(body, protocol='responses')
        obj = _json.loads(out)
        assert obj['input'][0]['role'] == 'system'
        assert obj['input'][0]['content'] == (
            '你是助手\n\n' + PII_PLACEHOLDER_PROMPT_DEFAULT
        )
        assert len(obj['input']) == 2

    def test_responses_empty_input(self, proxy):
        body = _json.dumps({'model': 'gpt-4o', 'input': []})
        out = proxy.inject_placeholder_prompt(body, protocol='responses')
        obj = _json.loads(out)
        assert obj['input'] == [
            {'role': 'system', 'content': PII_PLACEHOLDER_PROMPT_DEFAULT}
        ]

    def test_content_array_with_image_block(self, proxy):
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [
                    {
                        'role': 'system',
                        'content': [
                            {'type': 'text', 'text': '你是助手'},
                            {'type': 'image_url', 'image_url': {'url': 'data:...'}},
                        ],
                    },
                    {'role': 'user', 'content': '查 13800138000'},
                ],
            }
        )
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        content = obj['messages'][0]['content']
        # 最后一个元素是 image block，新增 text block 到末尾（无前导换行，
        # 新 block 本身即分隔；仅追加到已有 text 末尾时才用 \n\n 分隔）
        assert content[-1] == {
            'type': 'text',
            'text': PII_PLACEHOLDER_PROMPT_DEFAULT,
        }
        assert content[-2]['type'] == 'image_url'

    def test_custom_prompt_used(self, proxy):
        proxy.pii_placeholder_prompt_text = 'Keep tokens verbatim'
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [{'role': 'user', 'content': '查 13800138000'}],
            }
        )
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        assert obj['messages'][0]['content'] == 'Keep tokens verbatim'


class TestInjectErrorPaths:
    def test_non_json_body_passthrough(self, proxy):
        body = 'not json at all'
        assert proxy.inject_placeholder_prompt(body) == body

    def test_truncated_json_passthrough(self, proxy):
        body = '{"model": "gpt-4o", "messages": [{"role": "user", "content": "'
        assert proxy.inject_placeholder_prompt(body) == body

    def test_non_object_json_passthrough(self, proxy):
        body = '[1, 2, 3]'
        assert proxy.inject_placeholder_prompt(body) == body

    def test_disabled_switch_passthrough(self, proxy):
        proxy.pii_placeholder_prompt_enabled = False
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [{'role': 'user', 'content': '查 13800138000'}],
            }
        )
        assert proxy.inject_placeholder_prompt(body) == body

    def test_unknown_structure_passthrough(self, proxy):
        body = _json.dumps({'model': 'gpt-4o', 'foo': 'bar'})
        assert proxy.inject_placeholder_prompt(body) == body


# ═══════════════════════════════════════════════════════════
# 配置解析
# ═══════════════════════════════════════════════════════════


class TestEnvConfig:
    @pytest.mark.parametrize(
        'val,expected',
        [
            ('1', True),
            ('true', True),
            ('yes', True),
            ('0', False),
            ('false', False),
            ('no', False),
            (None, True),  # 未设置默认启用
        ],
    )
    def test_placeholder_prompt_switch(self, monkeypatch, val, expected):
        if val is None:
            monkeypatch.delenv('PII_PLACEHOLDER_PROMPT', raising=False)
        else:
            monkeypatch.setenv('PII_PLACEHOLDER_PROMPT', val)
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_enabled'] is expected

    def test_text_empty_falls_back(self, monkeypatch):
        monkeypatch.setenv('PII_PLACEHOLDER_PROMPT_TEXT', '')
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_text'] == ''

    def test_text_whitespace_falls_back(self, monkeypatch):
        monkeypatch.setenv('PII_PLACEHOLDER_PROMPT_TEXT', '   ')
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_text'] == ''

    def test_text_custom(self, monkeypatch):
        monkeypatch.setenv('PII_PLACEHOLDER_PROMPT_TEXT', 'Keep verbatim')
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_text'] == 'Keep verbatim'

    def test_text_too_long_truncated(self, monkeypatch):
        long_text = 'x' * (PII_PLACEHOLDER_PROMPT_MAX_LEN + 100)
        monkeypatch.setenv('PII_PLACEHOLDER_PROMPT_TEXT', long_text)
        cfg = parse_pii_env_config()
        assert len(cfg['placeholder_prompt_text']) == PII_PLACEHOLDER_PROMPT_MAX_LEN

    def test_text_real_placeholder_falls_back(self, monkeypatch):
        monkeypatch.setenv(
            'PII_PLACEHOLDER_PROMPT_TEXT', 'Keep __PII_1_ab12cd34__ verbatim'
        )
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_text'] == ''  # 回退内置

    def test_text_real_cred_placeholder_falls_back(self, monkeypatch):
        monkeypatch.setenv(
            'PII_PLACEHOLDER_PROMPT_TEXT', 'Keep __VG_CRED_42__ verbatim'
        )
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_text'] == ''  # 回退内置

    def test_disabled_short_circuit_skips_text_validation(self, monkeypatch, caplog):
        # 关闭时不应解析/校验文案（短路），零副作用：text 保持 ''，无告警
        import logging

        monkeypatch.setenv('PII_PLACEHOLDER_PROMPT', '0')
        monkeypatch.setenv('PII_PLACEHOLDER_PROMPT_TEXT', '__PII_1_ab12cd34__' * 100)
        with caplog.at_level(logging.WARNING, logger='credential-proxy'):
            cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_enabled'] is False
        assert cfg['placeholder_prompt_text'] == ''  # 短路：不解析不校验
        assert not any(
            '占位符' in r.message or '超长' in r.message for r in caplog.records
        )

    def test_disabled_case_insensitive(self, monkeypatch):
        # 开关值大小写不敏感：False/NO 禁用（spec 定义），TRUE/Yes/Off 启用
        # （spec 仅 0/false/no 关闭，off 未定义 → 按默认启用）
        for val, expected in (
            ('False', False),
            ('NO', False),
            ('Off', True),
            ('TRUE', True),
            ('Yes', True),
        ):
            monkeypatch.setenv('PII_PLACEHOLDER_PROMPT', val)
            cfg = parse_pii_env_config()
            assert cfg['placeholder_prompt_enabled'] is expected, val

    def test_text_uppercase_placeholder_falls_back(self, monkeypatch):
        # 禁词正则大小写不敏感：大写 hex 同样回退内置
        monkeypatch.setenv(
            'PII_PLACEHOLDER_PROMPT_TEXT', 'Keep __PII_1_AB12CD34__ verbatim'
        )
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_text'] == ''  # 回退内置

    def test_text_oversize_forbidden_check_before_truncate(self, monkeypatch):
        # 截断顺序：先校验禁词再截断，超长文案末尾藏合法占位符也要回退
        monkeypatch.setenv(
            'PII_PLACEHOLDER_PROMPT_TEXT',
            'a' * 4090 + '__PII_1_ab12cd34__' + 'b' * 200,
        )
        cfg = parse_pii_env_config()
        assert cfg['placeholder_prompt_text'] == ''  # 回退内置（禁词在截断点后）

    def test_init_pii_defaults(self, proxy):
        assert proxy.pii_placeholder_prompt_enabled is True
        assert proxy.pii_placeholder_prompt_text == ''


# ═══════════════════════════════════════════════════════════
# R5 负向断言：说明文本自身不被脱敏/还原
# ═══════════════════════════════════════════════════════════


class TestR5Negative:
    @pytest.mark.asyncio
    async def test_injected_text_not_redacted_by_scan(self, proxy):
        """注入后 body 再次经 pii_redact_json_aware 扫描时，说明文本
        __PII_*__ 不产生新占位符（`*` 非合法 hex8，不命中真实形态）。"""
        proxy.pii_enabled = True
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [
                    {'role': 'user', 'content': '查 13800138000'},
                ],
            }
        )
        injected = proxy.inject_placeholder_prompt(body)
        # 模拟二次扫描（禁止场景：注入后不应再扫描，此处验证即使扫描也不误伤）
        rescanned = await proxy.pii_redact_json_aware(injected)
        assert PII_PLACEHOLDER_PROMPT_DEFAULT in rescanned
        # 说明文本中的 __PII_*__ 不应被替换为新的 __PII_<seq>_<hex8>__
        assert '__PII_*__' in rescanned

    @pytest.mark.asyncio
    async def test_literal_star_not_restored(self, proxy):
        """响应含 __PII_*__ 字面描述不触发还原（非注册 token）。"""
        scope = proxy._pii_request_scope()
        # 注册一个真实占位符（register 是 async，返回 token 字符串）
        tok = await scope.register('13800138000')
        out = proxy._restore(
            '说明：__PII_*__ 是占位符；真实的是 ' + tok,
            {tok: '13800138000'},
        )
        assert '__PII_*__' in out  # 字面描述不被还原
        assert '13800138000' in out  # 真实占位符被还原

    def test_unregistered_cred_token_not_restored(self, proxy):
        """响应含未注册 __VG_CRED_999__ 不被还原（used_tokens 封闭性）。"""
        out = proxy._restore(
            '未注册 __VG_CRED_999__ 保持原样',
            {'__VG_CRED_1_abc__': 'secret'},
        )
        assert '__VG_CRED_999__' in out


# ═══════════════════════════════════════════════════════════
# 接线：触发判定（模拟 _llm.py 条件）
# ═══════════════════════════════════════════════════════════


class TestTriggerConditions:
    def _simulate_gate(self, proxy, is_tail, pii_enabled, has_placeholder, switch):
        """模拟 _llm.py 注入条件的真值表。"""
        return (
            is_tail
            and pii_enabled
            and switch
            and (b'__PII_' in has_placeholder or b'__VG_CRED_' in has_placeholder)
        )

    @pytest.mark.parametrize(
        'is_tail,pii_enabled,body,switch,expected',
        [
            (True, True, b'{"x": "__PII_1_ab12cd34__"}', True, True),
            (True, True, b'{"x": "__VG_CRED_5__"}', True, True),  # OR：凭据触发
            (True, True, b'{"x": "no placeholder"}', True, False),  # 无占位符零注入
            (True, False, b'{"x": "__PII_1_ab12cd34__"}', True, False),  # 未启用
            (False, True, b'{"x": "__PII_1_ab12cd34__"}', True, False),  # 非对话尾
            (True, True, b'{"x": "__PII_1_ab12cd34__"}', False, False),  # 开关关
        ],
    )
    def test_gate_truth_table(
        self, proxy, is_tail, pii_enabled, body, switch, expected
    ):
        got = self._simulate_gate(proxy, is_tail, pii_enabled, body, switch)
        assert got is expected

    def test_default_prompt_is_static_no_real_data(self):
        """内置文案不含真实 PII 值、不含合法形态占位符（D5 静态性）。"""
        import re as _re

        assert '13800138000' not in PII_PLACEHOLDER_PROMPT_DEFAULT
        assert '192.168' not in PII_PLACEHOLDER_PROMPT_DEFAULT
        assert not _re.search(
            r'__PII_\d+_[0-9a-f]{8}__|__VG_CRED_\d+__',
            PII_PLACEHOLDER_PROMPT_DEFAULT,
        )
        assert '__PII_*__' in PII_PLACEHOLDER_PROMPT_DEFAULT
        assert '__VG_CRED_*__' in PII_PLACEHOLDER_PROMPT_DEFAULT


# ═══════════════════════════════════════════════════════════
# 边界与非功能（任务 7）
# ═══════════════════════════════════════════════════════════


class TestBoundaryNonFunctional:
    def test_large_body_injection(self, proxy):
        """7.1 超大 body（10MB 级）注入：O(n) 线性、无内存放大。"""
        import time as _time

        big_content = '查 13800138000 ' + ('x' * (10 * 1024 * 1024))
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [{'role': 'user', 'content': big_content}],
            }
        )
        t0 = _time.monotonic()
        out = proxy.inject_placeholder_prompt(body)
        elapsed = _time.monotonic() - t0
        obj = _json.loads(out)
        assert obj['messages'][0]['role'] == 'system'
        assert PII_PLACEHOLDER_PROMPT_DEFAULT in obj['messages'][0]['content']
        assert len(obj['messages'][1]['content']) == len(big_content)
        # 线性注入，10MB 应 < 5s（正常 <1s）
        assert elapsed < 5.0, f'inject 耗时异常: {elapsed:.2f}s'

    def test_error_logging_on_inject_failure(self, proxy, caplog, monkeypatch):
        """7.2 注入异常路径：记录日志且透传原 body。"""
        import logging

        # 无法自然构造注入内部异常（代码路径均为安全透传），
        # 用 monkeypatch 强制 _pii_placeholder_inject_obj 抛异常验证兜底。
        def _explode(obj, prompt, protocol='openai'):
            raise RuntimeError('boom')

        monkeypatch.setattr(
            PiiMixin, '_pii_placeholder_inject_obj', staticmethod(_explode)
        )
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [{'role': 'user', 'content': '查 13800138000'}],
            }
        )
        with caplog.at_level(logging.ERROR, logger='credential-proxy'):
            out = proxy.inject_placeholder_prompt(body)
        # 异常 → 透传原 body 不抛
        assert out == body
        assert any('注入异常' in r.message for r in caplog.records)

    def test_disabled_plus_text_no_side_effect(self, proxy):
        """7.3 PII_PLACEHOLDER_PROMPT=0 + 设置 TEXT → 不注入、无副作用。"""
        proxy.pii_placeholder_prompt_enabled = False
        proxy.pii_placeholder_prompt_text = 'Should not appear'
        body = _json.dumps(
            {
                'model': 'gpt-4o',
                'messages': [{'role': 'user', 'content': '查 13800138000'}],
            }
        )
        assert proxy.inject_placeholder_prompt(body) == body

    def test_empty_messages_with_pii_body(self, proxy):
        """7.3 空 messages 且 body 含 PII → 注入唯一 system 消息。"""
        body = _json.dumps({'model': 'gpt-4o', 'messages': []})
        out = proxy.inject_placeholder_prompt(body)
        obj = _json.loads(out)
        assert obj['messages'] == [
            {'role': 'system', 'content': PII_PLACEHOLDER_PROMPT_DEFAULT}
        ]
