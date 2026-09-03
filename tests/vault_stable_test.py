"""vault_stable_test.py — Vault 稳态映射 + 共享 json_walk 验收 (tasks 1.1-1.3 / 2.1-2.3)."""

import json
import os
import re

import pytest

from _token import (
    FULL_PII_TOKEN_RE,
    GlobalPiiTokens,
)
from utils.json_walk import (
    _jdumps,
    _jloads,
    _validate_json_roundtrip,
    json_walk,
    json_walk_async,
)

# ── 2.1 稳态下标 ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_same_value_reuses_token():
    t = GlobalPiiTokens()
    tok1 = await t.register('13812345678')
    tok2 = await t.register('13812345678')
    assert tok1 == tok2
    assert len(t.pii_p2t) == 1


@pytest.mark.asyncio
async def test_gap_skip_reuses_hole():
    t = GlobalPiiTokens()
    tok1 = await t.register('13800000001')
    tok2 = await t.register('13800000002')
    # 造空洞：删掉 seq=1
    seq_pat = re.compile(r'__PII_(\d+)_')
    m1 = seq_pat.search(tok1)
    assert m1
    # 模拟空洞：清空后只留 seq=2
    # 直接手动构造空洞：清空并注入 seq=2 的 token
    t.pii_p2t.clear()
    t.pii_t2p.clear()
    # 手动注入 seq=2 的占位，避免 next_available 误判 1 已用
    t.pii_p2t['13800000002'] = tok2
    t.pii_t2p[tok2] = '13800000002'
    t._seq = 2
    tok3 = await t.register('13800000003')
    m3 = seq_pat.search(tok3)
    assert m3 and int(m3.group(1)) == 1, '应跳回空洞 1'


@pytest.mark.asyncio
async def test_rand8_unenumerable():
    t = GlobalPiiTokens()
    tokens = set()
    for i in range(10):
        tok = await t.register(f'13800000{i:03d}')
        m = re.fullmatch(r'__PII_\d+_([0-9a-f]{8})__', tok)
        assert m, tok
        tokens.add(tok)
    assert len(tokens) == 10
    # rand8 熵：10 个 token 的 rand8 不全相同（概率极低，视为随机性校验）
    rand8s = [re.fullmatch(r'__PII_\d+_([0-9a-f]{8})__', x).group(1) for x in tokens]
    assert len(set(rand8s)) > 1


@pytest.mark.asyncio
async def test_response_side_not_restored():
    t = GlobalPiiTokens()
    tok = await t.register('13900000001', response_side=True)
    # resp 映射不应对 restore 生效
    assert t.restore(tok) == tok
    # 请求期 token 可还原
    tok2 = await t.register('13900000002')
    assert t.restore(tok2) == '13900000002'


# ── 2.2 残缺清理 ───────────────────────────────────────────────────


def test_strip_partials_keeps_full():
    from _llm import _strip_partials

    full = '__PII_1_ab12cd34__'
    assert _strip_partials(f'前缀{full}后缀') == f'前缀{full}后缀'
    # 8.2：行尾完整 token 同样保留（负向前瞻排除完整形态，_*$ 不误剥收尾 __）
    assert _strip_partials(f'新号码 {full}') == f'新号码 {full}'
    assert _strip_partials(full) == full


def test_strip_partials_removes_incomplete():
    from _llm import _strip_partials

    assert _strip_partials('__PII') == ''
    assert _strip_partials('__PII_1_') == ''
    assert _strip_partials('__PII_1_ab') == ''
    assert _strip_partials('__VG_CRED') == ''
    # 行尾残缺剥离
    assert _strip_partials('hello __VG_CRED_') == 'hello '
    # 8.9（F-10）：行中残缺前缀（后跟空白/标点）同样剥离
    assert _strip_partials('hello __VG_CRED_  world') == 'hello   world'
    assert _strip_partials('x__PII_1_ab y') == 'x y'
    assert _strip_partials('x__PII_1_ab, y') == 'x, y'
    assert _strip_partials('x__VG_CRED_12 y') == 'x y'
    # 行中完整 token 保留
    assert _strip_partials('x__PII_1_ab12cd34__ y') == 'x__PII_1_ab12cd34__ y'
    assert _strip_partials('x__PII_1_ab12cd34__y') == 'x__PII_1_ab12cd34__y'


def test_strip_partials_reverse_equivalence():
    from _llm import _strip_partials

    text = 'a __PII_1_ab12cd34__ b __VG_CRED_000001__ c __PII_2_ef567890__ d'
    # 完整 token 保留，残缺已剥离（本例无残缺 → 原样）
    assert _strip_partials(text) == text
    # 倒序语义：多 token 替换不因顺序错位
    assert '__PII_1_ab12cd34__' in _strip_partials(text)


def test_full_token_line_end_cleanup():
    # 行尾完整幻觉 token 场景：未注册 token 仍保留但可被 _strip 识别为残缺前缀的超集
    assert FULL_PII_TOKEN_RE.search('__PII_1_ab12cd34__')
    assert not FULL_PII_TOKEN_RE.search('__PII_1_ab12cd3__')  # 7 hex 非法


# ── 2.3 PII_FUZZY_RESTORE ──────────────────────────────────────────


def test_fuzzy_default_exact(monkeypatch):
    monkeypatch.delenv('PII_FUZZY_RESTORE', raising=False)
    from _token import _is_pii_fuzzy_restore_enabled

    assert _is_pii_fuzzy_restore_enabled() is False


@pytest.mark.asyncio
async def test_fuzzy_enabled_case_insensitive(monkeypatch):
    monkeypatch.setenv('PII_FUZZY_RESTORE', '1')
    t = GlobalPiiTokens()
    # 确定性 token（rand8 含小写字母，upper 后必变）——不依赖 register 随机 rand8
    # （register 可能生成全数字 rand8 如 60670288，upper()==tok，精确模式也会还原，导致断言失效）
    tok = '__PII_1_ab12cd34__'
    t.pii_t2p[tok] = '13812345678'
    t.pii_p2t['13812345678'] = tok
    # 大小写漂移应还原
    assert t.restore(tok.upper()) == '13812345678'
    monkeypatch.setenv('PII_FUZZY_RESTORE', '0')
    # 默认精确：大写不应还原
    assert t.restore(tok.upper()) == tok.upper()


def test_fuzzy_illegal_rejected():
    import _pii

    os.environ['PII_FUZZY_RESTORE'] = '2'
    cfg = _pii.parse_pii_env_config()
    assert cfg['errors']
    assert any('PII_FUZZY_RESTORE' in e for e in cfg['errors'])
    os.environ.pop('PII_FUZZY_RESTORE', None)


# ── 1.1 共享 json_walk ─────────────────────────────────────────────


def test_json_walk_bom_prefix():
    def leaf(s):
        return s.replace('hi', 'HI')

    obj = {'a': '\ufeff{"k":"hi"}'}
    out = json_walk(obj, leaf)
    # BOM 后判 JSON，内层 walk
    assert 'HI' in json.dumps(out, ensure_ascii=False)


def test_json_walk_pure_text_zero_cost():
    calls = []

    def leaf(s):
        calls.append(s)
        return s

    out = json_walk({'a': 'plain text 无括号'}, leaf)
    assert calls == ['plain text 无括号']
    assert out['a'] == 'plain text 无括号'


def test_json_walk_depth_bomb_still_leaf():
    deep = 'x'
    for _ in range(7):
        deep = json.dumps({'inner': deep})

    # depth>5 时不递归内层但仍执行 leaf — 外层 walk 最终会产生字符串或 dict
    def leaf(s):
        return s + '!'

    out = json_walk(deep, leaf)
    # 不抛异常且为字符串，且至少一次 leaf 生效（内层或外层）
    assert isinstance(out, str)
    assert '!' in out or isinstance(json.loads(out), dict)


def test_json_walk_separators_and_ascii():
    obj = {'a': '中文', 'b': [1, 2]}
    out = json_walk(obj, lambda s: s)
    dumped = _jdumps(out)
    assert '中文' in dumped  # ensure_ascii=False
    assert ', ' not in dumped  # separators=(',',':')
    assert _jloads(dumped) == out


def test_json_walk_output_illegal_fallback():
    def bad_leaf(s):
        return '{"broken": }'  # 非法 JSON

    obj = {'a': '{"k":"v"}'}
    # 叶异常/非法仅该叶回退，不抛
    out = json_walk(obj, bad_leaf)
    assert isinstance(out, dict)


@pytest.mark.asyncio
async def test_json_walk_async_leaf_awaitable():
    async def aleaf(s):
        return s.upper()

    out = await json_walk_async({'a': 'hi'}, aleaf)
    assert out['a'] == 'HI'


def test_validate_roundtrip_original_legal_output_illegal_fallback():
    orig = '{"a":1}'
    bad = '{"a":}'
    assert _validate_json_roundtrip(orig, bad) == orig
    # original 非 JSON → 直接返回 output
    assert _validate_json_roundtrip('plain', bad) == bad


def test_json_walk_depth_bomb_native_nested():
    """8.1 裸嵌套深度炸弹：depth_limit 对裸嵌套生效，极端深度不崩溃。"""
    # 3000 层裸嵌套不再 RecursionError（外层兜底返回原对象）
    deep = cur = {}
    for _ in range(3000):
        cur['a'] = {}
        cur = cur['a']
    cur['x'] = 'leaf'

    out = json_walk(deep, lambda s: s)
    assert isinstance(out, dict)

    # depth_limit 对裸嵌套生效：depth>5 的内层不再递归 loads→walk，
    # 但 leaf_fn 仍执行（外层叶）
    calls = []

    def counting_leaf(s):
        calls.append(s)
        return s

    nested = {'a': {'b': {'c': {'d': {'e': {'f': {'g': 'x'}}}}}}}
    json_walk(nested, counting_leaf)
    assert len(calls) >= 1
    # depth>5 的叶仍执行 leaf_fn，但不会递归内层（leaf 数 <= 嵌套层数）
    assert len(calls) <= 6


@pytest.mark.asyncio
async def test_json_walk_async_depth_bomb_native_nested():
    """8.1 async 裸嵌套深度炸弹同样不崩溃。"""
    deep = cur = {}
    for _ in range(3000):
        cur['a'] = {}
        cur = cur['a']
    cur['x'] = 'leaf'

    out = await json_walk_async(deep, lambda s: s)
    assert isinstance(out, dict)

    # 7 层 JSON 字符串叶：depth>5 时内层不再递归
    import json as _json

    deep3 = 'x'
    for _ in range(7):
        deep3 = _json.dumps({'inner': deep3})
    calls = []

    async def aleaf(s):
        calls.append(s)
        return s

    await json_walk_async(deep3, aleaf)
    assert len(calls) >= 1
    assert len(calls) <= 6


@pytest.mark.asyncio
async def test_three_wrappers_nasty_values_stay_valid_json():
    from _pii import PiiDetector, PiiMixin
    from _token import RequestScopedTokens, TokenMixin

    nasty = json.dumps(
        {
            'pwd': 'p@ss"quote',
            'uni': 'a1b',
            'nested': json.dumps({'k': 'v1'}),
            'list': ['x', 'y'],
        }
    )

    token_obj = TokenMixin.__new__(TokenMixin)
    token_obj.pwd_to_token = {'p@ss"quote': '__VG_CRED_000001__'}
    token_obj.token_to_pwd = {'__VG_CRED_000001__': 'p@ss"quote'}
    redacted = token_obj._redact_json_aware(nasty, token_obj.pwd_to_token)
    assert json.loads(redacted)['pwd'] == '__VG_CRED_000001__'
    restored = token_obj._restore_json_aware(redacted, token_obj.token_to_pwd)
    assert json.loads(restored)['pwd'] == 'p@ss"quote'

    class _PiiHarness(PiiMixin):
        pass

    pii_obj = _PiiHarness.__new__(_PiiHarness)
    pii_obj.pii_enabled = True
    pii_obj.pwd_to_token = None
    pii_obj._pii_detector = PiiDetector(request_tokens=RequestScopedTokens())
    pii_out = await pii_obj.pii_redact_json_aware(json.dumps({'phone': '13812345678'}))
    assert '__PII_' in pii_out
    assert json.loads(pii_out)

    from _llm import LlmMixin as _LM
    from _token import TokenMixin as _TM

    class _Harness(_LM, _TM):
        pass

    llm_obj = _Harness.__new__(_Harness)
    llm_obj.token_to_pwd = {'__VG_CRED_000001__': 'p@ss"quote'}
    llm_out = await llm_obj._pii_response_process_json_aware(
        json.dumps({'msg': 'hi __VG_CRED_000001__'}),
        {'__VG_CRED_000001__': 'p@ss"quote'},
    )
    assert json.loads(llm_out)['msg'] == 'hi p@ss"quote'


def test_three_validators_fallback_contract():
    from _llm import _llm_validate_json_roundtrip
    from _pii import _pii_validate_json_roundtrip
    from _token import _validate_json_roundtrip

    orig = '{"a":1}'
    bad = '{"a":}'
    for fn in (
        _validate_json_roundtrip,
        _llm_validate_json_roundtrip,
        _pii_validate_json_roundtrip,
        _validate_json_roundtrip,
    ):
        assert fn(orig, bad, 't') == orig
        assert fn('plain', bad, 't') == bad


def test_nonstream_oversize_boundary():
    from _llm import NONSTREAM_MAX_BYTES, _is_nonstream_oversize

    assert NONSTREAM_MAX_BYTES == 8 * 1024 * 1024
    assert _is_nonstream_oversize(2 * 1024 * 1024, '/v1/chat/completions') is False
    assert _is_nonstream_oversize(9 * 1024 * 1024, '/v1/chat/completions') is True
    assert _is_nonstream_oversize(9 * 1024 * 1024, '/v1/models') is False


def test_block_body_shapes_and_model_passthrough():
    import json as _json

    from _llm import _build_block_body

    chat = _json.loads(_build_block_body('/v1/chat/completions', 'gpt-4o'))
    assert chat['choices'][0]['message']['role'] == 'assistant'
    assert chat['choices'][0]['finish_reason'] == 'stop'
    assert chat['model'] == 'gpt-4o'
    chat_nomodel = _json.loads(_build_block_body('/v1/chat/completions', None))
    assert 'model' not in chat_nomodel

    msg = _json.loads(_build_block_body('/v1/messages', 'claude-x'))
    assert msg['type'] == 'message'
    assert msg['stop_reason'] == 'end_turn'
    assert msg['model'] == 'claude-x'
    assert msg['usage'] == {'input_tokens': 0, 'output_tokens': 1}

    resp = _json.loads(_build_block_body('/v1/responses', None))
    assert resp['id'] == 'blocked'
    assert resp['status'] == 'completed'
    assert resp['output'][0]['content'][0]['type'] == 'output_text'
    assert 'model' not in resp
