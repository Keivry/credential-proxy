"""test_token.py — TokenMixin 单元测试。

覆盖: _make_token, _register_secret, _redact, _restore, 缓存版本管理, 边界。
"""
import asyncio
import pytest

from _token import (
    TokenMixin, _make_token,
    TOKEN_PREFIX, TOKEN_SUFFIX, MAX_TOKEN_ENTRIES, SECRET_MIN_LENGTH,
    TOKEN_RE, TOKEN_STR_RE,
)


# ═══════════════════════════════════════════════════════════
# 测试辅助: 最小化的 TokenMixin 实例
# ═══════════════════════════════════════════════════════════

class TestToken(TokenMixin):
    """最小实现：提供 TokenMixin 需要的 self 属性。"""

    def __init__(self):
        self._lock = asyncio.Lock()
        self.token_to_pwd = {}
        self._token_seq = 0
        self.pwd_to_token = type('FakeOD', (dict,), {
            'move_to_end': lambda self, k: None,
        })()


# ═══════════════════════════════════════════════════════════
# _make_token
# ═══════════════════════════════════════════════════════════

def test_make_token_format():
    assert _make_token(0) == "__VG_CRED_000000__"
    assert _make_token(1) == "__VG_CRED_000001__"
    assert _make_token(999999) == "__VG_CRED_999999__"


def test_make_token_large():
    assert _make_token(1234567) == "__VG_CRED_1234567__"


# ═══════════════════════════════════════════════════════════
# TOKEN_RE / TOKEN_STR_RE
# ═══════════════════════════════════════════════════════════

def test_token_re_matches():
    assert TOKEN_RE.match(b"__VG_CRED_000001__")
    assert TOKEN_RE.match(b"__VG_CRED_999999__")
    assert TOKEN_RE.match(b"__VG_CRED_1234567__")
    assert not TOKEN_RE.match(b"__VG_CRED_abc__")
    assert not TOKEN_RE.match(b"hello")


def test_token_str_re_fullmatch():
    assert TOKEN_STR_RE.fullmatch("__VG_CRED_000001__")
    assert not TOKEN_STR_RE.fullmatch("hello__VG_CRED_000001__")


# ═══════════════════════════════════════════════════════════
# _register_secret
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_register_secret_normal():
    t = TestToken()
    token = await t._register_secret("my_password")
    assert token.startswith("__VG_CRED_")
    assert token.endswith("__")
    assert t.pwd_to_token["my_password"] == token
    assert t.token_to_pwd[token] == "my_password"


@pytest.mark.asyncio
async def test_register_secret_short():
    t = TestToken()
    assert await t._register_secret("ab") == "ab"
    assert len(t.pwd_to_token) == 0


@pytest.mark.asyncio
async def test_register_secret_empty():
    t = TestToken()
    assert await t._register_secret("") == ""


@pytest.mark.asyncio
async def test_register_secret_duplicate():
    t = TestToken()
    t1 = await t._register_secret("dup" * 2)  # len >= 4
    t2 = await t._register_secret("dup" * 2)
    assert t1 == t2
    assert len(t.pwd_to_token) == 1


@pytest.mark.asyncio
async def test_register_secret_sequential():
    t = TestToken()
    t1 = await t._register_secret("a" * 10)
    t2 = await t._register_secret("b" * 10)
    assert t1 != t2
    assert t._token_seq == 2


@pytest.mark.asyncio
async def test_register_secret_rejects_token_format():
    t = TestToken()
    with pytest.raises(ValueError, match="token"):
        await t._register_secret("__VG_CRED_000001__")


@pytest.mark.asyncio
async def test_fifo_eviction():
    t = TestToken()
    n = MAX_TOKEN_ENTRIES + 10
    for i in range(n):
        await t._register_secret(f"pw_{i:06d}")
    assert len(t.pwd_to_token) == MAX_TOKEN_ENTRIES
    assert "pw_000000" not in t.pwd_to_token
    assert f"pw_{n-1:06d}" in t.pwd_to_token


# ═══════════════════════════════════════════════════════════
# _redact
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_redact_single():
    t = TestToken()
    token = await t._register_secret("hello")
    result = t._redact("say hello world")
    assert token in result
    assert "hello" not in result


@pytest.mark.asyncio
async def test_redact_multiple():
    t = TestToken()
    t1 = await t._register_secret("alphaa")  # len >= 4
    t2 = await t._register_secret("betaaa")
    result = t._redact("alphaa and betaaa")
    assert t1 in result
    assert t2 in result


@pytest.mark.asyncio
async def test_redact_substring_collision():
    """长密码先替换，防止短密码是长密码子串时泄漏。"""
    t = TestToken()
    await t._register_secret("hello")
    await t._register_secret("helloworld")
    result = t._redact("say helloworld")
    assert "helloworld" not in result
    assert "hello" not in result


@pytest.mark.asyncio
async def test_redact_empty_mapping():
    t = TestToken()
    assert t._redact("unchanged") == "unchanged"


@pytest.mark.asyncio
async def test_redact_empty_text():
    t = TestToken()
    await t._register_secret("pw12")  # len >= 4
    assert t._redact("") == ""


@pytest.mark.asyncio
async def test_redact_no_match():
    t = TestToken()
    await t._register_secret("secrets")
    assert t._redact("clean text") == "clean text"


@pytest.mark.asyncio
async def test_redact_special_chars():
    t = TestToken()
    await t._register_secret("a+b*c[d]e(f)")
    result = t._redact("prefix a+b*c[d]e(f) suffix")
    assert "a+b" not in result


# ═══════════════════════════════════════════════════════════
# _restore
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_restore_single():
    t = TestToken()
    _ = await t._register_secret("my_pwd")
    redacted = t._redact("use my_pwd here")
    restored = t._restore(redacted)
    assert restored == "use my_pwd here"


@pytest.mark.asyncio
async def test_restore_empty_mapping():
    t = TestToken()
    assert t._restore("__VG_CRED_000001__") == "__VG_CRED_000001__"


@pytest.mark.asyncio
async def test_restore_explicit_mapping():
    t = TestToken()
    explicit = {"__TOK__": "original"}
    result = t._restore("use __TOK__", token_to_pwd=explicit)
    assert result == "use original"


@pytest.mark.asyncio
async def test_roundtrip():
    t = TestToken()
    for pw in ["alphaX", "betaaX", "gammaX"]:
        await t._register_secret(pw)
    original = "alphaX meets betaaX, gammaX waves"
    redacted = t._redact(original)
    restored = t._restore(redacted)
    assert restored == original


# ═══════════════════════════════════════════════════════════
# _redact 缓存
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_redact_cache_initialized():
    t = TestToken()
    await t._register_secret("hello")
    assert not hasattr(t, '_redact_cache_ver')
    t._redact("hello")
    assert hasattr(t, '_redact_cache_ver')


@pytest.mark.asyncio
async def test_redact_cache_rebuild():
    t = TestToken()
    await t._register_secret("pw1_x")
    t._redact("pw1_x")
    ver1 = t._redact_cache_ver
    await t._register_secret("pw2_x")
    t._redact("pw2_x")
    assert t._redact_cache_ver > ver1


@pytest.mark.asyncio
async def test_redact_cache_hit():
    t = TestToken()
    await t._register_secret("pw1_x")
    await t._register_secret("pw2_x")
    t._redact("pw1_x pw2_x")
    ver = t._redact_cache_ver
    t._redact("pw1_x again")
    assert t._redact_cache_ver == ver


# ═══════════════════════════════════════════════════════════
# _maybe_register
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_maybe_register_enabled():
    t = TestToken()
    result = await t._maybe_register("secret", use_token=True)
    assert result != "secret"
    assert result in t.token_to_pwd


@pytest.mark.asyncio
async def test_maybe_register_disabled():
    t = TestToken()
    result = await t._maybe_register("plaintxt", use_token=False)
    assert result == "plaintxt"
    assert "plaintxt" not in t.pwd_to_token
