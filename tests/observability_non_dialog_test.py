"""非对话请求排除单测（dashboard-filter-charts change 5.4）。

覆盖 observability-metrics 非对话口径：
- v1/models / v1/embeddings 等非 3 端点不调 incr_event
- is_chat_tail 的 rstrip('/') 边界（/v1/responses/ 判定为对话）
"""

from __future__ import annotations

from _llm import is_chat_tail


class TestIsChatTail:
    def test_chat_endpoints(self):
        assert is_chat_tail('v1/chat/completions') is True
        assert is_chat_tail('/v1/messages') is True
        assert is_chat_tail('/v1/responses') is True

    def test_non_chat_endpoints(self):
        assert is_chat_tail('/v1/models') is False
        assert is_chat_tail('/v1/embeddings') is False
        assert is_chat_tail('/health') is False
        assert is_chat_tail('') is False

    def test_rstrip_slash_boundary(self):
        # rstrip('/') 后仍判定对话
        assert is_chat_tail('/v1/responses/') is True
        assert is_chat_tail('/v1/chat/completions/') is True

    def test_one_level_custom_suffix(self):
        # Y-11：一层自定义后缀仍计对话（中转自定义路径）
        assert is_chat_tail('/v1/chat/completions/custom') is True
        assert is_chat_tail('/v1/chat/completions/custom/') is True
        assert is_chat_tail('/v1/messages/ext') is True
        assert is_chat_tail('/v1/responses/extra') is True

    def test_two_level_suffix_not_chat(self):
        # Y-11：两层及以上后缀不判对话（防误统计非对话端点）
        assert is_chat_tail('/v1/chat/completions/a/b') is False
        assert is_chat_tail('/v1/chat/completionsx') is False
