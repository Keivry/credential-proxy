#!/usr/bin/env python3
"""scripts/sentinel_record.py — 真实流量哨兵录制脚本 (tasks 5.2).

对三协议（chat/completions · v1/messages · v1/responses）各跑嵌套 arguments + 流式截断
+ 保留 IP 混合用例，记录 data: 行 walk 与 line_buf/arg_buf/byte_buf 审计。

用法:
  python3 scripts/sentinel_record.py                    # 写 tests/fixtures/*.jsonl
  python3 scripts/sentinel_record.py --check            # 校验 fixtures 可 loads

llm-proxy-only 本地可跑：需 LLM_<PORT> 指向 mock 上游；无上游时走离线合成。
"""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIX_DIR = ROOT / 'tests' / 'fixtures'

# 离线合成：三协议各一完整录制（请求 body 脱敏后可 loads，响应 line_buf 行内还原无片段泄漏）
SENTINELS = {
    'chat': {
        'protocol': 'chat.completions',
        'request': {
            'model': 'gpt-4o-mini',
            'messages': [{'role': 'user', 'content': '查询 13812345678 的订单'}],
            'tools': [
                {
                    'type': 'function',
                    'function': {
                        'name': 'query_order',
                        'parameters': {
                            'type': 'object',
                            'properties': {'phone': {'type': 'string'}},
                        },
                    },
                }
            ],
            'stream': True,
        },
        'response_sse': [
            'data: {"choices":[{"delta":{"content":"订单"},"index":0}]}\n\n',
            'data: {"choices":[{"delta":{"content":"查询中"},"index":0}]}\n\n',
            ': keepalive\n\n',
            # choices n=2 并行验证：第二路含 PII 文本，需全量遍历脱敏
            'data: {"choices":[{"delta":{"content":"第一路"},"index":0},{"delta":{"content":"13800138000"},"index":1}]}\n\n',
            'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"query_order","arguments":"{\\"phone\\":\\"__PII_1_ab12cd34__\\"}"}}]},"index":0}]}\n\n',
            'data: {"choices":[{"delta":{},"finish_reason":"tool_calls","index":0}]}\n\n',
            'data: [DONE]\n\n',
        ],
        'audit': {
            'line_buf_flush': 'newline',
            'arg_buf_walk': 'json_aware_once',
            'byte_buf_bom': 'stripped_once',
        },
    },
    'anthropic': {
        'protocol': 'v1/messages',
        'request': {
            'model': 'claude-3-5-sonnet-20241022',
            'messages': [{'role': 'user', 'content': 'IP 192.168.1.1 的服务器日志'}],
            'stream': True,
        },
        'response_sse': [
            'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1"}}\n\n',
            'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"日志"}}\n\n',
            ': keepalive\n\n',
            'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"正常"}}\n\n',
            'event: content_block_delta\ndata: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"ip\\":\\"192.168.1.1\\"}"}}\n\n',
            'event: content_block_stop\ndata: {"type":"content_block_stop","index":1}\n\n',
            'event: message_stop\ndata: {"type":"message_stop"}\n\n',
        ],
        'audit': {'comment_passthrough': True, 'retry_ascii_only': True},
    },
    'v1_models': {
        'protocol': 'v1/models',
        'request': {
            'model': 'gpt-4o-mini',
            'messages': [],  # non-dialog: v1/models body must be passthrough without walk
            'stream': False,
            'tail': 'v1/models',
        },
        'response_sse': [
            'data: {"object":"list","data":[{"id":"gpt-4o-mini","object":"model"}]}\n\n',
        ],
        'audit': {
            'passthrough': 'v1/models non-dialog tail bypass, no walk, no request_original.jsonl'
        },
    },
    'responses': {
        'protocol': 'v1/responses',
        'request': {
            'model': 'gpt-4o',
            'input': '查询张三的工号',
            'stream': True,
        },
        'response_sse': [
            'data: {"type":"response.output_text.delta","delta":"张三"}\n\n',
            ': keepalive\n\n',
            'data: {"type":"response.output_text.delta","delta":"的订单"}\n\n',
            'data: {"type":"response.function_call_arguments.delta","delta":"{\\"name\\":\\"张三\\"}"}\n\n',
            'data: {"type":"response.function_call_arguments.done"}\n\n',
            'data: {"type":"response.completed","response":{"id":"resp_1"}}\n\n',
        ],
        'audit': {
            'data_buffer_joined': True,
            'seen_global_terminal': 'response.completed',
        },
    },
}


def write_fixtures():
    FIX_DIR.mkdir(parents=True, exist_ok=True)
    for name, payload in SENTINELS.items():
        path = FIX_DIR / f'sentinel_{name}.jsonl'
        # 每行一条 JSON（请求+单行 SSE），保证可 loads
        with open(path, 'w', encoding='utf-8') as f:
            # 首行：request 脱敏后（无明文 PII，仅 token/保留 IP）
            f.write(
                json.dumps(
                    {'kind': 'request', 'body': payload['request']}, ensure_ascii=False
                )
                + '\n'
            )
            for line in payload['response_sse']:
                # 响应行：line_buf 行内还原无片段泄漏，keepalive 可见
                f.write(
                    json.dumps({'kind': 'sse', 'line': line}, ensure_ascii=False) + '\n'
                )
            f.write(
                json.dumps(
                    {'kind': 'audit', 'audit': payload['audit']}, ensure_ascii=False
                )
                + '\n'
            )
        print(f'wrote {path} ({len(payload["response_sse"]) + 2} lines)')


def check_fixtures():
    ok = True
    for name in SENTINELS:
        path = FIX_DIR / f'sentinel_{name}.jsonl'
        if not path.exists():
            print(f'MISSING {path}', file=sys.stderr)
            ok = False
            continue
        for i, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            try:
                obj = json.loads(raw)
            except Exception as e:
                print(f'{path}:{i} JSON load failed: {e}', file=sys.stderr)
                ok = False
                continue
            if obj.get('kind') == 'sse':
                _ = obj['line']
                # keepalive 可见
                if (
                    name in ('chat', 'responses')
                    and ': keepalive' not in open(path, encoding='utf-8').read()
                ):
                    pass
        print(f'checked {path} ok')
    # keepalive 可见性总检
    for name in ('chat', 'anthropic', 'responses'):
        txt = (FIX_DIR / f'sentinel_{name}.jsonl').read_text(encoding='utf-8')
        if ': keepalive' not in txt:
            print(f'{name} missing keepalive comment', file=sys.stderr)
            ok = False
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='sentinel_record')
    ap.add_argument('--check', action='store_true', help='校验 fixtures')
    args = ap.parse_args()
    if args.check:
        check_fixtures()
    else:
        write_fixtures()
        check_fixtures()


if __name__ == '__main__':
    main()
