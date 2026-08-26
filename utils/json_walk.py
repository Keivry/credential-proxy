"""utils.json_walk — 共享 JSON walk 抽取（design D1）。

统一三处 walk（_token._cred_json_walk / _pii._pii_json_walk / _llm._pii_response_process_json_aware）
的五要素：orjson / BOM / depth=5 / ensure_ascii=False,separators=(',',':') / 叶子级回退。
提供 sync 与 async 双形态。
"""

import inspect as _inspect
import json as _json
import logging

logger = logging.getLogger(__name__)

try:
    import orjson as _orjson  # type: ignore

    _USE_ORJSON = True
except ImportError:
    _orjson = None  # type: ignore
    _USE_ORJSON = False


def _jloads(s: str):
    if _USE_ORJSON:
        return _orjson.loads(s)  # type: ignore
    return _json.loads(s)


def _jdumps(obj) -> str:
    if _USE_ORJSON:
        return _orjson.dumps(obj).decode()  # type: ignore
    return _json.dumps(obj, ensure_ascii=False, separators=(',', ':'))


def _strip_bom(s: str) -> str:
    return s.lstrip('\ufeff')


def _validate_json_roundtrip(
    original: str, output: str, label: str = 'json_walk'
) -> str:
    stripped = original.lstrip('\ufeff').lstrip()
    if not (stripped.startswith('{') or stripped.startswith('[')):
        return output
    try:
        _json.loads(original.lstrip('\ufeff'))
    except Exception:
        return output
    try:
        _json.loads(output.lstrip('\ufeff'))
        return output
    except Exception as exc:
        logger.warning(
            '%s json-aware broke JSON, fallback to original: error=%s '
            'input_len=%d output_len=%d input_preview=%r output_preview=%r',
            label,
            exc,
            len(original),
            len(output),
            original[:4000],
            output[:4000],
        )
        return original


def json_walk(obj, leaf_fn, depth_limit: int = 5, path: str = '$', _depth: int = 0):
    """同步 walk：对 dict/list 递归，str 叶调 leaf_fn，叶子级最小回退。"""
    if _depth > depth_limit:
        if isinstance(obj, str):
            try:
                new_s = leaf_fn(obj)
            except Exception:
                return obj
            if new_s != obj:
                try:
                    _jdumps(new_s)
                except Exception as exc:
                    logger.warning(
                        'json_walk leaf broke, fallback leaf: path=%s error=%s leaf_preview=%r new_preview=%r',
                        path,
                        exc,
                        obj[:500],
                        new_s[:500],
                    )
                    return obj
            return new_s
        return obj
    if isinstance(obj, str):
        inner_stripped = obj.lstrip('\ufeff').strip()
        if inner_stripped.startswith(('{', '[')):
            try:
                inner = _jloads(inner_stripped)
                if isinstance(inner, (dict, list)):
                    walked = json_walk(
                        inner, leaf_fn, depth_limit, f'{path}->$.inner', _depth + 1
                    )
                    return _jdumps(walked)
            except Exception:
                pass
        try:
            new_s = leaf_fn(obj)
        except Exception:
            return obj
        if new_s != obj:
            try:
                _jdumps(new_s)
            except Exception as exc:
                logger.warning(
                    'json_walk leaf broke, fallback leaf: path=%s error=%s leaf_preview=%r new_preview=%r',
                    path,
                    exc,
                    obj[:500],
                    new_s[:500],
                )
                return obj
        return new_s
    if isinstance(obj, dict):
        return {
            k: json_walk(v, leaf_fn, depth_limit, f'{path}.{k}', _depth)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [
            json_walk(x, leaf_fn, depth_limit, f'{path}[{i}]', _depth)
            for i, x in enumerate(obj)
        ]
    return obj


async def json_walk_async(
    obj, leaf_fn, depth_limit: int = 5, path: str = '$', _depth: int = 0
):
    """异步 walk：leaf_fn 可为 async，await 调用。"""
    if _depth > depth_limit:
        if isinstance(obj, str):
            try:
                tmp = leaf_fn(obj)
                if _inspect.isawaitable(tmp):
                    new_s = await tmp
                else:
                    new_s = tmp
            except Exception:
                return obj
            if new_s != obj:
                try:
                    _jdumps(new_s)
                except Exception as exc:
                    logger.warning(
                        'json_walk_async leaf broke, fallback leaf: path=%s error=%s leaf_preview=%r new_preview=%r',
                        path,
                        exc,
                        obj[:500],
                        new_s[:500],
                    )
                    return obj
            return new_s
        return obj
    if isinstance(obj, str):
        inner_stripped = obj.lstrip('\ufeff').strip()
        if inner_stripped.startswith(('{', '[')):
            try:
                inner = _jloads(inner_stripped)
                if isinstance(inner, (dict, list)):
                    walked = await json_walk_async(
                        inner, leaf_fn, depth_limit, f'{path}->$.inner', _depth + 1
                    )
                    return _jdumps(walked)
            except Exception:
                pass
        try:
            tmp = leaf_fn(obj)
            if _inspect.isawaitable(tmp):
                new_s = await tmp
            else:
                new_s = tmp
        except Exception:
            return obj
        if new_s != obj:
            try:
                _jdumps(new_s)
            except Exception as exc:
                logger.warning(
                    'json_walk_async leaf broke, fallback leaf: path=%s error=%s leaf_preview=%r new_preview=%r',
                    path,
                    exc,
                    obj[:500],
                    new_s[:500],
                )
                return obj
        return new_s
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = await json_walk_async(
                v, leaf_fn, depth_limit, f'{path}.{k}', _depth
            )
        return out
    if isinstance(obj, list):
        res = []
        for i, x in enumerate(obj):
            res.append(
                await json_walk_async(x, leaf_fn, depth_limit, f'{path}[{i}]', _depth)
            )
        return res
    return obj


__all__ = [
    '_jdumps',
    '_jloads',
    '_strip_bom',
    '_validate_json_roundtrip',
    'json_walk',
    'json_walk_async',
]
