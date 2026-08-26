"""pytest 共享配置：确保项目根目录可导入。

测试文件移到 tests/ 后，pytest 会把 tests/ 加入 sys.path，
但根目录模块（_token/_llm/_pii 等）不在其中。
这里显式把项目根目录插入 sys.path 首位，保证 `from _token import ...` 可用。
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
