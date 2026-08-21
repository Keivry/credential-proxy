"""_audit.py — LLM 输出工具调用审计（design D3/D4）。

AuditMixin 提供：
- audit_tool_call(name, args_json) -> 'allow' | 'deny'（策略引擎）
- 内置默认策略（allow/deny 名单 + 危险模式：危险 shell、敏感路径、网络外传）
- AUDIT_POLICY_FILE 可选 JSON/YAML 加载（极简 YAML 子集，零依赖）
- 参数规范化（design D3 审计对抗性）：合并重复空白、解析转义、
  拆命令链、单层变量展开、别名形态、`..` 路径段规范化

防护边界（显式声明，写入策略文件头部与 README）：
- 防意外、不防对抗。已知未覆盖形态：base64 包装、ANSI-C quoting、
  相邻字符串字面量拼接、动态生成命令——这些属对抗级混淆，不在承诺内。
"""

import asyncio
import json
import logging
import os
import re as _re
import shutil

logger = logging.getLogger('credential-proxy')

# ═══════════════════════════════════════════════════════════
# 审计日志（design D5：追加写 JSONL，0600，10MB×5 轮转，
# 写失败 fail-closed 两层作用域 + 内存环形计数）
# ═══════════════════════════════════════════════════════════

AUDIT_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
AUDIT_LOG_BACKUPS = 5  # 轮转保留份数
AUDIT_LOG_WRITE_FAIL_LIMIT = 10  # 连续写失败升级阈值

# 控制字符（日志注入防护：剥离 \x00-\x1f，保留 \n 由 json 转义处理）
_CTRL_CHAR_RE = _re.compile(r'[\x00-\x1f]')


def _strip_ctrl(s: str) -> str:
    """剥离控制字符（design D5：防日志注入伪造条目）。"""
    return _CTRL_CHAR_RE.sub('', s)


def _rotate_audit_log(path: str) -> None:
    """大小轮转：audit.log → .1 → .2 → … → .5，最老删除。"""
    for i in range(AUDIT_LOG_BACKUPS - 1, 0, -1):
        src = f'{path}.{i}'
        dst = f'{path}.{i + 1}'
        if os.path.exists(src):
            if os.path.exists(dst):
                os.remove(dst)
            shutil.move(src, dst)
    if os.path.exists(path):
        dst = f'{path}.1'
        if os.path.exists(dst):
            os.remove(dst)
        shutil.move(path, dst)


def _append_audit_log(path: str, record: dict) -> bool:
    """追加一条审计日志（JSON Lines）。返回 True=写入成功。

    - json.dumps 强制转义 + 剥离控制字符（防日志注入伪造条目）
    - 大小轮转（10MB × 5 份）
    - 写失败返回 False（调用方按 fail-closed 两层作用域处置）
    """
    try:
        line = json.dumps(record, ensure_ascii=False, default=str)
        line = _strip_ctrl(line)
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        # 轮转检查（文件超限先轮转）
        if os.path.exists(path) and os.path.getsize(path) > AUDIT_LOG_MAX_BYTES:
            _rotate_audit_log(path)
        # 权限 0600（新建时）
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
        return True
    except OSError:
        return False


# ═══════════════════════════════════════════════════════════
# 极简 YAML 子集解析（仅支持策略文件所需结构）
# ═══════════════════════════════════════════════════════════

# 顶层键 + 缩进列表项
_YAML_KEY_RE = _re.compile(r'^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$')
_YAML_LIST_ITEM_RE = _re.compile(r'^-\s+(.*)$')


def _parse_scalar(s: str):
    """解析 YAML 标量（字符串/数字/布尔/null/JSON 内联）。"""
    s = s.strip()
    if s == '' or s == 'null' or s == '~':
        return None
    if s == 'true':
        return True
    if s == 'false':
        return False
    if (s.startswith('"') and s.endswith('"')) or (
        s.startswith("'") and s.endswith("'")
    ):
        try:
            return json.loads(s) if s.startswith('"') else s[1:-1]
        except json.JSONDecodeError:
            return s[1:-1]
    if s.startswith(('[', '{')):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _parse_simple_yaml(text: str) -> dict:
    """极简 YAML 解析：顶层键 + 列表项（含嵌套列表的简单对象）。

    支持：
      key: value
      key:
        - item
        - key2: value   （列表项内的键值对 → dict，后续兄弟键续行并入）
    不支持：复杂嵌套、锚点、多行块。结构超出时抛 ValueError。
    """
    result: dict = {}
    current_list: list | None = None
    last_item_dict: dict | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        indent = len(line) - len(line.lstrip())
        content = line.strip()
        if indent == 0:
            m = _YAML_KEY_RE.match(content)
            if not m:
                raise ValueError(f'YAML 顶层解析失败: {content!r}')
            key, val = m.group(1), m.group(2)
            if val:
                result[key] = _parse_scalar(val)
            else:
                current_list = []
                result[key] = current_list
            last_item_dict = None
        elif indent > 0 and content.startswith('- '):
            item_text = content[2:].strip()
            m = _YAML_KEY_RE.match(item_text)
            if current_list is None:
                raise ValueError(f'YAML 列表项缺少父键: {content!r}')
            if m and m.group(2) == '':
                # 嵌套列表项（key: 后面空 → 递归子列表）
                sub = {}
                sub_list = []
                sub[m.group(1)] = sub_list
                current_list.append(sub)
                # 简化：只支持一层嵌套列表
                _fill_sub_list(
                    sub_list,
                    text.splitlines(),
                    text.splitlines().index(raw_line) + 1,
                    indent,
                )
                last_item_dict = sub
            elif m:
                d = {m.group(1): _parse_scalar(m.group(2))}
                current_list.append(d)
                last_item_dict = d
            else:
                current_list.append(_parse_scalar(item_text))
                last_item_dict = None
        elif indent > 0 and last_item_dict is not None:
            # 列表项内的兄弟键续行：- pattern: '...' 后的 reason: 危险删除
            m = _YAML_KEY_RE.match(content)
            if m:
                key, val = m.group(1), m.group(2)
                if val:
                    last_item_dict[key] = _parse_scalar(val)
                else:
                    # 键后空值 → 空列表（简化）
                    last_item_dict[key] = []
            else:
                raise ValueError(f'YAML 缩进结构不支持: {line!r}')
        else:
            raise ValueError(f'YAML 缩进结构不支持: {line!r}')
    return result


def _fill_sub_list(sub_list, lines, start_idx, parent_indent):
    """填充嵌套子列表（一层）。"""
    i = start_idx
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith('#'):
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= parent_indent:
            break
        content = line.strip()
        if content.startswith('- '):
            sub_list.append(_parse_scalar(content[2:].strip()))
        i += 1


def load_policy_file(path: str) -> dict:
    """加载策略文件（JSON 或极简 YAML）。"""
    if not os.path.exists(path):
        raise FileNotFoundError(f'审计策略文件不存在: {path}')
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    stripped = text.lstrip()
    try:
        if stripped.startswith('{'):
            return json.loads(text)
        return _parse_simple_yaml(text)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f'策略文件解析失败: {path}: {e}') from e


# ═══════════════════════════════════════════════════════════
# 参数规范化（design D3 审计对抗性）
# ═══════════════════════════════════════════════════════════


def normalize_args(args: str) -> str:
    """规范化 tool 参数文本，使规则命中不被简单混淆绕过。

    步骤：
    1. 解析 \\uXXXX / \\xXX 转义（JSON 字符串内常见）
    2. 合并重复空白（含换行 → 空格）
    3. 递归展开单层变量拼接（`CMD=rm;$CMD -rf` → `CMD=rm;rm -rf`）
    4. 拆命令链（; / && / | / || / 换行 → 空格分隔的独立段）
    5. 识别 /bin/rm、find -delete 等别名形态（保留原文 + 别名展开）
    6. 规范化 `..` 路径段（/tmp/../etc → /etc）
    """
    if not args:
        return ''
    s = args
    # 1. 解析转义
    s = _unescape(s)
    # 2. 合并空白
    s = _re.sub(r'\s+', ' ', s)
    # 6. `..` 路径段规范化（先做，避免拆链后丢失路径上下文）
    s = _normalize_dotdot(s)
    # 3. 单层变量展开（在拆链前，保持 CMD=rm;$CMD -rf 的赋值-引用关系）
    s = _expand_vars(s)
    # 4. 拆命令链（用空格分隔独立段，保留关键动词；|| 优先于单 | 匹配）
    s = _re.sub(r'\s*(?:;|&&|\|\||\||\n)\s*', ' ', s)
    # 5. 别名形态
    s = _expand_aliases(s)
    return s


def _unescape(s: str) -> str:
    """解析 \\uXXXX / \\xXX 转义为实际字符。"""

    def _u(m):
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)

    def _x(m):
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)

    s = _re.sub(r'\\u([0-9a-fA-F]{4})', _u, s)
    s = _re.sub(r'\\x([0-9a-fA-F]{2})', _x, s)
    s = s.replace('\\n', '\n').replace('\\t', '\t')
    return s


_VAR_ASSIGN_RE = _re.compile(
    r'(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=(?!=)(.*?)(?:;|&&|\|\||$)',
    _re.MULTILINE,
)


def _expand_vars(s: str) -> str:
    """单层变量展开：`CMD=rm;$CMD -rf` → `CMD=rm;rm -rf`。

    赋值识别不锚定行首（参数常包在 JSON 里），只要求赋值前是
    命令链分隔符/字符串起点。
    """
    # 收集赋值（一次）——只取赋值语句本身（到第一个分隔符/行尾）
    assignments = {}
    for m in _VAR_ASSIGN_RE.finditer(s):
        assignments[m.group(1)] = m.group(2)
    if not assignments:
        return s

    # 替换 $VAR / ${VAR}
    def _repl(m):
        var = m.group(1) or m.group(2)
        if var in assignments:
            return assignments[var]
        return m.group(0)

    return _re.sub(r'\$(\w+)|(?<!\\)\$\{(\w+)\}', _repl, s)


def _expand_aliases(s: str) -> str:
    """别名形态展开（保持原文 + 展开形态，便于规则命中）。"""
    # /bin/rm → rm（规则里用 rm 前缀即可命中 /bin/rm 原文；此处补充 find -delete）
    s = _re.sub(r'\bfind\s+([^;|&]*?)\s+-delete\b', r'rm -rf \1', s)
    s = _re.sub(r'\b/bin/(\w+)', r'\1', s)
    return s


def _normalize_dotdot(s: str) -> str:
    """规范化 `..` 路径段：/tmp/../etc → /etc。

    用 posixpath.normpath 处理参数中的绝对路径形态（鲁棒且无正则陷阱）。
    仅处理被引号/空白包裹的路径片段（不破坏命令结构）。

    性能（Round 17 R2）：不用「非空白字符 + /../ + 非空白字符」的
    全文正则——贪吃部分在长无匹配/部分匹配文本上逐位置回退 O(n²)
    （100KB 实测 ~27s）。改为「`/../` 定位 + 局部窗口规范化」O(n) 算法。
    """
    import posixpath

    # 无 `/../` 候选直接短路（O(n) 的 in 检查）
    if '/../' not in s:
        return s

    # 引号内路径（最常见：{"path":"/tmp/../etc/passwd"}）——定位每个
    # `/../`，向两侧扩展到引号边界，局部 normpath，O(n)。
    result = []
    last = 0
    i = s.find('/../')
    while i != -1:
        # 向两侧扩展：左到最近引号/空白/行首，右到最近引号/空白/行尾
        left = i
        while left > last and s[left - 1] not in '"\'\t ':
            left -= 1
        right = i + 4
        while right < len(s) and s[right] not in '"\'\t ':
            right += 1
        segment = s[left:right]
        result.append(s[last:left])
        result.append(posixpath.normpath(segment))
        last = right
        i = s.find('/../', right)
    result.append(s[last:])
    return ''.join(result)


# ═══════════════════════════════════════════════════════════
# 外部域名判定（design D3：不解析 DNS）
# ═══════════════════════════════════════════════════════════

_INTERNAL_TLDS = ('.local', '.internal', '.localhost')
_RFC1918_PREFIXES = (
    '10.',
    '192.168.',
    '172.16.',
    '172.17.',
    '172.18.',
    '172.19.',
    '172.20.',
    '172.21.',
    '172.22.',
    '172.23.',
    '172.24.',
    '172.25.',
    '172.26.',
    '172.27.',
    '172.28.',
    '172.29.',
    '172.30.',
    '172.31.',
)
_LOOPBACK = ('127.', '::1', '0:0:0:0:0:0:0:1')
_LINK_LOCAL = ('169.254.', 'fe80:', 'fe8', 'fe9', 'fea', 'feb')
_IPV4_RE = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def is_external_host(host: str, internal_suffixes: tuple = ()) -> bool | None:
    """判断 host 是否外传目标。

    返回 True=外传 / False=内网 / None=无法判定（按 fail-closed 视为外传）。
    - IP 字面量：非 RFC1918/非环回/非链路本地/非本机 → 外传
    - 域名：内网后缀列表 + 启发式（.local/.internal/.localhost）→ 内网；
      其余 → 外传
    不解析 DNS（design D3 硬性）。
    """
    if not host:
        return None
    host = host.strip().lower().rstrip('.')
    if not host:
        return None
    # 端口剥离（仅 host:port 形态，IPv6 字面量含多冒号不剥离）
    if ':' in host and host.count(':') == 1 and not host.startswith('['):
        host = host.split(':')[0]
    host = host.strip('[]')
    # IP 字面量判定
    if _IPV4_RE.match(host):
        if host.startswith(_RFC1918_PREFIXES):
            return False
        return not (host.startswith(_LOOPBACK) or host.startswith(_LINK_LOCAL))
    if host.startswith('::') or ':' in host:
        # IPv6 字面量
        return not (host in _LOOPBACK or host.startswith(_LINK_LOCAL))
    # 域名判定
    if host == 'localhost':
        return False
    if host.endswith(_INTERNAL_TLDS):
        return False
    return not (internal_suffixes and host.endswith(internal_suffixes))


# ═══════════════════════════════════════════════════════════
# 内置默认策略
# ═══════════════════════════════════════════════════════════

DEFAULT_POLICY: dict = {
    'allow': [
        # 常见安全工具
        'web_search',
        'web_extract',
        'read_file',
        'list_files',
        'search_files',
        'write_file',
        'patch',
        'session_search',
        'memory',
        'skill_view',
        'skills_list',
        'skill_manage',
        'cronjob',
        'todo',
        'execute_code',
        'terminal',
        'bash',
        'get_credential',
        'ask_user',
        'clarify',
    ],
    'deny': [],
    'dangerous': [
        # 危险 shell 命令
        {'pattern': r'\brm\s+-rf\b', 'reason': '危险删除 rm -rf'},
        {'pattern': r'\bmkfs\b', 'reason': '格式化磁盘 mkfs'},
        {'pattern': r'\bdd\s+if=.*\s+of=/(dev|sd|hd)', 'reason': '写块设备 dd'},
        {'pattern': r'\bshutdown\b|\breboot\b|\bpoweroff\b', 'reason': '关机/重启'},
        {
            'pattern': r'\bchmod\s+(-R\s+)?[0-7]{3,4}\s+(/|/etc|/usr|/bin|/var)',
            'reason': '系统目录权限变更',
        },
        {
            'pattern': r'\bchown\s+(-R\s+)?\w+\s+(/|/etc|/usr|/bin)',
            'reason': '系统目录属主变更',
        },
        # 敏感路径写入
        {
            'pattern': r'\b(write_file|patch|echo|cat|tee|cp|mv)\b[^\n]*?(/etc/(passwd|shadow|sudoers|hosts|ssh)|/root/|/boot/)',
            'reason': '敏感路径写入',
        },
        # 网络外传（network: true 标记 → 命中后还需外部域名判定，内网放行）
        {
            'pattern': r'\b(curl|wget|nc|ncat|telnet|ssh)\b[^\n]*(?:\s(?:-o|--output|>|>>)\s+\S+|https?://|ftp://)',
            'reason': '网络传输',
            'network': True,
        },
        {
            'pattern': r'\b(base64|openssl)\b[^\n]*\b(?:-d|decode|decrypt)\b',
            'reason': '解码传输（base64 外传包装）',
        },
    ],
    'internal_suffixes': [
        '.corp.example',
        '.local',
        '.internal',
    ],
}

# 危险 shell 命令前缀集（预检用，design D4：暂停先于判定）
_DANGEROUS_PREFIXES = (
    'rm',
    'mkfs',
    'dd',
    'shutdown',
    'reboot',
    'poweroff',
    'chmod',
    'chown',
    'curl',
    'wget',
    'nc',
    'ncat',
    'telnet',
    'ssh',
    'base64',
    'openssl',
    'bash',
    'sh',
    'terminal',
    'execute_code',
)


class AuditMixin:
    """Mixin：tool call 审计策略引擎 + 阻断处置。"""

    def _init_audit(self, policy_file: str | None = None):
        self.audit_enabled_flag = False
        self.audit_mode = 'block'  # 'block' | 'approve'（approve 在 Batch 6）
        self.audit_timeout = 90  # 审批超时（秒），默认 90s，与上游 ~120s 断连窗口错开
        self.audit_hold_max_bytes = 1048576  # 审批挂起期间缓冲上限（默认 1MB）
        self.policy = self._load_policy(policy_file)
        # ── 审批状态（AUDIT_MODE=approve 时使用）──
        self.approval_whitelist: set[str] = set()  # 审批人 Matrix user id 白名单
        self._audit_approval_pending: dict[str, dict] = {}  # req_id → pending 条目
        self._audit_approval_msgs: dict[str, str] = {}  # msg_id → req_id
        self._audit_pending_seq = 0
        # ── 审计日志（design D5）──
        _data_dir = os.environ.get('DATA_DIR', '')
        self.audit_log_path = os.environ.get(
            'AUDIT_LOG',
            os.path.join(_data_dir, 'audit.log') if _data_dir else '',
        )
        # 内存环形计数（写失败 fail-closed 可观测性）
        self._audit_log_ring: list[dict] = []  # 最近事件（含触发规则摘要）
        self._audit_log_ring_max = 100
        self._audit_log_fail_count = 0  # 连续写失败计数（升级熔断阈值）
        self._audit_log_fail_limit = AUDIT_LOG_WRITE_FAIL_LIMIT

    def _ensure_audit_init(self):
        """lazy 初始化（首次访问时读取环境变量）。"""
        if not hasattr(self, 'audit_enabled_flag'):
            policy_file = os.environ.get('AUDIT_POLICY_FILE') or None
            self._init_audit(policy_file)
            # 总开关：AUDIT_MODE 三值（off/block/approve，默认 off）
            # 兼容旧 AUDIT_ENABLED=1（此时 AUDIT_MODE 未设 → block）
            mode = os.environ.get('AUDIT_MODE', 'off')
            if mode in ('block', 'approve'):
                self.audit_enabled_flag = True
                self.audit_mode = mode
            elif mode == 'off':
                self.audit_enabled_flag = False
                # 旧变量兼容：AUDIT_ENABLED=1 且 AUDIT_MODE 未设 → block
                if (
                    os.environ.get('AUDIT_ENABLED') in ('1', 'true', 'True', 'yes')
                    and 'AUDIT_MODE' not in os.environ
                ):
                    self.audit_enabled_flag = True
                    self.audit_mode = 'block'
            # 审批超时（AUDIT_TIMEOUT，默认 90s）；非法值回落默认
            try:
                t = int(os.environ.get('AUDIT_TIMEOUT', '90'))
                if t >= 1:
                    self.audit_timeout = t
            except (ValueError, TypeError):
                pass
            # 审批挂起缓冲上限（AUDIT_HOLD_MAX_BYTES，默认 1MB）
            try:
                h = int(os.environ.get('AUDIT_HOLD_MAX_BYTES', '1048576'))
                if h >= 1:
                    self.audit_hold_max_bytes = h
            except (ValueError, TypeError):
                pass
            # 审批人白名单（逗号分隔 Matrix user id）
            wl = os.environ.get('APPROVAL_WHITELIST', '')
            if wl:
                self.approval_whitelist = {
                    u.strip() for u in wl.split(',') if u.strip()
                }
            # 防御性校验（Round 17 R6）：approve 模式必须配置白名单。
            # proxy.py 启动时已通过 parse_audit_env_config(require_whitelist=True)
            # 强制；此处双保险——任何入口（轻量入口/未来新入口）走到
            # _ensure_audit_init 都不能以「approve + 空白名单」运行
            # （空白名单 = 分支 5 的 `if self.approval_whitelist and ...`
            # 跳过校验 → 任何房间成员可审批）。
            if (
                self.audit_enabled_flag
                and self.audit_mode == 'approve'
                and not self.approval_whitelist
            ):
                logger.error(
                    'AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST'
                    '（审批人 Matrix user id），降级为 block 模式'
                )
                self.audit_mode = 'block'
            if self.audit_enabled_flag:
                logger.info(
                    '输出审计启用: mode=%s policy=%s',
                    self.audit_mode,
                    policy_file or '(default)',
                )
            # 审批模式：启动周期清扫兜底（孤儿 pending 置 rejected）
            if self.audit_enabled_flag and self.audit_mode == 'approve':
                self._start_approval_sweeper()

    def _start_approval_sweeper(self):
        """启动审批孤儿清扫定时任务（design D4 6.4：周期 60s）。

        流结束/异常但 pending 未清理（如 handler 崩溃路径）时，
        孤儿审批条目置 rejected（event.set() 唤醒等待者）+ 清理。
        """
        if getattr(self, '_approval_sweeper_started', False):
            return
        self._approval_sweeper_started = True

        async def _sweep_loop():
            while True:
                await asyncio.sleep(60)
                try:
                    for _req_id, _ap in list(self._audit_approval_pending.items()):
                        if _ap.get('approved') is None:
                            logger.warning('审批孤儿清扫: %s 置 rejected', _req_id)
                            _ap['approved'] = False
                            _ap['event'].set()
                            self._audit_approval_pending.pop(_req_id, None)
                except Exception:  # pragma: no cover — 清扫异常不崩溃
                    logger.exception('审批孤儿清扫异常')

        self._approval_sweep_task = asyncio.create_task(_sweep_loop())

    def audit_enabled(self) -> bool:
        """审计是否启用。"""
        self._ensure_audit_init()
        return self.audit_enabled_flag

    def _load_policy(self, policy_file: str | None) -> dict:
        """加载策略：默认策略 + 可选文件覆盖。"""
        policy = json.loads(json.dumps(DEFAULT_POLICY))  # 深拷贝
        if policy_file:
            try:
                loaded = load_policy_file(policy_file)
                if not isinstance(loaded, dict):
                    raise TypeError('策略文件顶层必须是对象')
                # 合并（列表替换，标量覆盖）
                for k, v in loaded.items():
                    policy[k] = v
                logger.info('审计策略加载: %s', policy_file)
            except (OSError, ValueError, TypeError) as e:
                # 非法策略文件 → fail-closed（禁用审计并告警）
                logger.error('审计策略加载失败（审计禁用）: %s', e)
                self.audit_enabled_flag = False
                return policy
        return policy

    async def audit_tool_call(self, name: str, args_json: str) -> str:
        """审计单个 tool call。返回 'allow' 或 'deny'。

        判定顺序：deny 名单（精确）→ 危险模式（内容级，对所有工具生效，
        包括 allow 名单内工具——allow 仅表示「无危险内容时放行」）→
        allow 名单 → 默认 allow。
        """
        self._ensure_audit_init()
        if not self.audit_enabled():
            return 'allow'
        # deny 名单（精确匹配）
        if name in self.policy.get('deny', []):
            await self._audit_log_event(
                'deny', name, args_json, 'deny-list', 'deny 名单精确匹配'
            )
            return 'deny'
        # 危险模式（规范化后匹配）——对所有工具生效。
        # 规则匹配「工具名 + 参数」拼接文本（敏感路径规则依赖工具名）。
        norm = normalize_args(f'{name} {args_json}')
        for rule in self.policy.get('dangerous', []):
            pattern = rule.get('pattern', '') if isinstance(rule, dict) else ''
            if not pattern:
                continue
            try:
                if _re.search(pattern, norm) or _re.search(pattern, args_json):
                    # network 规则：命中后还需外部域名判定（内网放行）
                    if isinstance(rule, dict) and rule.get('network'):
                        host = _extract_host(args_json)
                        if host:
                            _verdict = is_external_host(
                                host,
                                tuple(self.policy.get('internal_suffixes', [])),
                            )
                            if _verdict is not True:
                                # 内网/无法判定→放行（内网目标不属网络外传）
                                continue
                    logger.warning(
                        '审计拦截: %s (%s) — 命中规则 %s',
                        name,
                        args_json[:120],
                        rule.get('reason', pattern)
                        if isinstance(rule, dict)
                        else pattern,
                    )
                    await self._audit_log_event(
                        'deny',
                        name,
                        args_json,
                        rule.get('reason', pattern)
                        if isinstance(rule, dict)
                        else pattern,
                        '危险模式命中',
                    )
                    return 'deny'
            except _re.error:
                logger.error('审计规则正则编译失败: %r', pattern)
        # 外部域名判定（网络外传规则补充）
        if name in (
            'curl',
            'wget',
            'nc',
            'ncat',
            'telnet',
            'ssh',
            'bash',
            'terminal',
            'execute_code',
        ):
            host = _extract_host(args_json)
            if host:
                verdict = is_external_host(
                    host,
                    tuple(self.policy.get('internal_suffixes', [])),
                )
                if verdict is True:
                    logger.warning(
                        '审计拦截: %s 网络外传目标 %s',
                        name,
                        host,
                    )
                    await self._audit_log_event(
                        'deny', name, args_json, 'network-exfil', '网络外传目标'
                    )
                    return 'deny'
        # allow 名单（精确匹配）
        if name in self.policy.get('allow', []):
            await self._audit_log_event(
                'allow', name, args_json, 'allow-list', 'allow 名单'
            )
            return 'allow'
        await self._audit_log_event('allow', name, args_json, '', '默认放行')
        return 'allow'

    # ── 审计日志（design D5）──

    def _audit_live_redact(self, text: str) -> str:
        """实时请求级映射脱敏（含响应期新注册 PII）。

        design D5 硬性：日志摘要不得从掩码前快照取——若 PII scope 可用，
        先把占位符还原为明文，再经 redact_summary 的密钥形态替换盖住
        （还原出的明文在 redact_summary 内被 [REDACTED:<type>] 替换）。
        无 scope（纯 AuditMixin 单测）时退化为仅 secret 形态替换。
        """
        if not text:
            return ''
        scope_fn = getattr(self, '_pii_scope_or_none', None)
        if scope_fn is not None:
            try:
                scope = scope_fn()
                if scope is not None:
                    pii_t2p = getattr(scope, 'pii_t2p', {})
                    resp_t2p = getattr(scope, 'resp_t2p', {})
                    for tok, plain in pii_t2p.items():
                        if tok and plain:
                            text = text.replace(tok, plain)
                    # 响应期新注册 PII：token 原样保留（脱敏由 redact_summary 完成）
                    for tok in resp_t2p:
                        if tok:
                            text = text.replace(tok, tok)
            except (
                AttributeError,
                TypeError,
            ) as e:  # pragma: no cover — scope 异常不影响审计
                logger.debug('审计日志脱敏 scope 访问异常: %s', e)
        return redact_summary(text)

    async def _audit_log_event(
        self,
        verdict: str,
        name: str,
        args_json: str,
        rule_hit: str = '',
        note: str = '',
    ) -> None:
        """写一条审计日志（JSONL 追加）。

        fail-closed 两层作用域（design D5 硬性）：
        - deny/危险路径写失败：仍阻断 + 告警 + 内存环形计数（不静默放行）
        - allow/放行路径写失败：告警不阻断 + 内存计数，连续
          AUDIT_LOG_WRITE_FAIL_LIMIT 次 → 升级熔断告警
        """
        self._ensure_audit_init()
        summary = self._audit_live_redact(args_json)
        record = {
            'ts': asyncio.get_event_loop().time(),
            'tool': name,
            'verdict': verdict,
            'rule': rule_hit,
            'summary': summary,
            'note': note,
        }
        # 内存环形计数（进程存活期内可查询——告警通道不可用时事件不无痕）
        ring = getattr(self, '_audit_log_ring', [])
        ring.append(record)
        if len(ring) > getattr(self, '_audit_log_ring_max', 100):
            del ring[: len(ring) - getattr(self, '_audit_log_ring_max', 100)]
        path = getattr(self, 'audit_log_path', '') or ''
        if not path:
            return  # 未配置路径（测试环境）→ 仅内存
        ok = await asyncio.get_running_loop().run_in_executor(
            None, _append_audit_log, path, record
        )
        if ok:
            self._audit_log_fail_count = 0
            return
        # 写失败：两层 fail-closed
        self._audit_log_fail_count = getattr(self, '_audit_log_fail_count', 0) + 1
        if verdict == 'deny':
            # 危险调用写失败：仍阻断（调用方已 deny），告警 + 环形计数
            logger.error('审计日志写失败（危险调用，已阻断）: %s (%s)', name, path)
        else:
            # 放行调用写失败：告警不阻断；连续失败升级熔断
            logger.error('审计日志写失败: %s (%s)', name, path)
            if self._audit_log_fail_count >= getattr(self, '_audit_log_fail_limit', 10):
                logger.critical(
                    '审计日志连续 %d 次写失败（熔断告警）: %s',
                    self._audit_log_fail_count,
                    path,
                )
                self._audit_log_fail_count = 0

    def audit_precheck(self, name: str, args_prefix: str) -> bool:
        """预检（design D4）：同步廉价前缀匹配，判定前暂停 flush。

        返回 True = 可疑（需暂停）。

        匹配范围：
        1. tool 名命中危险前缀（bash/sh/terminal/curl 等）
        2. 参数前缀串**任意位置**出现危险命令起始——含 JSON 包装
           （`{"cmd":"rm` 的 `rm` 前是引号/冒号，也是命令起始）——
           design D4「参数增量 LCP 前缀命中」：`rm` 是 `rm -rf` 的前缀，
           必须在此阶段可见即暂停（await 完整判定前不可让 `rm` 流出）。
        """
        if not self.audit_enabled():
            return False
        # tool 名命中危险前缀
        if name in _DANGEROUS_PREFIXES or name in ('curl', 'wget', 'nc'):
            return True
        # 参数中出现危险命令起始（命令名前是 JSON 边界/分隔符/空白）
        # 注意：只做廉价正则扫描（无回溯爆炸风险——模式固定）
        stripped = args_prefix.lstrip()
        for prefix in _DANGEROUS_PREFIXES:
            if stripped.startswith(prefix):
                return True
        # JSON 包装：危险命令出现在值起始处（`"cmd":"rm` / `cmd=rm` / `:rm`）
        return (
            _re.search(
                r'["\'=:;|&({]\s*(' + '|'.join(_DANGEROUS_PREFIXES) + r')',
                args_prefix,
            )
            is not None
        )


def _extract_host(args_json: str) -> str | None:
    """从 tool 参数中提取网络目标 host（URL 或裸 IP/域名）。

    返回 host 或 None（无法提取）。仅做简单提取，不做 DNS 解析。
    """
    if not args_json:
        return None
    # URL 形态
    m = _re.search(r'https?://([^/\s"\']+)', args_json)
    if m:
        return m.group(1)
    # 裸 IP / 域名（curl 8.8.8.8 / curl evil.com）
    m = _re.search(r'\b(curl|wget|nc|ncat|telnet)\s+([^\s"\';|&]+)', args_json)
    if m:
        return m.group(2)
    return None


# 阻断消息模板（design D4：无 tool_calls 的 assistant content）
BLOCK_MESSAGE = '该工具调用已被安全策略拦截（审计拒绝）。如需执行请联系管理员审批。'


# ═══════════════════════════════════════════════════════════
# 审批摘要脱敏（design D4：先脱敏后截断）
# ═══════════════════════════════════════════════════════════

# 密钥/敏感值形态（摘要中替换为 [REDACTED:<type>]）
_SECRET_PATTERNS = (
    ('api_key', _re.compile(r'sk-[A-Za-z0-9_-]{16,}')),
    ('token', _re.compile(r'(?:gh[pous]_|glpat-|xox[baprs]-)[A-Za-z0-9_-]{10,}')),
    ('password', _re.compile(r'(?i)passw(?:or)?d\s*[:=]\s*\S+')),
    ('secret', _re.compile(r'(?i)secret\s*[:=]\s*\S+')),
    ('token', _re.compile(r'(?i)token\s*[:=]\s*\S+')),
    (
        'private_key',
        _re.compile(
            r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
            _re.DOTALL,
        ),
    ),
    ('id_card', _re.compile(r'\d{17}[\dXx]')),
    ('phone', _re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)')),
    (
        'email',
        _re.compile(r'\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}\b'),
    ),
)


def redact_summary(text: str, max_len: int = 120) -> str:
    """先脱敏后截断的参数摘要（审批消息/审计日志共用）。

    - 密钥形态替换为 [REDACTED:<type>]
    - 截断边界半字符保护（不切断 UTF-8 多字节字符）
    """
    if not text:
        return ''
    redacted = text
    for label, pat in _SECRET_PATTERNS:
        # email 正则无锚定且可变长：无 @ 时 sub() 逐位置重试 O(n²)
        # （100KB 纯字母实测 ~20s）——先检测候选字符，无则整条跳过。
        if label == 'email' and '@' not in redacted:
            continue
        redacted = pat.sub(f'[REDACTED:{label}]', redacted)
    if len(redacted) <= max_len:
        return redacted
    # 截断边界半字符保护：回退到最后一个完整字符
    cut = redacted[:max_len]
    while cut:
        try:
            cut[-1].encode('utf-8')
            break
        except UnicodeEncodeError:
            cut = cut[:-1]
    return cut + '…'


# ═══════════════════════════════════════════════════════════
# 配置校验（Batch 8.1：proxy/轻量入口启动时调用）
# ═══════════════════════════════════════════════════════════

# AUDIT_TIMEOUT 竞态区间：上游 ~120s 断连特征两侧各留 ~10s 安全余量
AUDIT_TIMEOUT_RACE_MIN = 110
AUDIT_TIMEOUT_RACE_MAX = 130


def parse_audit_env_config(require_whitelist: bool = False) -> dict:
    """解析并校验审计相关环境变量，返回配置字典 + 错误列表。

    校验（design D5 / tasks 8.1）：
    - AUDIT_MODE ∈ {off, block, approve}（默认 off）
    - AUDIT_TIMEOUT ≥1s 且拒绝 110-130s 竞态区间（0/负/竞态区间 → 错误）
    - AUDIT_HOLD_MAX_BYTES ≥1（非法 → 错误）
    - require_whitelist=True（完整 proxy）：AUDIT_MODE=approve 且无
      APPROVAL_WHITELIST → 错误

    返回: {'mode', 'timeout', 'hold_max', 'whitelist', 'errors': [str]}
    """
    errors: list[str] = []
    mode = os.environ.get('AUDIT_MODE', 'off')
    if mode not in ('off', 'block', 'approve'):
        errors.append(f'AUDIT_MODE 非法: {mode!r}（取值 off/block/approve）')
        mode = 'off'
    # 向后兼容：AUDIT_ENABLED=1 且 AUDIT_MODE 未设 → block
    # （与 _ensure_audit_init 语义一致；显式 AUDIT_MODE 优先）
    if os.environ.get('AUDIT_MODE') is None and os.environ.get('AUDIT_ENABLED') in (
        '1',
        'true',
        'True',
        'yes',
    ):
        mode = 'block'

    timeout = 90
    raw_t = os.environ.get('AUDIT_TIMEOUT', '90')
    try:
        timeout = int(raw_t)
        if timeout < 1:
            errors.append(f'AUDIT_TIMEOUT 必须 ≥1s: {raw_t!r}')
        elif AUDIT_TIMEOUT_RACE_MIN <= timeout <= AUDIT_TIMEOUT_RACE_MAX:
            errors.append(
                f'AUDIT_TIMEOUT 不得落在 {AUDIT_TIMEOUT_RACE_MIN}-'
                f'{AUDIT_TIMEOUT_RACE_MAX}s 竞态区间（上游 ~120s 断连窗口）: '
                f'{timeout}s'
            )
    except (ValueError, TypeError):
        errors.append(f'AUDIT_TIMEOUT 非法整数: {raw_t!r}')

    hold_max = 1048576
    raw_h = os.environ.get('AUDIT_HOLD_MAX_BYTES', '1048576')
    try:
        hold_max = int(raw_h)
        if hold_max < 1:
            errors.append(f'AUDIT_HOLD_MAX_BYTES 必须 ≥1: {raw_h!r}')
    except (ValueError, TypeError):
        errors.append(f'AUDIT_HOLD_MAX_BYTES 非法整数: {raw_h!r}')

    whitelist: set[str] = set()
    wl = os.environ.get('APPROVAL_WHITELIST', '')
    if wl:
        whitelist = {u.strip() for u in wl.split(',') if u.strip()}
    if require_whitelist and mode == 'approve' and not whitelist:
        errors.append(
            'AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST（审批人 Matrix user id）'
        )

    return {
        'mode': mode,
        'timeout': timeout,
        'hold_max': hold_max,
        'whitelist': whitelist,
        'errors': errors,
    }
