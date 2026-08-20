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

import json
import logging
import os
import re as _re

logger = logging.getLogger('credential-proxy')

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
    # 4. 拆命令链（用空格分隔独立段，保留关键动词）
    s = _re.sub(r'\s*(?:;|&&|\|\||\n)\s*', ' ', s)
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
    """
    import posixpath

    # 提取路径片段（/xxx/../xxx 或 引号内路径）
    def _norm(m):
        return posixpath.normpath(m.group(1))

    # 引号内路径（最常见：{"path":"/tmp/../etc/passwd"}）
    s = _re.sub(
        r'"([^"]*/\.\./[^"]*)"', lambda m: f'"{posixpath.normpath(m.group(1))}"', s
    )
    # 裸路径（空格分隔的 /a/../b 片段）
    s = _re.sub(r'(\S*/\.\./\S*)', lambda m: posixpath.normpath(m.group(1)), s)
    return s


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
        self.policy = self._load_policy(policy_file)

    def _ensure_audit_init(self):
        """lazy 初始化（首次访问时读取环境变量）。"""
        if not hasattr(self, 'audit_enabled_flag'):
            policy_file = os.environ.get('AUDIT_POLICY_FILE') or None
            self._init_audit(policy_file)
            if os.environ.get('AUDIT_ENABLED') in ('1', 'true', 'True', 'yes'):
                self.audit_enabled_flag = True
            mode = os.environ.get('AUDIT_MODE', 'block')
            if mode in ('block', 'approve'):
                self.audit_mode = mode
            if self.audit_enabled_flag:
                logger.info(
                    '输出审计启用: mode=%s policy=%s',
                    self.audit_mode,
                    policy_file or '(default)',
                )

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
                    return 'deny'
        # allow 名单（精确匹配）
        if name in self.policy.get('allow', []):
            return 'allow'
        return 'allow'

    def audit_precheck(self, name: str, args_prefix: str) -> bool:
        """预检（design D4）：同步廉价前缀匹配，判定前暂停 flush。

        返回 True = 可疑（需暂停）。
        """
        if not self.audit_enabled():
            return False
        # tool 名命中危险前缀
        if name in _DANGEROUS_PREFIXES or name in ('curl', 'wget', 'nc'):
            return True
        # 参数前缀含危险命令（如 'rm' 是 'rm -rf' 的前缀）
        for prefix in _DANGEROUS_PREFIXES:
            if args_prefix.lstrip().startswith(prefix):
                return True
        return False


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
