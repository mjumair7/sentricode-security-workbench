from __future__ import annotations

import ast
import re
from bisect import bisect_right

from .common import PII, finding, AnalysisLimit, MAX_FINDINGS_PER_FILE


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + '.' + node.attr
    return ''


def literal(node: ast.AST | None, value) -> bool:
    return isinstance(node, ast.Constant) and node.value == value


class PythonAnalyzer(ast.NodeVisitor):
    """Small intraprocedural tracker: assignments, explicit input sources and sinks.

    It deliberately makes no interprocedural, sanitizer or reachability claims.
    """

    def __init__(self, path: str, source: str):
        self.path, self.source = path, source
        self.lines = source.splitlines()
        self.findings: list[dict] = []
        self.aliases: dict[str, str] = {}
        self.flows: dict[str, list[dict]] = {}
        self.dynamic: set[str] = set()
        self.sensitive: set[str] = set()

    def name(self, node: ast.AST) -> str:
        raw = dotted(node)
        head, _, tail = raw.partition('.')
        return self.aliases.get(head, head) + ('.' + tail if tail else '')

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f'{node.module}.{alias.name}'

    def flow(self, node: ast.AST) -> list[dict]:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.flows:
                return self.flows[child.id]
            name = self.name(child.func) if isinstance(child, ast.Call) else self.name(child)
            if name in ('input', 'sys.argv') or re.search(r'\b(?:request|req)\.(?:args|form|json|GET|POST|query_params|cookies|headers|data|files)', name):
                return [{'label': 'User input: ' + name, 'kind': 'source', 'file': self.path, 'line': getattr(child, 'lineno', 1)}]
        return []

    def is_dynamic(self, node: ast.AST) -> bool:
        return isinstance(node, (ast.JoinedStr, ast.BinOp)) or (isinstance(node, ast.Call) and self.name(node.func).endswith('.format')) or any(isinstance(child, ast.Name) and child.id in self.dynamic for child in ast.walk(node))

    def is_sensitive(self, node: ast.AST) -> bool:
        return any(PII.search(self.name(child)) or isinstance(child, ast.Name) and child.id in self.sensitive for child in ast.walk(node))

    def visit_Assign(self, node):
        flow = self.flow(node.value)
        dynamic = self.is_dynamic(node.value)
        sensitive = self.is_sensitive(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.flows.pop(target.id, None)
                self.dynamic.discard(target.id)
                self.sensitive.discard(target.id)
                if flow:
                    self.flows[target.id] = flow[:15] + [{'label': 'Assigned to ' + target.id, 'kind': 'transform', 'file': self.path, 'line': node.lineno}]
                if dynamic:
                    self.dynamic.add(target.id)
                if sensitive:
                    self.sensitive.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            synthetic = ast.Assign(targets=[node.target], value=node.value, lineno=node.lineno)
            self.visit_Assign(synthetic)

    def visit_FunctionDef(self, node):
        saved = (self.flows, self.dynamic, self.sensitive, self.aliases)
        self.flows, self.dynamic, self.sensitive, self.aliases = {}, set(), set(), self.aliases.copy()
        for statement in node.body:
            self.visit(statement)
        self.flows, self.dynamic, self.sensitive, self.aliases = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def emit(self, node, rule_id, title, severity, cwe, description, remediation, category='sast', trace=None):
        if len(self.findings) >= MAX_FINDINGS_PER_FILE:
            raise AnalysisLimit('Per-file finding budget exceeded')
        data_flow = self.flow(trace or node)
        if data_flow:
            data_flow = data_flow + [{'label': title, 'kind': 'sink', 'file': self.path, 'line': node.lineno}]
        self.findings.append(finding(rule_id, title, severity, category, self.path, node.lineno,
            '\n'.join(self.lines[node.lineno-1:min(getattr(node, 'end_lineno', node.lineno), node.lineno+3)]),
            description, remediation, cwe=cwe, data_flow=data_flow,
            confidence=0.95 if data_flow else 0.8, owasp='A05:2025 Injection' if cwe in ('CWE-78', 'CWE-89', 'CWE-94', 'CWE-79') else None))

    def visit_Call(self, node):
        name = self.name(node.func)
        kwargs = {item.arg: item.value for item in node.keywords}
        arg = node.args[0] if node.args else None
        if name in ('eval', 'exec', 'builtins.eval', 'builtins.exec'):
            self.emit(node, 'SC-PY-001', 'Dynamic code execution', 'high', 'CWE-94', 'This call interprets text as Python code. Review the origin of every value reaching it.', 'Replace eval/exec with an explicit operation map or a strict data parser.')
        if name in ('os.system', 'os.popen') or name.startswith('subprocess.') and literal(kwargs.get('shell'), True):
            self.emit(node, 'SC-PY-002', 'Shell command execution', 'high', 'CWE-78', 'Shell interpretation can turn untrusted input into additional commands.', 'Pass an argument list to subprocess.run with shell=False. Validate each argument and avoid invoking a shell.', trace=arg)
        if name in ('pickle.load', 'pickle.loads', 'dill.load', 'dill.loads', 'marshal.loads'):
            self.emit(node, 'SC-PY-003', 'Unsafe object deserialization', 'high', 'CWE-502', 'Deserializing a Python object can execute code. The format is unsuitable for untrusted input.', 'Use JSON or another data-only format with schema validation. Only load trusted, integrity-verified artifacts.')
        if name in ('yaml.load', 'yaml.unsafe_load') and self.name(kwargs.get('Loader', ast.Constant(None))) not in ('yaml.SafeLoader', 'yaml.CSafeLoader', 'SafeLoader', 'CSafeLoader'):
            self.emit(node, 'SC-PY-004', 'Unsafe YAML loader', 'high', 'CWE-502', 'An unsafe or unspecified YAML loader can construct arbitrary Python objects.', 'Use yaml.safe_load, or explicitly choose yaml.SafeLoader.')
        if name.endswith(('.execute', '.executemany', '.raw')) and arg is not None and self.is_dynamic(arg):
            self.emit(node, 'SC-PY-005', 'SQL built with string interpolation', 'high', 'CWE-89', 'The query is assembled as a string before it reaches the database. Review whether user input can change its SQL structure.', 'Use database parameter binding for values. For identifiers, use an explicit allowlist.', trace=arg)
        if name.startswith(('requests.', 'httpx.')) and literal(kwargs.get('verify'), False):
            self.emit(node, 'SC-PY-006', 'TLS verification disabled', 'high', 'CWE-295', 'Disabling certificate validation permits an intermediary to impersonate the destination.', 'Keep certificate verification enabled and configure a trusted CA bundle when necessary.')
        if name.startswith(('requests.', 'httpx.', 'urllib.request.')) and arg is not None and self.flow(arg):
            self.emit(node, 'SC-PY-007', 'User input reaches an outbound request', 'medium', 'CWE-918', 'An input-derived destination reaches an HTTP request. This local trace cannot establish whether a surrounding allowlist exists.', 'Allowlist destination hosts and schemes, resolve and reject internal IP ranges, and validate redirects.', trace=arg)
        if name in ('open', 'io.open', 'send_file', 'flask.send_file') and arg is not None and self.flow(arg):
            self.emit(node, 'SC-PY-008', 'User input reaches a filesystem path', 'medium', 'CWE-22', 'An input-derived path reaches file access. Confirm that access is confined to an intended directory.', 'Resolve against a fixed base directory and reject paths outside it; prefer server-generated identifiers.', trace=arg)
        if name.startswith('hashlib.') and name.rsplit('.', 1)[-1] in ('md5', 'sha1'):
            self.emit(node, 'SC-CRYPTO-001', 'Weak cryptographic hash', 'low', 'CWE-327', 'MD5 and SHA-1 are unsuitable where collision resistance is required. Non-security checksums may be acceptable.', 'Use SHA-256 for integrity and a dedicated password hasher such as Argon2id for passwords.')
        if name.endswith('.run') and literal(kwargs.get('debug'), True):
            self.emit(node, 'SC-PY-009', 'Debug mode enabled', 'medium', 'CWE-489', 'A debug server may expose diagnostic information or an interactive debugger.', 'Disable debug mode outside local development; serve production applications through a production server.')
        if name in ('jwt.decode', 'jose.jwt.decode'):
            options = kwargs.get('options')
            disabled = literal(kwargs.get('verify'), False) or isinstance(options, ast.Dict) and any(literal(k, 'verify_signature') and literal(v, False) for k, v in zip(options.keys, options.values))
            if disabled:
                self.emit(node, 'SC-API-001', 'JWT signature verification disabled', 'critical', 'CWE-347', 'The decoded claims are not authenticated when signature verification is disabled.', 'Verify signatures with an explicit algorithm allowlist and trusted keys; validate issuer, audience and expiry.')
        if (name == 'print' or re.search(r'(?:logger|logging|log)\.(?:debug|info|warning|warn|error|exception|critical)$', name)) and any(self.is_sensitive(arg) for arg in node.args):
            self.emit(node, 'SC-DATA-001', 'Sensitive value reaches application logs', 'high', 'CWE-532', 'A sensitive attribute or a locally assigned alias is passed to a logging sink. Logs often have broader access and retention than application data.', 'Remove the sensitive value, log a non-sensitive event identifier, or apply a field allowlist before logging.', category='privacy')
        self.generic_visit(node)


def python_findings(path: str, source: str) -> list[dict]:
    analyzer = PythonAnalyzer(path, source)
    tree = ast.parse(source, filename=path)
    if sum(1 for _ in ast.walk(tree)) > 50000:
        raise AnalysisLimit('Python AST node budget exceeded')
    analyzer.visit(tree)
    return analyzer.findings


JS_RULES = [
    ('SC-JS-001', r'\b(?:eval|new\s+Function)\s*\(', 'Dynamic JavaScript execution', 'high', 'CWE-94', 'Source text is interpreted as executable JavaScript.', 'Use structured data parsing or an explicit operation map.'),
    ('SC-JS-002', r'(?:\b(?:exec|execSync)\s*\(|\bchild_process\s*\.\s*exec(?:Sync)?\s*\()', 'Shell command execution', 'high', 'CWE-78', 'This API executes a command through a shell. Check whether interpolated input can reach the command.', 'Use execFile or spawn with an argument array and shell disabled.'),
    ('SC-JS-003', r'\.innerHTML\s*=|dangerouslySetInnerHTML\s*=', 'HTML injection sink', 'medium', 'CWE-79', 'Raw HTML reaches a rendering sink. This pattern check cannot prove whether the value was sanitized.', 'Use textContent or normal escaped JSX. If HTML is essential, sanitize it with a maintained allowlist-based sanitizer.'),
    ('SC-JS-004', r'\b(?:query|execute)\s*\(\s*(?:`[^`]{0,4096}\$\{|[\"\'][^\n]{0,4096}[\"\']\s*\+)', 'Interpolated database query', 'high', 'CWE-89', 'A query appears to contain string interpolation or concatenation.', 'Bind values with the database driver parameter API, and allowlist dynamic identifiers.'),
    ('SC-JS-005', r'rejectUnauthorized\s*:\s*false', 'TLS verification disabled', 'high', 'CWE-295', 'The connection accepts an unverified TLS certificate.', 'Remove rejectUnauthorized:false and configure the expected CA bundle.'),
    ('SC-JS-006', r'\b(?:createHash)\s*\(\s*[\"\'](?:md5|sha1)[\"\']', 'Weak cryptographic hash', 'low', 'CWE-327', 'This hash is unsuitable for collision-resistant security checks.', 'Use SHA-256 for integrity or Argon2id for password hashing.'),
    ('SC-API-002', r'\bjwt\.decode\s*\(', 'JWT decoded without verification', 'medium', 'CWE-347', 'Decoding a JWT does not authenticate claims. This is a review finding; decoding may be intentional for display.', 'Use jwt.verify with explicit algorithms, issuer and audience before trusting claims.'),
]


def javascript_findings(path: str, source: str) -> list[dict]:
    results = []
    lines = source.splitlines()
    newlines = [match.start() for match in re.finditer('\n', source)]
    # These are lexical checks, not a JavaScript parser or cross-file taint engine.
    for rule, pattern, title, severity, cwe, description, remediation in JS_RULES:
        for match in re.finditer(pattern, source):
            line = bisect_right(newlines, match.start()) + 1
            if lines[line-1].lstrip().startswith(('//', '*')):
                continue
            if len(results) >= MAX_FINDINGS_PER_FILE:
                raise AnalysisLimit('Per-file finding budget exceeded')
            results.append(finding(rule, title, severity, 'sast', path, line, lines[line-1], description + ' JavaScript checks are lexical and need review.', remediation, cwe=cwe, confidence=0.7))
    for match in re.finditer(r'\b(?:console|logger|log)\.(?:log|info|warn|error|debug)\s*\(([^;\n]{0,1000})', source):
        if PII.search(match.group(1)):
            line = bisect_right(newlines, match.start()) + 1
            if len(results) >= MAX_FINDINGS_PER_FILE:
                raise AnalysisLimit('Per-file finding budget exceeded')
            results.append(finding('SC-DATA-001', 'Sensitive value reaches application logs', 'high', 'privacy', path, line, lines[line-1], 'A sensitive field name appears in a logging call. This lexical check cannot establish runtime values.', 'Remove sensitive values from the log payload or select an explicit allowlist of safe fields.', cwe='CWE-532', confidence=0.8,
                data_flow=[{'label': 'Sensitive field reference', 'kind': 'source', 'file': path, 'line': line}, {'label': 'Logging call (lexical match)', 'kind': 'sink', 'file': path, 'line': line}]))
    return results


def config_findings(path: str, source: str) -> list[dict]:
    results = []
    rules = [
        ('SC-IAC-001', r'(?im)^[ \t]*(?:privileged\s*:\s*true|privileged\s*=\s*true)', 'Privileged container', 'high', 'CWE-250', 'Privileged containers receive extensive host capabilities.', 'Remove privileged mode and grant only the capabilities the workload needs.'),
        ('SC-IAC-002', r'(?im)(?:cidr_blocks\s*=.*[\"\']0\.0\.0\.0/0|cidr_ip\s*[:=]\s*[\"\']?0\.0\.0\.0/0)', 'Network rule open to the internet', 'medium', 'CWE-284', 'An unrestricted IPv4 range appears in an infrastructure rule. Check the resource, ports and direction.', 'Restrict ingress to the smallest required source ranges and ports.'),
        ('SC-IAC-003', r'(?im)^[ \t]*(?:runAsUser\s*:\s*0|runAsNonRoot\s*:\s*false|USER\s+(?:root|0)(?:\s|$))', 'Container explicitly runs as root', 'medium', 'CWE-250', 'The configuration explicitly selects the root user.', 'Create a dedicated user and run the workload without root privileges.'),
        ('SC-IAC-004', r'(?im)^[ \t]*(?:permissions\s*:\s*write-all)', 'Broad GitHub Actions permissions', 'medium', 'CWE-269', 'The workflow grants write access across all token permission scopes.', 'Set permissions to contents:read at workflow level and grant specific write scopes only to jobs that need them.'),
        ('SC-IAC-005', r'(?im)^[ \t]*(?:acl\s*=\s*[\"\']public-read(?:-write)?[\"\']|publicly_accessible\s*=\s*true)', 'Public cloud resource', 'high', 'CWE-284', 'This configuration explicitly enables public access.', 'Disable public access unless it is an intended, reviewed requirement and add explicit access controls.'),
        ('SC-IAC-006', r'(?im)^[ \t]*(?:allowPrivilegeEscalation\s*:\s*true|readOnlyRootFilesystem\s*:\s*false)', 'Weak container security context', 'medium', 'CWE-250', 'The workload explicitly relaxes a container security control.', 'Disable privilege escalation and use a read-only root filesystem with dedicated writable volumes.'),
    ]
    lines = source.splitlines()
    newlines = [match.start() for match in re.finditer('\n', source)]
    for rule, pattern, title, severity, cwe, description, remediation in rules:
        for match in re.finditer(pattern, source):
            line = bisect_right(newlines, match.start()) + 1
            if len(results) >= MAX_FINDINGS_PER_FILE:
                raise AnalysisLimit('Per-file finding budget exceeded')
            results.append(finding(rule, title, severity, 'iac', path, line, lines[line-1], description, remediation, cwe=cwe, confidence=0.9, owasp='A02:2025 Security Misconfiguration'))
    if path.rsplit('/', 1)[-1].lower().startswith('dockerfile'):
        # Inspect the final stage; an earlier USER does not protect a later FROM.
        stages = re.split(r'(?im)^[ \t]*FROM\s+', source)
        final = stages[-1]
        if len(stages) > 1 and not re.search(r'(?im)^[ \t]*USER\s+\S+', final):
            line = max(i for i, text in enumerate(lines, 1) if re.match(r'(?i)^\s*FROM\s+', text))
            if len(results) >= MAX_FINDINGS_PER_FILE:
                raise AnalysisLimit('Per-file finding budget exceeded')
            results.append(finding('SC-IAC-007', 'Final image has no explicit non-root user', 'low', 'iac', path, line, lines[line-1], 'No USER instruction is present in the final stage. The base image may provide one; verify its default.', 'Set a dedicated non-root USER in the final image stage.', cwe='CWE-250', confidence=0.65))
    return results
