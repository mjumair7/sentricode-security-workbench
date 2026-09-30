from __future__ import annotations

import hashlib
from bisect import bisect_right
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

MAX_FINDINGS_PER_FILE = 500


class AnalysisLimit(ValueError):
    """Input exceeded a documented analysis budget; report incomplete coverage."""


SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
RISK = {'critical': 92, 'high': 75, 'medium': 50, 'low': 25, 'info': 5}
LANGUAGES = {'.py': 'Python', '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript', '.java': 'Java', '.go': 'Go', '.rs': 'Rust', '.cs': 'C#', '.c': 'C', '.h': 'C', '.cpp': 'C++', '.sql': 'SQL', '.yaml': 'YAML', '.yml': 'YAML', '.json': 'JSON', '.tf': 'Terraform', '.hcl': 'Terraform', '.toml': 'TOML', '.sh': 'Shell'}
SECRET_NAME = r'(?:[\w.-]{0,100}(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret|credential)[\w.-]{0,100}|token)'
ASSIGNMENT = re.compile(r'(?i)(\b[\"\']?'+SECRET_NAME+r'[\"\']?\s*[:=]\s*)([\"\'])([^\r\n]{0,8192}?)\2')
ENV_ASSIGNMENT = re.compile(r'(?im)^[ \t]*('+SECRET_NAME+r'\s*=\s*)([^\s\"\'#$][^\r\n#]*)')
PATTERNS = [
    ('SC-SECRET-002', 'Cloud access key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('SC-SECRET-003', 'GitHub token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b')),
    ('SC-SECRET-004', 'Service API token', re.compile(r'\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{15,})\b')),
    ('SC-SECRET-005', 'Encoded access token', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')),
]
PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|\Z)')
URL_CREDENTIAL = re.compile(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|https?)://[^\s:/]+:([^\s@]+)@')
PII = re.compile(r'(?i)\b(?:password|passwd|ssn|sin|passport_number|credit_card|card_number|cvv|date_of_birth|medical_record|patient_id|bank_account|access_token|api_key|secret)\b')


def placeholder(value: str) -> bool:
    value = value.strip()
    return not value or len(value) < 5 or bool(re.fullmatch(r'(?i)(?:x+|\*+|\.+|<[^>]+>|\$\{[^}]+\}|\{\{.*\}\}|(?:your|insert|replace|example|dummy|test|placeholder|changeme|redacted|none|null)[-_ ].*|changeme|redacted|example|dummy|password|secret|true|false)', value))


def secret_pattern(secrets: set[str] | None):
    if not secrets:
        return None
    if sum(map(len, secrets)) > 512*1024:
        raise AnalysisLimit('Known-secret redaction budget exceeded')
    return re.compile('|'.join(re.escape(value) for value in sorted(secrets, key=len, reverse=True) if value))


def redact(text: Any, secrets=None) -> str:
    result = str(text)
    matcher = secret_pattern(secrets) if isinstance(secrets, set) else secrets
    if matcher is not None:
        result = matcher.sub('[REDACTED]', result)
    result = PRIVATE_KEY.sub('[REDACTED PRIVATE KEY]', result)
    for _, _, pattern in PATTERNS:
        result = pattern.sub('[REDACTED]', result)
    result = ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + '[REDACTED]' + m.group(2), result)
    result = ENV_ASSIGNMENT.sub(lambda m: m.group(1) + '[REDACTED]', result)
    result = URL_CREDENTIAL.sub(lambda m: m.group(0).replace(m.group(1), '[REDACTED]'), result)
    return result


def sanitize(value: Any, secrets: set[str] | None = None) -> Any:
    matcher = secret_pattern(secrets)
    def walk(item):
        if isinstance(item, str):
            return redact(item, matcher)
        if isinstance(item, list):
            return [walk(child) for child in item]
        if isinstance(item, dict):
            return {redact(key, matcher) if isinstance(key, str) else key: walk(child) for key, child in item.items()}
        return item
    return walk(value)


def language(path: str) -> str:
    return 'Dockerfile' if Path(path).name.lower().startswith('dockerfile') else LANGUAGES.get(Path(path).suffix.lower(), 'Text')


def score(finding: dict) -> int:
    risk = RISK.get(finding['severity'], 50) * (0.8 + 0.2 * finding.get('confidence', 0.7))
    if finding.get('epss') is not None:
        risk += min(8, float(finding['epss']) * 8)
    if finding.get('kev') is True:
        risk += 12
    return min(100, round(risk))


def finding(rule_id: str, title: str, severity: str, category: str, path: str, line: int, evidence: str, description: str, remediation: str, *, scanner='SentriCode', cwe=None, confidence=0.85, data_flow=None, **extra) -> dict:
    evidence = redact(evidence).strip()[:1800]
    # Moving a finding down a file should not invalidate an accepted CI baseline.
    normalized = re.sub(r'\s+', ' ', evidence).strip()
    fingerprint = hashlib.sha256(f'{rule_id}\0{path}\0{normalized}'.encode()).hexdigest()[:32]
    item = {'id': fingerprint, 'fingerprint': fingerprint, 'rule_id': rule_id, 'title': title,
        'description': description, 'severity': severity, 'category': category, 'scanner': scanner,
        'file': path, 'line_start': max(1, line), 'line_end': max(1, line), 'language': language(path),
        'confidence': confidence, 'cwe': cwe, 'owasp': None, 'cvss': None, 'cve': None, 'epss': None,
        'kev': None, 'status': 'open', 'evidence': evidence, 'remediation': remediation,
        'references': [f'https://cwe.mitre.org/data/definitions/{cwe.split("-")[-1]}.html'] if cwe else [],
        'data_flow': data_flow or [], 'package': None}
    item.update(extra)
    item['sentri_score'] = score(item)
    return item


def secret_findings(path: str, source: str) -> tuple[list[dict], set[str]]:
    matches: list[tuple[int, str, str, str]] = []
    def add(start, value, rule, title):
        if len(matches) >= MAX_FINDINGS_PER_FILE or len(value) > 8192:
            raise AnalysisLimit('Secret match budget exceeded')
        matches.append((start, value, rule, title))
    for rule_id, title, pattern in PATTERNS:
        for match in pattern.finditer(source):
            add(match.start(), match.group(), rule_id, title)
    for match in PRIVATE_KEY.finditer(source):
        add(match.start(), match.group(), 'SC-SECRET-006', 'Private key committed to source')
    assignment_patterns = [(ASSIGNMENT, 3), (URL_CREDENTIAL, 1)]
    if Path(path).name.startswith('.env') or Path(path).suffix in ('.env', '.ini', '.properties', '.conf'):
        assignment_patterns.append((ENV_ASSIGNMENT, 2))
    for pattern, group in assignment_patterns:
        for match in pattern.finditer(source):
            value = match.group(group).strip()
            if not placeholder(value):
                add(match.start(), value, 'SC-SECRET-001', 'Hardcoded credential')
    secrets = {value for _, value, _, _ in matches}
    results, seen = [], set()
    matcher = secret_pattern(secrets)
    newlines = [match.start() for match in re.finditer('\n', source)]
    lines = source.splitlines()
    for start, value, rule_id, title in matches:
        line = bisect_right(newlines, start) + 1
        if (line, value) in seen:
            continue
        seen.add((line, value))
        results.append(finding(rule_id, title, 'critical' if rule_id == 'SC-SECRET-006' else 'high', 'secrets', path, line, redact(lines[line-1], matcher),
            'A credential-shaped literal is stored in a source file. Pattern matching cannot establish whether it is active.',
            'If this is a real credential, revoke and rotate it first. Remove it from source and history, then load it from an environment variable or a secret manager.',
            cwe='CWE-798', confidence=0.96 if rule_id != 'SC-SECRET-001' else 0.8, owasp='A07:2025 Authentication Failures'))
    return results, secrets


def summary(findings: list[dict]) -> dict:
    counts = Counter(item['severity'] for item in findings)
    # A transparent posture indicator; neither exploit prediction nor a safety guarantee.
    penalty = sum({'critical': 18, 'high': 9, 'medium': 3, 'low': 1, 'info': 0}[item['severity']] for item in findings)
    return {'total': len(findings), **{level: counts[level] for level in SEVERITIES}, 'score': max(0, 100-penalty)}
