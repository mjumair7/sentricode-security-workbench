import json
import os
from pathlib import Path

import pytest

import sentricode.scanner as scanner
from sentricode.analysis.external import docker_command, normalize, run_external, tool_arguments


def test_symlink_and_vendor_exclusion(tmp_path):
    outside = tmp_path.parent/'outside-secret.py'
    outside.write_text('password = "do-not-read-outside-93485"')
    target = tmp_path/'project'
    target.mkdir()
    (target/'escape.py').symlink_to(outside)
    (target/'node_modules').mkdir()
    (target/'node_modules'/'vendor.js').write_text('eval(input)')
    (target/'safe.py').write_text('print("hello")')
    report = scanner.scan_directory(target)
    assert report['files_scanned'] == 1
    assert not report['findings']


def test_project_ignore_can_be_disabled_for_trusted_ci(tmp_path):
    (tmp_path/'app.py').write_text('eval(input())')
    (tmp_path/'.sentricodeignore').write_text('*.py\n')
    assert not scanner.scan_directory(tmp_path)['findings']
    assert scanner.scan_directory(tmp_path, respect_ignore=False)['findings']


def test_budget_exhaustion_is_operational_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, 'MAX_FILE_BYTES', 8)
    (tmp_path/'app.py').write_text('eval(input())')
    report = scanner.scan_directory(tmp_path)
    assert report['coverage']['limits_hit']
    assert report['engines'][0]['status'] == 'failed'


def test_total_and_count_budget_fail_closed(tmp_path, monkeypatch):
    (tmp_path/'a.py').write_text('pass')
    (tmp_path/'b.py').write_text('pass')
    monkeypatch.setattr(scanner, 'MAX_FILES', 1)
    assert scanner.scan_directory(tmp_path)['coverage']['limits_hit']
    monkeypatch.setattr(scanner, 'MAX_FILES', 10)
    monkeypatch.setattr(scanner, 'MAX_TOTAL_BYTES', 5)
    assert scanner.scan_directory(tmp_path)['coverage']['limits_hit']


def test_invalid_python_does_not_disable_secret_scan(tmp_path):
    (tmp_path/'bad.py').write_text('def broken(:\npassword = "sensitive-fixture-986723"')
    report = scanner.scan_directory(tmp_path)
    assert any(e['status'] == 'failed' and 'SAST' in e['name'] for e in report['engines'])
    assert report['findings'][0]['category'] == 'secrets'
    assert 'sensitive-fixture-986723' not in json.dumps(report)


def test_deep_and_history_never_claim_unrequested_coverage(tmp_path):
    (tmp_path/'app.py').write_text('pass')
    report = scanner.scan_directory(tmp_path, mode='deep', history=True)
    assert any(e['name'] == 'Git history' and e['status'] == 'failed' for e in report['engines'])
    assert any('Cross-file' in notice for notice in report['warnings'])


def test_docker_command_is_fixed_networkless_and_readonly(tmp_path):
    image = 'vendor/scanner@sha256:'+'a'*64
    command = docker_command('bandit', tmp_path, tmp_path/'rules', image)
    for flag in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pull=never', '--user=65534:65534', '--pids-limit=128', '--memory=1g'):
        assert flag in command
    assert any('target=/src,readonly' in item for item in command)
    assert all('docker.sock' not in item for item in command)
    assert '--entrypoint' in command
    with pytest.raises(ValueError):
        docker_command('bandit', tmp_path, tmp_path/'rules', 'vendor/scanner:latest')


def test_adapter_never_requests_builds_registry_rules_or_autofix():
    for tool in ('semgrep', 'bandit', 'gitleaks', 'checkov', 'trivy', 'syft'):
        arguments = tool_arguments(tool, '/source', '/trusted-rules')
        assert '--autofix' not in arguments
        assert '--allow-local-builds' not in arguments
        assert 'auto' not in arguments
    assert tool_arguments('gitleaks', '/src', '/rules', history=True)[0] == 'git'
    assert tool_arguments('trivy', '/src', '/rules')[0] == 'config'


def test_missing_external_tools_are_skipped(monkeypatch, tmp_path):
    monkeypatch.setattr('sentricode.analysis.external.shutil.which', lambda _: None)
    findings, engines, document = run_external(tmp_path)
    assert not findings and document is None
    assert len(engines) == 6
    assert all(engine['status'] == 'skipped' for engine in engines)


def test_external_gitleaks_discards_raw_secret_and_match_fields(tmp_path):
    records = [{'RuleID': 'github-pat', 'Description': 'GitHub token', 'File': str(tmp_path/'app.py'), 'StartLine': 2, 'Secret': 'leaked-very-private-value', 'Match': 'token=leaked-very-private-value', 'Commit': 'abc123'}]
    findings = normalize('gitleaks', records, tmp_path)
    assert findings[0]['file'] == 'app.py'
    assert findings[0]['line_start'] == 2
    assert findings[0]['commit'] == 'abc123'
    assert 'leaked-very-private-value' not in json.dumps(findings)


@pytest.mark.parametrize('tool,data,rule', [
    ('semgrep', {'results': [{'check_id': 'PY001', 'path': '/src/main.py', 'start': {'line': 3}, 'extra': {'message': 'Unsafe eval', 'severity': 'ERROR', 'lines': 'eval(data)', 'metadata': {'cwe': ['CWE-94']}}}]}, 'PY001'),
    ('bandit', {'results': [{'test_id': 'B301', 'filename': '/src/main.py', 'line_number': 2, 'issue_text': 'Pickle', 'issue_severity': 'HIGH', 'issue_cwe': {'id': 502}, 'code': 'pickle.loads(data)'}]}, 'B301'),
    ('checkov', [{'results': {'failed_checks': [{'check_id': 'CKV_1', 'check_name': 'Public bucket', 'file_path': '/main.tf', 'file_line_range': [4, 6], 'code_block': [[4, 'acl = "public-read"']]}]}}], 'CKV_1'),
    ('trivy', {'Results': [{'Target': '/src/Dockerfile', 'Misconfigurations': [{'ID': 'DS001', 'Title': 'Root user', 'Severity': 'HIGH', 'CauseMetadata': {'StartLine': 2}}]}]}, 'DS001'),
])
def test_external_report_normalization(tool, data, rule, tmp_path):
    findings = normalize(tool, data, tmp_path)
    assert len(findings) == 1
    assert findings[0]['rule_id'] == rule
    assert findings[0]['file'] in ('main.py', 'main.tf', 'Dockerfile')
    assert findings[0]['epss'] is None
    assert findings[0]['kev'] is None


def test_large_secret_fixture_fails_budget_without_leaking_or_hanging(tmp_path):
    import time
    source = '\n'.join(f'password_{i} = "private-value-{i:06d}-test"' for i in range(2000))
    (tmp_path/'many.py').write_text(source)
    started = time.monotonic()
    report = scanner.scan_directory(tmp_path)
    assert time.monotonic()-started < 5
    assert any(e['name'] == 'SecretGuard' and e['status'] == 'failed' for e in report['engines'])
    assert 'private-value-' not in json.dumps(report)
    assert any('budget exceeded' in notice for notice in report['warnings'])


def test_whole_scan_finding_budget_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, 'MAX_FINDINGS', 2)
    (tmp_path/'app.py').write_text('eval(a)\neval(b)\neval(c)\n')
    report = scanner.scan_directory(tmp_path)
    assert len(report['findings']) == 2
    assert any(e['name'] == 'Analysis budgets' and e['status'] == 'failed' for e in report['engines'])


def test_long_nonmatching_identifier_does_not_trigger_regex_backtracking(tmp_path):
    import time
    (tmp_path/'large.txt').write_text('a'*1_000_000)
    started = time.monotonic()
    report = scanner.scan_directory(tmp_path)
    assert time.monotonic()-started < 5
    assert not report['findings']


def test_long_assignment_chain_has_bounded_trace():
    from sentricode.analysis.sast import python_findings
    source = 'v0 = input()\n'+'\n'.join(f'v{i}=v{i-1}' for i in range(1, 1000))+'\nimport subprocess\nsubprocess.run(v999, shell=True)'
    findings = python_findings('chain.py', source)
    assert len(findings[0]['data_flow']) <= 17
