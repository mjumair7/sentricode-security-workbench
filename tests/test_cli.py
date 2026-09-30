import json

from sentricode.cli import main, evaluate_policy


def test_cli_report_policy_exit_codes_and_baseline(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'app.py').write_text('eval(input())')
    report = tmp_path/'report.json'
    baseline = tmp_path/'baseline.json'
    assert main(['scan', str(source), '--format', 'json', '--output', str(report), '--fail-on', 'critical,high']) == 1
    data = json.loads(report.read_text())
    assert data['policy']['passed'] is False
    assert main(['baseline', str(report), '-o', str(baseline)]) == 0
    assert main(['scan', str(source), '--format', 'json', '-o', str(report), '--fail-on', 'high', '--baseline', str(baseline)]) == 0
    (source/'app.py').write_text('eval(input())\nexec(input())')
    assert main(['scan', str(source), '--format', 'json', '-o', str(report), '--fail-on', 'high', '--baseline', str(baseline)]) == 1
    assert json.loads(report.read_text())['baseline'] == {'new': 1, 'resolved': 0, 'unchanged': 1}
    delta = tmp_path/'delta.json'
    assert main(['compare', str(report), '--baseline', str(baseline), '-o', str(delta)]) == 0
    assert len(json.loads(delta.read_text())['new']) == 1


def test_policy_thresholds_and_lifecycle():
    findings = [{'severity': 'high', 'category': 'sast'}, {'severity': 'high', 'category': 'sast', 'status': 'accepted_risk'}, {'severity': 'critical', 'category': 'secrets', 'status': 'resolved'}]
    assert evaluate_policy(findings, {'fail_on': ['high', 'critical'], 'max_high': 1, 'fail_on_secrets': True})['passed']
    assert not evaluate_policy(findings, {'fail_on': ['high'], 'max_high': 0})['passed']
    findings.append({'severity': 'low', 'category': 'secrets'})
    assert not evaluate_policy(findings, {'fail_on': [], 'fail_on_secrets': True})['passed']


def test_cli_operational_errors_not_confused_with_policy_failure(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'bad.py').write_text('def (:')
    output = tmp_path/'report.json'
    assert main(['scan', str(source), '--format', 'json', '-o', str(output)]) == 2
    assert main(['baseline', str(output), '-o', str(tmp_path/'baseline.json')]) == 2
    assert main(['scan', str(tmp_path/'absent')]) == 2


def test_missing_required_engine_is_operational_failure(tmp_path):
    (tmp_path/'safe.py').write_text('pass')
    assert main(['scan', str(tmp_path), '--require-engines', 'Semgrep']) == 2


def test_severity_output_filter_cannot_bypass_policy(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'app.py').write_text('eval(input())')
    output = tmp_path/'report.json'
    assert main(['scan', str(source), '--format', 'json', '-o', str(output), '--severity', 'critical', '--fail-on', 'high']) == 1
    data = json.loads(output.read_text())
    assert not data['findings']
    assert data['summary']['high'] == 1
    assert not data['policy']['passed']


def test_cli_policy_file_and_invalid_configuration(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'app.py').write_text('eval(input())')
    policy = tmp_path/'policy.yml'
    policy.write_text('fail_on: [high]\nmax_high: 1\nfail_on_secrets: true\n')
    assert main(['scan', str(source), '--policy', str(policy)]) == 0
    policy.write_text('fail_on: [surprise]')
    assert main(['scan', str(source), '--policy', str(policy)]) == 2
    policy.write_text('fail_on: [high]\nmax_high: -1')
    assert main(['scan', str(source), '--policy', str(policy)]) == 2
    assert main(['scan', str(source), '--fail-on', 'madeup']) == 2


def test_cli_trusted_ignore_and_sarif_output(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'app.py').write_text('eval(input())')
    (source/'.sentricodeignore').write_text('*')
    report = tmp_path/'scan.sarif'
    assert main(['scan', str(source), '--no-project-ignore', '--format', 'sarif', '-o', str(report), '--fail-on', 'high']) == 1
    assert json.loads(report.read_text())['runs'][0]['results'][0]['ruleId'] == 'SC-PY-001'


def test_baseline_rejects_invalid_shape(tmp_path):
    path = tmp_path/'invalid.json'
    path.write_text('{}')
    assert main(['baseline', str(path), '-o', str(tmp_path/'output.json')]) == 2


def test_malformed_yaml_policy_returns_operational_failure(tmp_path):
    policy = tmp_path/'policy.yml'
    policy.write_text('fail_on: [high')
    assert main(['scan', str(tmp_path), '--policy', str(policy)]) == 2
