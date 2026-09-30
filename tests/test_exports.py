import csv
import io
import json

from sentricode.analysis.common import finding
from sentricode.exports import to_csv, to_sarif


def example(**overrides):
    item = finding('SC-EXAMPLE-001', 'Example', 'high', 'sast', 'src/my file.py', 7, 'eval(data)', 'Untrusted code execution', 'Replace eval with a parser', cwe='CWE-94')
    item.update(overrides)
    return {'findings': [item], 'engines': [{'name': 'test', 'status': 'completed', 'message': 'done'}]}


def test_sarif_location_rules_fingerprints_and_failure_status():
    report = example()
    data = to_sarif(report)
    run = data['runs'][0]
    result = run['results'][0]
    assert data['version'] == '2.1.0'
    assert result['locations'][0]['physicalLocation']['region']['startLine'] == 7
    assert result['locations'][0]['physicalLocation']['artifactLocation']['uri'] == 'src/my%20file.py'
    assert result['partialFingerprints']['sentricode/v1'] == report['findings'][0]['fingerprint']
    assert result['ruleIndex'] == 0
    assert run['tool']['driver']['rules'][0]['id'] == result['ruleId']
    assert run['invocations'][0]['executionSuccessful'] is True
    report['engines'][0]['status'] = 'failed'
    assert to_sarif(report)['runs'][0]['invocations'][0]['executionSuccessful'] is False


def test_exports_apply_redaction_as_defense_in_depth():
    token = 'ghp_'+'a'*36
    report = example(description='Bearer '+token, title='token = "unredacted-fixture-293872"')
    assert token not in json.dumps(to_sarif(report))
    assert 'unredacted-fixture-293872' not in to_csv(report)


def test_csv_prevents_formula_injection_and_preserves_rows():
    data = to_csv(example(title='=HYPERLINK("https://example.com")', file='@malicious.py'))
    rows = list(csv.DictReader(io.StringIO(data)))
    assert len(rows) == 1
    assert rows[0]['title'].startswith("'=")
    assert rows[0]['file'].startswith("'@")
    assert rows[0]['line_start'] == '7'


def test_sarif_deduplicates_rule_metadata():
    report = example()
    report['findings'].append(dict(report['findings'][0], file='another.py'))
    assert len(to_sarif(report)['runs'][0]['tool']['driver']['rules']) == 1
