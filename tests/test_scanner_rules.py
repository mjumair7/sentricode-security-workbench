"""Vulnerable/safe pairs exercise actual analyzers, not implementation mirrors."""
import json
from pathlib import Path

import pytest

from sentricode.scanner import scan_directory
from sentricode.analysis.common import redact, secret_findings
from sentricode.analysis.sast import python_findings, javascript_findings, config_findings


@pytest.mark.parametrize('source,rule,cwe,line', [
    ('eval(input())', 'SC-PY-001', 'CWE-94', 1),
    ('import subprocess as sp\nsp.run(input(), shell=True)', 'SC-PY-002', 'CWE-78', 2),
    ('from pickle import loads as decode\ndecode(blob)', 'SC-PY-003', 'CWE-502', 2),
    ('import yaml\nyaml.load(payload)', 'SC-PY-004', 'CWE-502', 2),
    ('cursor.execute(f"SELECT * FROM t WHERE x={value}")', 'SC-PY-005', 'CWE-89', 1),
    ('import requests\nrequests.get(url, verify=False)', 'SC-PY-006', 'CWE-295', 2),
    ('import requests\nurl = request.args.get("url")\nrequests.get(url)', 'SC-PY-007', 'CWE-918', 3),
    ('filename = input()\nopen(filename)', 'SC-PY-008', 'CWE-22', 2),
    ('import hashlib\nhashlib.md5(data)', 'SC-CRYPTO-001', 'CWE-327', 2),
    ('app.run(debug=True)', 'SC-PY-009', 'CWE-489', 1),
    ('import jwt\njwt.decode(token, options={"verify_signature":False})', 'SC-API-001', 'CWE-347', 2),
    ('logger.info(user.ssn)', 'SC-DATA-001', 'CWE-532', 1),
])
def test_python_known_vulnerabilities(source, rule, cwe, line):
    found = [item for item in python_findings('app.py', source) if item['rule_id'] == rule]
    assert len(found) == 1
    assert found[0]['cwe'] == cwe
    assert found[0]['line_start'] == line
    assert found[0]['file'] == 'app.py'


@pytest.mark.parametrize('source', [
    'import subprocess\nsubprocess.run(["ls", filename], shell=False)',
    'import yaml\nyaml.safe_load(payload)',
    'import yaml as y\ny.load(payload, Loader=y.SafeLoader)',
    'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
    'import requests\nrequests.get("https://example.com", verify=True)',
    'logger.info(user.display_name)',
    'import hashlib\nhashlib.sha256(data)',
    'import jwt\njwt.decode(token, key, algorithms=["RS256"])',
    'app.run(debug=False)',
])
def test_python_safe_pairs(source):
    assert not python_findings('safe.py', source)


def test_trace_tracks_aliases_without_cross_function_leakage():
    source = '''import subprocess

def route():
    command = request.args.get('cmd')
    alias = command
    subprocess.run(alias, shell=True)

def other():
    subprocess.run(command, shell=True)
'''
    findings = python_findings('app.py', source)
    first, second = [item for item in findings if item['rule_id'] == 'SC-PY-002']
    assert [node['kind'] for node in first['data_flow']] == ['source', 'transform', 'transform', 'sink']
    assert first['data_flow'][0]['line'] == 4
    assert not second['data_flow']


def test_reassignment_clears_taint_and_tracks_sensitive_alias():
    source = '''import requests
url = input()
url = 'https://example.com'
requests.get(url)
safe_name = user.ssn
logger.info(safe_name)
'''
    findings = python_findings('app.py', source)
    assert [item['rule_id'] for item in findings] == ['SC-DATA-001']


@pytest.mark.parametrize('source,rule', [
    ('eval(req.body.code);', 'SC-JS-001'),
    ('child_process.exec(command);', 'SC-JS-002'),
    ('element.innerHTML = userInput;', 'SC-JS-003'),
    ('db.query(`SELECT * FROM t WHERE id=${id}`);', 'SC-JS-004'),
    ('const options = {rejectUnauthorized:false};', 'SC-JS-005'),
    ('crypto.createHash("md5");', 'SC-JS-006'),
    ('jwt.decode(token);', 'SC-API-002'),
    ('console.log(user.password);', 'SC-DATA-001'),
])
def test_js_review_findings(source, rule):
    assert rule in {item['rule_id'] for item in javascript_findings('app.ts', source)}


def test_js_safe_pair_and_comment():
    assert not javascript_findings('safe.ts', 'element.textContent = userInput;\nconsole.log(user.name);\n// eval(input);')


@pytest.mark.parametrize('path,source,rule', [
    ('compose.yml', 'privileged: true', 'SC-IAC-001'),
    ('main.tf', 'cidr_blocks = ["0.0.0.0/0"]', 'SC-IAC-002'),
    ('Dockerfile', 'FROM ubuntu:latest\nUSER root', 'SC-IAC-003'),
    ('.github/workflows/ci.yml', 'permissions: write-all', 'SC-IAC-004'),
    ('main.tf', 'acl = "public-read"', 'SC-IAC-005'),
    ('deployment.yml', 'allowPrivilegeEscalation: true', 'SC-IAC-006'),
    ('Dockerfile', 'FROM a\nUSER app\nFROM b\nCOPY --from=0 /app /app', 'SC-IAC-007'),
])
def test_configuration_rules(path, source, rule):
    assert rule in {item['rule_id'] for item in config_findings(path, source)}


def test_nonroot_final_stage_is_safe():
    assert 'SC-IAC-007' not in {item['rule_id'] for item in config_findings('Dockerfile', 'FROM a\nFROM b\nUSER 1000')}


@pytest.mark.parametrize('path,source,value', [
    ('app.py', 'API_KEY = "sensitive-realistic-value-98273"', 'sensitive-realistic-value-98273'),
    ('.env', 'DATABASE_PASSWORD=unquoted-credential-23984', 'unquoted-credential-23984'),
    ('config.json', '{"client_secret":"private-value-786523"}', 'private-value-786523'),
    ('config.yml', 'url: postgres://alice:DBpass4721@database/mydb', 'DBpass4721'),
    ('app.ts', 'const x = "ghp_abcdefghijklmnopqrstuvwxyz123456789012";', 'ghp_abcdefghijklmnopqrstuvwxyz123456789012'),
    ('key.pem', '-----BEGIN PRIVATE KEY-----\nABCD0123fakekey\n-----END PRIVATE KEY-----', 'ABCD0123fakekey'),
])
def test_secret_redaction_covers_entire_report(tmp_path, path, source, value):
    (tmp_path/path).write_text(source)
    report = scan_directory(tmp_path)
    assert any(item['category'] == 'secrets' for item in report['findings'])
    assert value not in json.dumps(report)
    assert '[REDACTED' in json.dumps(report)


def test_secret_on_same_line_as_sast_never_survives(tmp_path):
    secret = 'active-looking-value-591347'
    (tmp_path/'app.py').write_text(f'API_KEY = "{secret}"; eval(API_KEY)\n')
    report = scan_directory(tmp_path)
    assert len(report['findings']) == 2
    assert secret not in json.dumps(report)


@pytest.mark.parametrize('source', ['password = os.getenv("PASSWORD")', 'password = user.password', 'API_KEY = "your-api-key"', 'PASSWORD = "${PASSWORD}"', 'secret = "changeme"'])
def test_placeholders_and_dynamic_credentials_not_findings(source):
    assert not secret_findings('app.py', source)[0]


def test_redact_known_token_outside_assignment():
    value = 'sk-proj-'+'a'*45
    assert value not in redact('Bearer '+value)


def test_stable_fingerprints_survive_line_number_changes(tmp_path):
    path = tmp_path/'app.py'
    path.write_text('eval(input())\neval(input())\n')
    first = scan_directory(tmp_path)['findings']
    path.write_text('\n# shifted\neval(input())\n\neval(input())\n')
    second = scan_directory(tmp_path)['findings']
    assert len({item['fingerprint'] for item in first}) == 2
    assert {item['fingerprint'] for item in first} == {item['fingerprint'] for item in second}


def test_never_executes_input(tmp_path):
    marker = tmp_path/'executed'
    (tmp_path/'malicious.py').write_text(f'from pathlib import Path\nPath({str(marker)!r}).write_text("BAD")\neval(input())\n')
    scan_directory(tmp_path)
    assert not marker.exists()


def test_fixture_has_real_findings():
    report = scan_directory(Path(__file__).parents[1]/'examples'/'vulnerable-shop')
    assert {'sast', 'secrets', 'privacy', 'iac'} <= {item['category'] for item in report['findings']}
    assert report['dependencies'][0]['name'] == 'lodash'
    assert report['dependencies'][0]['version'] == '4.17.20'
