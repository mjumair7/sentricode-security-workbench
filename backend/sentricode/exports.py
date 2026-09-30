from __future__ import annotations

import csv
import io
from urllib.parse import quote

from .analysis.common import sanitize


def to_sarif(report: dict) -> dict:
    report = sanitize(report)
    rules, indices, results = [], {}, []
    for item in report.get('findings', []):
        rule_id = item['rule_id']
        if rule_id not in indices:
            indices[rule_id] = len(rules)
            rule = {'id': rule_id, 'shortDescription': {'text': item['title']}, 'fullDescription': {'text': item['description']},
                'help': {'text': item['remediation']}, 'properties': {'tags': list(filter(None, ['security', item.get('category'), item.get('cwe')])), 'precision': 'high' if item.get('confidence', 0) >= .9 else 'medium'}}
            if item.get('cvss') is not None:
                rule['properties']['security-severity'] = str(item['cvss'])
            if item.get('references'):
                rule['helpUri'] = item['references'][0]
            rules.append(rule)
        level = 'error' if item['severity'] in ('critical', 'high') else 'warning' if item['severity'] == 'medium' else 'note'
        location = {'physicalLocation': {'artifactLocation': {'uri': quote(item['file'].replace('\\', '/'), safe='/'), 'uriBaseId': '%SRCROOT%'}, 'region': {'startLine': max(1, item['line_start']), 'endLine': max(item['line_start'], item.get('line_end', item['line_start']))}}}
        results.append({'ruleId': rule_id, 'ruleIndex': indices[rule_id], 'level': level, 'message': {'text': item['description']}, 'locations': [location],
            'partialFingerprints': {'sentricode/v1': item['fingerprint']}, 'properties': {'severity': item['severity'], 'sentri_score': item.get('sentri_score'), 'scanner': item.get('scanner'), 'status': item.get('status', 'open')}})
    failures = [e for e in report.get('engines', []) if e['status'] == 'failed']
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'SentriCode', 'version': '0.1.0', 'informationUri': 'https://owasp.org/www-community/Source_Code_Analysis_Tools', 'rules': rules}},
        'invocations': [{'executionSuccessful': not failures, 'toolExecutionNotifications': [{'level': 'error', 'message': {'text': e['name']+': '+e['message']}} for e in failures]}],
        'results': results}]}


def to_csv(report: dict) -> str:
    fields = ['fingerprint', 'rule_id', 'title', 'severity', 'category', 'scanner', 'file', 'line_start', 'cwe', 'cve', 'cvss', 'epss', 'kev', 'sentri_score', 'status', 'remediation']
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for item in sanitize(report).get('findings', []):
        values = {}
        for key in fields:
            value = item.get(key, '')
            if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
                value = "'"+value  # Stop formulas when a report is opened in a spreadsheet.
            values[key] = value
        writer.writerow(values)
    return stream.getvalue()
