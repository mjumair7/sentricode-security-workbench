"""The same scanner used by the workbench, available in a terminal or CI job."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .analysis.common import SEVERITIES, sanitize
from .exports import to_csv, to_sarif
from .scanner import scan_directory


def evaluate_policy(findings: list[dict], policy: dict) -> dict:
    active = [item for item in findings if item.get('status', 'open') not in ('resolved', 'accepted_risk', 'false_positive')]
    counts = Counter(item['severity'] for item in active)
    violations = []
    for severity in policy.get('fail_on', []):
        limit = policy.get('max_high', 0) if severity == 'high' else 0
        if counts[severity] > limit:
            violations.append(f'{counts[severity]} {severity} finding(s) exceed the allowed {limit}.')
    secrets = sum(item.get('category') == 'secrets' for item in active)
    if policy.get('fail_on_secrets') and secrets:
        violations.append(f'{secrets} exposed credential finding(s) need review.')
    return {'passed': not violations, 'violations': violations}


def baseline_fingerprints(data: dict) -> set[str]:
    values = data.get('fingerprints')
    if values is None:
        values = [item['fingerprint'] for item in data.get('findings', [])]
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError('Baseline fingerprints must be a list of strings')
    if 'fingerprints' not in data and 'findings' not in data:
        raise ValueError('Baseline must contain fingerprints or report findings')
    return set(values)


def compare_report(report: dict, baseline: dict) -> dict:
    previous = baseline_fingerprints(baseline)
    findings = report.get('findings', [])
    current = {item['fingerprint'] for item in findings}
    resolved = sorted(previous-current)
    return {'new': [item for item in findings if item['fingerprint'] not in previous],
        'resolved': resolved, 'unchanged': len(previous & current)}


def read_json(path: Path) -> dict:
    if path.stat().st_size > 32*1024*1024:
        raise ValueError('Report or baseline exceeds 32 MiB limit')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object')
    return value


def load_policy(path: Path | None) -> dict:
    if path is None:
        return {'fail_on': [], 'max_high': 0, 'fail_on_secrets': False}
    if path.stat().st_size > 64*1024:
        raise ValueError('Policy exceeds 64 KiB limit')
    if path.suffix.lower() in ('.yaml', '.yml'):
        import yaml
        try:
            value = yaml.safe_load(path.read_text())
        except (yaml.YAMLError, RecursionError) as exc:
            raise ValueError('Policy YAML could not be parsed') from exc
    else:
        value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('Policy must be an object')
    unknown = set(value) - {'fail_on', 'max_high', 'fail_on_secrets'}
    if unknown:
        raise ValueError('Unknown policy fields: '+', '.join(sorted(unknown)))
    if not isinstance(value.get('fail_on', []), list) or any(level not in SEVERITIES for level in value.get('fail_on', [])):
        raise ValueError('fail_on must be a list of severity names')
    if type(value.get('max_high', 0)) is not int or value.get('max_high', 0) < 0:
        raise ValueError('max_high must be a nonnegative integer')
    if type(value.get('fail_on_secrets', False)) is not bool:
        raise ValueError('fail_on_secrets must be true or false')
    return {'fail_on': [], 'max_high': 0, 'fail_on_secrets': False, **value}


def table(report: dict) -> str:
    lines = ['SentriCode scan', f'Files: {report["files_scanned"]}   Findings: {report["summary"]["total"]}   Posture: {report["summary"]["score"]}/100', '']
    for item in report['findings']:
        lines.append(f'{item["severity"].upper():8} {item["file"]}:{item["line_start"]}  {item["title"]} [{item["rule_id"]}]')
    if not report['findings']:
        lines.append('No findings from the enabled checks. Review coverage before treating this as a clean result.')
    lines.extend(['', 'Engines:'])
    for engine in report['engines']:
        lines.append(f'  {engine["status"]:9} {engine["name"]}: {engine["message"]}')
    if report.get('warnings'):
        lines.extend(['', 'Coverage notes:', *('  '+notice for notice in report['warnings'])])
    if 'policy' in report:
        lines.append('\nPolicy: '+('passed' if report['policy']['passed'] else 'failed'))
        lines.extend('  '+message for message in report['policy']['violations'])
    return '\n'.join(lines)+'\n'


def output(text: str, destination: Path | None):
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)


def parser() -> argparse.ArgumentParser:
    app = argparse.ArgumentParser(prog='sentricode', description='Scan source without executing it. Optional network intelligence is opt-in.')
    app.add_argument('--version', action='version', version='SentriCode 0.1.0')
    commands = app.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('scan', help='Scan a source directory')
    scan.add_argument('path', type=Path, nargs='?', default=Path('.'))
    scan.add_argument('--mode', choices=['quick', 'standard', 'deep'], default='standard')
    scan.add_argument('--format', choices=['table', 'json', 'sarif', 'csv', 'sbom'], default='table')
    scan.add_argument('-o', '--output', type=Path)
    scan.add_argument('--network', action='store_true', help='Query OSV, FIRST EPSS and CISA KEV using package names/versions and CVEs')
    scan.add_argument('--external', action='store_true', help='Use configured, pre-pulled Docker scanner images with network disabled')
    scan.add_argument('--local-tools', action='store_true', help='Explicitly authorize installed scanners for your own trusted checkout; no container isolation')
    scan.add_argument('--history', action='store_true', help='Request Gitleaks Git history scanning; requires an external adapter')
    scan.add_argument('--no-project-ignore', action='store_true', help='Ignore repository-supplied .sentricodeignore; recommended for trusted CI')
    scan.add_argument('--baseline', type=Path, help='Report or baseline JSON; gate on new fingerprints only')
    scan.add_argument('--policy', type=Path, help='JSON/YAML file with fail_on, max_high and fail_on_secrets')
    scan.add_argument('--fail-on', help='Comma-separated severities that fail CI, such as critical,high')
    scan.add_argument('--max-high', type=int, help='Allow this many high findings when high is in fail_on')
    scan.add_argument('--fail-on-secrets', action='store_true', help='Fail CI on active secret findings')
    scan.add_argument('--require-engines', help='Comma-separated exact engine names; a skipped/missing engine exits 2')
    scan.add_argument('--severity', choices=list(SEVERITIES), help='Minimum displayed severity; policy still evaluates all findings')
    baseline = commands.add_parser('baseline', help='Create a reviewed fingerprint baseline from a JSON report')
    baseline.add_argument('report', type=Path)
    baseline.add_argument('-o', '--output', type=Path, required=True)
    compare = commands.add_parser('compare', help='Compare a JSON report to a previous report or baseline')
    compare.add_argument('report', type=Path)
    compare.add_argument('--baseline', type=Path, required=True)
    compare.add_argument('-o', '--output', type=Path)
    return app


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == 'baseline':
            report = read_json(arguments.report)
            if any(engine.get('status') == 'failed' for engine in report.get('engines', [])):
                raise ValueError('Cannot baseline an incomplete report with failed engines')
            result = {'schema_version': '1.0', 'fingerprints': sorted(baseline_fingerprints(report))}
            output(json.dumps(result, indent=2)+'\n', arguments.output)
            return 0
        if arguments.command == 'compare':
            result = compare_report(read_json(arguments.report), read_json(arguments.baseline))
            output(json.dumps(sanitize(result), indent=2)+'\n', arguments.output)
            return 0
        policy = load_policy(arguments.policy)
        if arguments.fail_on is not None:
            levels = [level.strip().lower() for level in arguments.fail_on.split(',') if level.strip()]
            if any(level not in SEVERITIES for level in levels):
                raise ValueError('Unknown severity in --fail-on')
            policy['fail_on'] = levels
        if arguments.max_high is not None:
            if arguments.max_high < 0:
                raise ValueError('--max-high must be nonnegative')
            policy['max_high'] = arguments.max_high
        if arguments.fail_on_secrets:
            policy['fail_on_secrets'] = True
        baseline = read_json(arguments.baseline) if arguments.baseline else None
        if baseline is not None:
            baseline_fingerprints(baseline)  # Validate before starting an expensive scan.
        report = scan_directory(arguments.path, mode=arguments.mode, network=arguments.network,
            external='local' if arguments.local_tools else arguments.external, history=arguments.history, respect_ignore=not arguments.no_project_ignore)
        gated = report['findings']
        if baseline is not None:
            delta = compare_report(report, baseline)
            report['baseline'] = {'new': len(delta['new']), 'resolved': len(delta['resolved']), 'unchanged': delta['unchanged']}
            gated = delta['new']
        report['policy'] = {'config': policy, **evaluate_policy(gated, policy)}
        operational_failure = any(engine['status'] == 'failed' for engine in report['engines'])
        if arguments.require_engines:
            completed = {engine['name'].lower() for engine in report['engines'] if engine['status'] == 'completed'}
            missing = [name.strip() for name in arguments.require_engines.split(',') if name.strip().lower() not in completed]
            if missing:
                operational_failure = True
                report['warnings'].append('Required engines did not complete: '+', '.join(missing))
        if arguments.severity:
            allowed = set(SEVERITIES[:SEVERITIES.index(arguments.severity)+1])
            report['findings'] = [item for item in report['findings'] if item['severity'] in allowed]
            report['warnings'].append('Output filtered by severity; summary and policy include all findings.')
        if arguments.format == 'csv':
            rendered = to_csv(report)
        elif arguments.format == 'table':
            rendered = table(report)
        else:
            value = to_sarif(report) if arguments.format == 'sarif' else report['sbom'] if arguments.format == 'sbom' else report
            rendered = json.dumps(value, indent=2)+'\n'
        output(rendered, arguments.output)
        return 2 if operational_failure else 0 if report['policy']['passed'] else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Report paths only; source fragments and scanner stderr are not printed.
        print(f'SentriCode could not finish: {sanitize(str(exc))}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
