"""Optional, fixed-command scanner adapters.

Docker images must be pre-pulled and pinned by digest through owner configuration.
The API does not enable local-tool mode. This module never installs dependencies,
starts repository services, loads repository Python, or runs project scripts.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from .common import finding

TOOLS = ('semgrep', 'bandit', 'gitleaks', 'checkov', 'trivy', 'syft')
SEMGREP_RULES = '''rules:
  - id: SC-EXT-PY-EVAL
    languages: [python]
    message: Text reaches Python eval. Replace dynamic execution with a data parser.
    severity: ERROR
    pattern: eval(...)
    metadata:
      cwe: CWE-94
  - id: SC-EXT-JS-EVAL
    languages: [javascript, typescript]
    message: Text reaches JavaScript eval. Replace dynamic execution with a data parser.
    severity: ERROR
    pattern: eval(...)
    metadata:
      cwe: CWE-94
  - id: SC-EXT-PY-PICKLE
    languages: [python]
    message: Pickle deserialization requires trusted input. Prefer a data-only format.
    severity: ERROR
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
    metadata:
      cwe: CWE-502
'''


def tool_arguments(tool: str, source: str, config: str, *, history=False) -> list[str]:
    if tool == 'semgrep':
        return ['scan', '--config', config+'/semgrep.yml', '--metrics=off', '--disable-version-check', '--json', '--quiet', '--no-git-ignore', '--disable-nosem', source]
    if tool == 'bandit':
        return ['-r', source, '--ini', config+'/bandit.ini', '-f', 'json', '-q', '--ignore-nosec']
    if tool == 'gitleaks':
        return ['git' if history else 'dir', source, '--redact=100', '--no-banner', '--report-format=json', '--report-path=/dev/stdout', '--exit-code=0', '--ignore-gitleaks-allow', '--config', config+'/gitleaks.toml', '--gitleaks-ignore-path', config+'/gitleaksignore', '--max-target-megabytes=2', '--timeout=120']
    if tool == 'checkov':
        return ['-d', source, '--config-file', config+'/empty.yml', '--output', 'json', '--quiet', '--skip-download', '--download-external-modules', 'false']
    if tool == 'trivy':
        # No image build or pull. Config scanning needs no vulnerability DB.
        return ['config', '--config', config+'/empty.yml', '--format', 'json', '--skip-check-update', '--quiet', source]
    if tool == 'syft':
        return ['scan', 'dir:'+source, '-o', 'cyclonedx-json', '--quiet']
    raise ValueError('Unsupported engine')


def docker_command(tool: str, root: Path, config: Path, image: str, *, history=False, container_name='sentricode-scanner') -> list[str]:
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}', image):
        raise ValueError('Scanner image must use an immutable sha256 digest')
    if ',' in str(root) or ',' in str(config):
        raise ValueError('Docker scanner paths cannot contain commas')
    return ['docker', 'run', '--rm', '--pull=never', '--name', container_name,
        '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--pids-limit=128', '--memory=1g', '--cpus=1', '--user=65534:65534',
        '--tmpfs=/tmp:rw,noexec,nosuid,size=256m', '--workdir=/tmp',
        '--env=HOME=/tmp', '--env=SEMGREP_SEND_METRICS=off', '--env=CHECKOV_SKIP_MAPPING=TRUE',
        '--mount', f'type=bind,source={root},target=/src,readonly',
        '--mount', f'type=bind,source={config},target=/rules,readonly',
        '--entrypoint', tool, image, *tool_arguments(tool, '/src', '/rules', history=history)]


def _relative(path: str, root: Path) -> str:
    path = str(path).replace('\\', '/')
    for prefix in (str(root).rstrip('/')+'/', '/src/'):
        if path.startswith(prefix):
            path = path[len(prefix):]
    path = path.lstrip('/')
    return path if '..' not in Path(path).parts else 'external-report'


def normalize(tool: str, data, root: Path) -> list[dict]:
    results = []
    def emit(rule, title, severity, category, path, line=1, evidence='', description='', cwe=None, **extras):
        if len(results) >= 5000:
            raise ValueError('External finding limit exceeded')
        level = {'error': 'high', 'warning': 'medium', 'warn': 'medium', 'note': 'low'}.get(str(severity).lower(), str(severity).lower())
        if level not in ('critical', 'high', 'medium', 'low', 'info'):
            level = 'medium'
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        if isinstance(cwe, str):
            match = re.search(r'CWE-\d+', cwe)
            cwe = match.group() if match else None
        results.append(finding(str(rule), str(title)[:250], level, category, _relative(path, root), int(line or 1), evidence,
            description or str(title), 'Review the linked rule and replace the unsafe construct. Confirm the fix with a focused regression test.', scanner=tool.title(), cwe=cwe, confidence=0.8, **extras))
    if tool == 'semgrep':
        for item in data.get('results', []):
            extra = item.get('extra', {})
            emit(item['check_id'], extra.get('message', item['check_id']), extra.get('severity', 'medium'), 'sast', item['path'], item.get('start', {}).get('line', 1), extra.get('lines', ''), cwe=extra.get('metadata', {}).get('cwe'))
    elif tool == 'bandit':
        for item in data.get('results', []):
            emit(item['test_id'], item.get('issue_text', item['test_id']), item.get('issue_severity', 'medium'), 'sast', item['filename'], item.get('line_number', 1), item.get('code', ''), cwe='CWE-'+str(item.get('issue_cwe', {}).get('id', '')))
    elif tool == 'gitleaks':
        for item in data or []:
            emit(item.get('RuleID', 'GITLEAKS'), item.get('Description', 'Secret found'), 'high', 'secrets', item.get('File', ''), item.get('StartLine', 1), '[REDACTED SECRET]', cwe='CWE-798', commit=item.get('Commit') or None)
    elif tool == 'checkov':
        for group in data if isinstance(data, list) else [data]:
            for item in group.get('results', {}).get('failed_checks', []):
                code = '\n'.join(str(line[1]) for line in item.get('code_block', []) if isinstance(line, list) and len(line) > 1)
                emit(item['check_id'], item.get('check_name', item['check_id']), item.get('severity') or 'medium', 'iac', item.get('file_path', ''), (item.get('file_line_range') or [1])[0], code, references=[item['guideline']] if item.get('guideline', '').startswith('https://') else [])
    elif tool == 'trivy':
        for target in data.get('Results', []):
            for item in target.get('Misconfigurations', []):
                emit(item.get('ID', 'TRIVY-CONFIG'), item.get('Title', 'Configuration finding'), item.get('Severity', 'medium'), 'iac', target.get('Target', ''), item.get('CauseMetadata', {}).get('StartLine', 1), '', item.get('Description', ''), references=item.get('References', [])[:8])
            for item in target.get('Vulnerabilities', []):
                emit(item.get('VulnerabilityID', 'TRIVY-VULN'), item.get('Title') or item.get('VulnerabilityID', ''), item.get('Severity', 'medium'), 'dependencies', target.get('Target', ''), 1, f'{item.get("PkgName", "")}=={item.get("InstalledVersion", "")}', item.get('Description', ''), cve=item.get('VulnerabilityID'), package={'name': item.get('PkgName'), 'version': item.get('InstalledVersion')})
    return results


def _run(command: list[str], workspace: Path, timeout=120) -> tuple[int, str]:
    # Disk-backed pipes plus a size watchdog prevent a scanner from filling RAM.
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(workspace), 'LANG': 'C.UTF-8', 'SEMGREP_SEND_METRICS': 'off', 'CHECKOV_SKIP_MAPPING': 'TRUE', 'SYFT_CHECK_FOR_APP_UPDATE': 'false'}
    out_path, err_path = workspace/'stdout.json', workspace/'stderr.txt'
    with out_path.open('wb') as out, err_path.open('wb') as err:
        process = subprocess.Popen(command, cwd=workspace, env=env, stdout=out, stderr=err, start_new_session=True)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic()-started > timeout:
                    raise TimeoutError('Scanner timeout')
                if out_path.stat().st_size + err_path.stat().st_size > 32*1024*1024:
                    raise ValueError('Scanner output limit exceeded')
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    if out_path.stat().st_size > 32*1024*1024:
        raise ValueError('Scanner output limit exceeded')
    return process.returncode, out_path.read_text(errors='replace')


def run_external(root: Path, *, local=False, history=False) -> tuple[list[dict], list[dict], dict | None]:
    all_findings, engines, external_sbom = [], [], None
    for tool in TOOLS:
        name = tool.title()
        image = os.environ.get('SENTRICODE_'+tool.upper()+'_IMAGE', '')
        executable = shutil.which(tool if local else 'docker')
        if not executable or not local and not image:
            reason = 'Executable not installed.' if not executable else f'Set SENTRICODE_{tool.upper()}_IMAGE to a pre-pulled image pinned by sha256 digest.'
            engines.append({'name': name, 'status': 'skipped', 'findings': 0, 'message': reason})
            continue
        container_name = 'sentricode-'+os.urandom(8).hex()
        with tempfile.TemporaryDirectory(prefix='sentricode-engine-') as scratch:
            work = Path(scratch)
            rules = work/'rules'
            rules.mkdir(mode=0o755)
            (rules/'semgrep.yml').write_text(SEMGREP_RULES)
            (rules/'empty.yml').write_text('{}\n')
            (rules/'bandit.ini').write_text('[bandit]\n')
            (rules/'gitleaks.toml').write_text('[extend]\nuseDefault = true\n')
            (rules/'gitleaksignore').write_text('')
            try:
                command = [executable, *tool_arguments(tool, str(root), str(rules), history=history)] if local else docker_command(tool, root, rules, image, history=history, container_name=container_name)
                code, output = _run(command, work)
                allowed = (0, 1) if tool in ('bandit', 'checkov') else (0,)
                if code not in allowed:
                    raise ValueError(f'engine exited {code}')
                data = json.loads(output)
                if tool in ('semgrep', 'bandit') and data.get('errors'):
                    raise ValueError('engine reported parse errors')
                if tool == 'syft':
                    if data.get('bomFormat') != 'CycloneDX':
                        raise ValueError('invalid SBOM format')
                    external_sbom = data
                    found = []
                else:
                    found = normalize(tool, data, root)
                all_findings.extend(found)
                engines.append({'name': name, 'status': 'completed', 'findings': len(found), 'message': ('Owner-authorized installed tool.' if local else 'Isolated container; network disabled.') + (' Git history scanned.' if tool == 'gitleaks' and history else '') + (' Configuration checks only; image CVE scanning is not enabled.' if tool == 'trivy' else '')})
            except (OSError, ValueError, KeyError, TypeError, TimeoutError) as exc:
                engines.append({'name': name, 'status': 'failed', 'findings': 0, 'message': f'Engine did not complete ({type(exc).__name__}). Check installation, image digest, compatibility and resource limits.'})
            finally:
                if not local:
                    # Killing the Docker client alone does not terminate its container.
                    try:
                        subprocess.run([executable, 'rm', '-f', container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
    return all_findings, engines, external_sbom
