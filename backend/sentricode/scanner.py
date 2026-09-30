"""Local-first source scanning with explicit optional network and tool adapters."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .analysis.common import AnalysisLimit, language, sanitize, secret_findings, summary
from .analysis.dependencies import enrich, inventory, sbom
from .analysis.external import TOOLS, run_external
from .analysis.sast import config_findings, javascript_findings, python_findings

EXCLUDED = {'.git', '.hg', '.svn', '.venv', 'venv', 'node_modules', '__pycache__', '.next', '.pytest_cache', '.mypy_cache', '.ruff_cache', 'dist', 'build', 'coverage', 'vendor', '.tox'}
MAX_FILE_BYTES = 2*1024*1024
MAX_TOTAL_BYTES = 64*1024*1024
MAX_FILES = 6000
MAX_FINDINGS = 5000
MAX_KNOWN_SECRETS = 2000


def collect_files(root: Path, *, respect_ignore=True) -> tuple[list[tuple[str, str]], list[str], bool]:
    files, warnings = [], []
    ignored = []
    ignore_file = root/'.sentricodeignore'
    if respect_ignore and ignore_file.is_file() and not ignore_file.is_symlink() and ignore_file.stat().st_size < 32*1024:
        ignored = [line.strip() for line in ignore_file.read_text(errors='replace').splitlines() if line.strip() and not line.lstrip().startswith('#')]
        if ignored:
            warnings.append(f'Applied {len(ignored)} patterns from .sentricodeignore. Excluded paths were not analyzed.')
    total, incomplete, count = 0, False, 0
    def skip(relative: str) -> bool:
        return any(fnmatch.fnmatch(relative, pat) or fnmatch.fnmatch(relative+'/', pat.rstrip('/')+'/') or relative.startswith(pat.rstrip('/')+'/') for pat in ignored)
    def walk_error(exc):
        nonlocal incomplete
        incomplete = True
        warnings.append(f'A source directory could not be read ({type(exc).__name__}).')
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(directory)/d).is_symlink() and not skip((Path(directory)/d).relative_to(root).as_posix()))
        for name in sorted(names):
            path = Path(directory)/name
            relative = path.relative_to(root).as_posix()
            if skip(relative):
                continue
            count += 1
            if count > MAX_FILES:
                warnings.append(f'File limit ({MAX_FILES}) reached; scan coverage is incomplete.')
                return files, warnings, True
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    continue
                if info.st_size > MAX_FILE_BYTES:
                    warnings.append(f'{relative}: exceeds 2 MiB file limit; skipped.')
                    incomplete = True
                    continue
                # O_NOFOLLOW protects against replacing a file with a link after lstat.
                descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
                with os.fdopen(descriptor, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    data = stream.read(MAX_FILE_BYTES+1)
                if len(data) > MAX_FILE_BYTES:
                    warnings.append(f'{relative}: changed beyond file limit; skipped.')
                    incomplete = True
                    continue
                if b'\0' in data[:8192]:
                    continue
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    warnings.append('64 MiB source budget reached; scan coverage is incomplete.')
                    return files, warnings, True
                try:
                    source = data.decode('utf-8-sig')
                except UnicodeDecodeError:
                    warnings.append(f'{relative}: non-UTF-8 content skipped.')
                    continue
                files.append((relative, source))
            except OSError as exc:
                warnings.append(f'{relative}: could not read source ({type(exc).__name__}).')
                incomplete = True
    return files, warnings, incomplete


def scan_directory(path: Path, *, mode='standard', network=False, external=False, history=False, progress=None, respect_ignore=True) -> dict:
    if mode not in ('quick', 'standard', 'deep'):
        raise ValueError('Mode must be quick, standard or deep')
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError('Scan target must be an existing directory')
    if external not in (False, True, 'local'):
        raise ValueError('External mode must be false, true, or local')
    started = time.monotonic()
    def notify(stage, message):
        if progress:
            progress(stage, message)
    notify('profiling', 'Reading text files and identifying languages')
    files, warnings, incomplete = collect_files(root, respect_ignore=respect_ignore)
    engines = [{'name': 'Repository profiler', 'status': 'failed' if incomplete else 'completed', 'findings': 0, 'message': f'Read {len(files)} text files. Generated, vendor and VCS directories excluded.'}]
    findings, secrets = [], set()
    blocked_files = set()
    finding_limit_hit = False
    def add_findings(items):
        nonlocal finding_limit_hit
        remaining = MAX_FINDINGS-len(findings)
        if len(items) > remaining:
            finding_limit_hit = True
        findings.extend(items[:remaining])
    counts = Counter(language(path) for path, _ in files)
    notify('secrets', 'Checking credentials and private keys')
    for filename, source in files:
        try:
            if len(secrets) >= MAX_KNOWN_SECRETS or finding_limit_hit:
                raise AnalysisLimit('Whole-scan secret budget exceeded')
            found, values = secret_findings(filename, source)
            if len(secrets | values) > MAX_KNOWN_SECRETS:
                raise AnalysisLimit('Whole-scan secret budget exceeded')
            add_findings(found)
            secrets.update(values)
        except AnalysisLimit:
            blocked_files.add(filename)
            warnings.append(f'{filename}: secret match budget exceeded; source withheld from further analysis and reporting.')
    files_for_analysis = [(filename, source) for filename, source in files if filename not in blocked_files]
    engines.append({'name': 'SecretGuard', 'status': 'failed' if blocked_files else 'completed', 'findings': len(findings), 'message': 'Credential patterns, assignment context, connection strings and private keys. Values redacted before reporting.'})
    notify('sast', 'Checking source and confidential-data logging')
    before, parse_errors = len(findings), 0
    for filename, source in files_for_analysis:
        if finding_limit_hit:
            break
        suffix = Path(filename).suffix.lower()
        if suffix == '.py':
            try:
                add_findings(python_findings(filename, source))
            except AnalysisLimit:
                parse_errors += 1
                warnings.append(f'{filename}: analysis budget exceeded; AST checks incomplete.')
            except (SyntaxError, ValueError, RecursionError):
                parse_errors += 1
                warnings.append(f'{filename}: Python syntax could not be parsed; AST checks skipped for this file.')
        elif suffix in ('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'):
            try:
                add_findings(javascript_findings(filename, source))
            except AnalysisLimit:
                parse_errors += 1
                warnings.append(f'{filename}: per-file finding budget exceeded; JavaScript checks incomplete.')
    engines.append({'name': 'SentriCode SAST + DataGuard', 'status': 'failed' if parse_errors else 'completed', 'findings': len(findings)-before, 'message': 'Python AST with local assignment traces; JavaScript/TypeScript lexical checks. Other languages receive secret checks only unless optional engines are enabled.'})
    dependencies, external_sbom = [], None
    if mode != 'quick':
        notify('configuration', 'Checking configuration and dependency manifests')
        before = len(findings)
        config_errors = 0
        for filename, source in files_for_analysis:
            if finding_limit_hit:
                break
            if Path(filename).suffix.lower() in ('.yaml', '.yml', '.tf', '.hcl') or Path(filename).name.lower().startswith('dockerfile'):
                try:
                    add_findings(config_findings(filename, source))
                except AnalysisLimit:
                    config_errors += 1
                    warnings.append(f'{filename}: per-file finding budget exceeded; configuration checks incomplete.')
        engines.append({'name': 'Configuration checks', 'status': 'failed' if config_errors else 'completed', 'findings': len(findings)-before, 'message': 'Focused Dockerfile, YAML, GitHub Actions and Terraform pattern checks.'})
        dependencies, errors = inventory(files_for_analysis)
        warnings.extend(errors)
        engines.append({'name': 'Dependency inventory + SBOM', 'status': 'failed' if errors else 'completed', 'findings': 0, 'message': f'Inventoried {len(dependencies)} package versions or constraints; does not install packages.'})
        if network:
            notify('intelligence', 'Querying OSV and public CVE intelligence')
            found, statuses, notices = enrich(dependencies)
            add_findings(found)
            engines.extend(statuses)
            warnings.extend(notices)
        else:
            engines.append({'name': 'OSV / EPSS / CISA KEV', 'status': 'skipped', 'findings': 0, 'message': 'Network enrichment is off. Known dependency vulnerabilities and exploit intelligence were not checked.'})
    else:
        engines.append({'name': 'Dependency + configuration checks', 'status': 'skipped', 'findings': 0, 'message': 'Quick mode checks current source and secrets only; it is not changed-file scanning.'})
        if network:
            warnings.append('Quick mode does not query dependency intelligence. Use standard or deep mode.')
    if external:
        notify('external', 'Running optional scanners')
        found, statuses, external_sbom = run_external(root, local=external == 'local', history=history)
        add_findings(found)
        engines.extend(statuses)
    else:
        engines.extend({'name': name.title(), 'status': 'skipped', 'findings': 0, 'message': 'Optional engine not requested.'} for name in TOOLS)
    if history and not external:
        warnings.append('Git history was requested but not scanned. Enable an external Gitleaks adapter to inspect history.')
        engines.append({'name': 'Git history', 'status': 'failed', 'findings': 0, 'message': 'History requires an enabled Gitleaks adapter.'})
    elif history and not any(e['name'] == 'Gitleaks' and e['status'] == 'completed' for e in engines):
        engines.append({'name': 'Git history', 'status': 'failed', 'findings': 0, 'message': 'Requested Git history scan did not complete.'})
    if mode == 'deep':
        warnings.append('Deep mode includes standard checks and requested optional tools. Cross-file taint, automatic AI review, image CVEs and history without --history are not implemented.')
    if finding_limit_hit:
        warnings.append('Whole-scan limit of 5,000 findings reached; coverage is incomplete.')
        engines.append({'name': 'Analysis budgets', 'status': 'failed', 'findings': 0, 'message': 'Finding budget exceeded.'})
    if not files:
        warnings.append('No supported text files were read. A clean finding list does not establish source coverage.')
    # Assign duplicate occurrence IDs without relying on line numbers. Identical
    # expressions remain distinct, while adding blank lines preserves baselines.
    occurrences = Counter()
    for item in findings:
        base = item['fingerprint']
        occurrences[base] += 1
        if occurrences[base] > 1:
            item['id'] = item['fingerprint'] = hashlib.sha256(f'{base}:{occurrences[base]}'.encode()).hexdigest()[:32]
    findings.sort(key=lambda item: (-item['sentri_score'], item['file'], item['line_start'], item['rule_id']))
    report = {'schema_version': '1.0', 'generated_at': datetime.now(timezone.utc).isoformat(), 'mode': mode,
        'duration_ms': round((time.monotonic()-started)*1000), 'files_scanned': len(files), 'languages': dict(counts),
        'findings': findings, 'dependencies': dependencies, 'engines': engines, 'summary': summary(findings),
        'sbom': external_sbom or sbom(dependencies), 'warnings': warnings,
        'coverage': {'network': bool(network), 'external': bool(external), 'history_requested': bool(history), 'limits_hit': incomplete, 'executed_repository_code': False}}
    notify('complete', 'Scan finished; findings are ready for review')
    return sanitize(report, secrets)
