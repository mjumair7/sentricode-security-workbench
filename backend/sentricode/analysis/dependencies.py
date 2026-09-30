from __future__ import annotations

import json
import math
import re
import tomllib
import uuid
from datetime import datetime, timezone
from urllib.parse import quote
import xml.etree.ElementTree as ET

from .common import AnalysisLimit, finding, score

EXACT = re.compile(r'^v?\d[\w.+!_-]*$')
ECOSYSTEM_PURL = {'PyPI': 'pypi', 'npm': 'npm', 'Go': 'golang', 'crates.io': 'cargo', 'Maven': 'maven', 'NuGet': 'nuget'}
MANIFESTS = {'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'poetry.lock', 'uv.lock', 'pyproject.toml', 'Cargo.lock', 'go.mod', 'go.sum', 'pom.xml', 'packages.lock.json'}


def exact_version(version: str) -> bool:
    return bool(EXACT.fullmatch(version)) and not bool(re.search(r'(?:^|\.)[xX*](?:\.|$)', version))


def package(name: str, version: str, ecosystem: str, path: str, direct: bool | None = None, *, locked=False) -> dict:
    resolved = exact_version(version)
    ecosystem_name = ECOSYSTEM_PURL[ecosystem]
    encoded = quote(name, safe='/')
    if ecosystem == 'PyPI':
        name = re.sub(r'[-_.]+', '-', name).lower()
        encoded = quote(name)
    if ecosystem == 'Maven':
        encoded = quote(name.replace(':', '/'), safe='/')
    purl = f'pkg:{ecosystem_name}/{encoded}' + ('@' + quote(version, safe='') if resolved else '')
    return {'name': name, 'version': version if resolved else None, 'constraint': version,
        'ecosystem': ecosystem, 'file': path, 'direct': direct, 'resolved': resolved, 'locked': locked, 'purl': purl}


def inventory(files: list[tuple[str, str]]) -> tuple[list[dict], list[str]]:
    packages, warnings = [], []
    def add(name, version, ecosystem, path, direct=None, locked=False):
        if len(packages) >= 10000:
            raise AnalysisLimit('Dependency inventory budget exceeded')
        if isinstance(name, str) and isinstance(version, str) and name and len(name) <= 300 and len(version) <= 200:
            packages.append(package(name, version, ecosystem, path, direct, locked=locked))
    for path, text in files:
        name = path.rsplit('/', 1)[-1]
        try:
            if name in ('package-lock.json', 'npm-shrinkwrap.json'):
                data = json.loads(text)
                if 'packages' in data:
                    direct = set(data['packages'].get('', {}).get('dependencies', {})) | set(data['packages'].get('', {}).get('devDependencies', {}))
                    for location, item in data['packages'].items():
                        if location and isinstance(item, dict):
                            dep = item.get('name') or location.rsplit('node_modules/', 1)[-1]
                            add(dep, item.get('version'), 'npm', path, dep in direct and location == 'node_modules/' + dep, True)
                else:
                    def walk(deps, direct):
                        for dep, item in deps.items():
                            add(dep, item.get('version'), 'npm', path, direct, True)
                            walk(item.get('dependencies', {}), False)
                    walk(data.get('dependencies', {}), True)
            elif name == 'package.json':
                data = json.loads(text)
                for key in ('dependencies', 'devDependencies', 'optionalDependencies'):
                    for dep, version in data.get(key, {}).items():
                        add(dep, version, 'npm', path, True)
            elif re.fullmatch(r'(?:requirements[^/]*|constraints[^/]*)\.txt', name):
                for line in text.splitlines():
                    match = re.match(r'\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$', line)
                    if match and not line.lstrip().startswith(('#', '-')):
                        constraint = re.sub(r'\s+#.*', '', line).split(';')[0].strip()
                        pinned = re.match(r'^[\w.-]+(?:\[[^\]]+\])?\s*===?\s*([^,\s]+)', constraint)
                        add(match.group(1), pinned.group(1) if pinned else constraint[len(match.group(1)):].strip(), 'PyPI', path, True, bool(pinned))
            elif name in ('poetry.lock', 'uv.lock', 'Cargo.lock'):
                data = tomllib.loads(text)
                for item in data.get('package', []):
                    add(item.get('name'), item.get('version'), 'crates.io' if name == 'Cargo.lock' else 'PyPI', path, None, True)
            elif name == 'pyproject.toml':
                data = tomllib.loads(text)
                deps = data.get('project', {}).get('dependencies', [])
                for dep in deps:
                    match = re.match(r'([\w.-]+)(?:\[[^\]]+\])?\s*(.*)', dep)
                    if match:
                        constraint = match.group(2).split(';')[0].strip()
                        add(match.group(1), constraint[2:] if constraint.startswith('==') and ',' not in constraint else constraint, 'PyPI', path, True)
                for dep, spec in data.get('tool', {}).get('poetry', {}).get('dependencies', {}).items():
                    if dep != 'python':
                        add(dep, spec if isinstance(spec, str) else spec.get('version', ''), 'PyPI', path, True)
            elif name == 'pnpm-lock.yaml':
                import yaml
                data = yaml.safe_load(text) or {}
                for key, item in data.get('packages', {}).items():
                    key = key.lstrip('/').split('(')[0]
                    if '@' in key[1:]:
                        dep, version = key.rsplit('@', 1)
                    else:
                        dep, version = key.rsplit('/', 1)
                    add(dep, version, 'npm', path, None, True)
            elif name == 'yarn.lock':
                selectors = []
                for line in text.splitlines():
                    if line and not line[0].isspace() and line.endswith(':'):
                        selectors = [part.strip(' \"') for part in line[:-1].split(', ')]
                    elif (match := re.match(r'\s+version\s*:?\s*[\"\']([^\"\']+)', line)):
                        for selector in selectors:
                            if '@' in selector[1:]:
                                add(selector.rsplit('@', 1)[0], match.group(1), 'npm', path, None, True)
            elif name in ('go.mod', 'go.sum'):
                for line in text.splitlines():
                    match = re.match(r'\s*(?:require\s+)?([\w./-]+)\s+(v[\w.+-]+)(?:/go.mod)?(?:\s|$)', line)
                    if match:
                        add(match.group(1), match.group(2), 'Go', path, None, name == 'go.sum')
            elif name == 'pom.xml':
                if '<!DOCTYPE' in text or '<!ENTITY' in text:
                    warnings.append(f'{path}: XML entities are not supported.')
                    continue
                root = ET.fromstring(text)
                ns = {'m': root.tag[1:].split('}')[0]} if root.tag.startswith('{') else {}
                prefix = 'm:' if ns else ''
                for dep in root.findall('.//' + prefix + 'dependency', ns):
                    group = dep.findtext(prefix+'groupId', namespaces=ns)
                    artifact = dep.findtext(prefix+'artifactId', namespaces=ns)
                    version = dep.findtext(prefix+'version', namespaces=ns)
                    if group and artifact:
                        add(group+':'+artifact, version or 'managed', 'Maven', path, True)
            elif name == 'packages.lock.json':
                for deps in json.loads(text).get('dependencies', {}).values():
                    for dep, item in deps.items():
                        add(dep, item.get('resolved'), 'NuGet', path, item.get('type') == 'Direct', True)
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, ET.ParseError) as exc:
            warnings.append(f'{path}: dependency inventory could not parse this manifest ({type(exc).__name__}).')
        except Exception as exc:
            # Optional YAML parsers report their own exception type; never include source snippets.
            warnings.append(f'{path}: dependency inventory failed ({type(exc).__name__}).')
    # Lockfiles take precedence over unresolved declarations within the same directory.
    locked = {(p['file'].rsplit('/', 1)[0] if '/' in p['file'] else '', p['ecosystem'], p['name']) for p in packages if p['locked'] and p['resolved']}
    result, seen = [], set()
    for item in sorted(packages, key=lambda p: (not p['locked'], p['file'], p['name'], p['constraint'])):
        directory = item['file'].rsplit('/', 1)[0] if '/' in item['file'] else ''
        if not item['locked'] and (directory, item['ecosystem'], item['name']) in locked:
            continue
        key = (item['ecosystem'], item['name'], item['constraint'], directory)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result, warnings


def sbom(packages: list[dict]) -> dict:
    components, seen = [], set()
    for item in packages:
        if item['purl'] in seen:
            continue
        seen.add(item['purl'])
        component = {'type': 'library', 'bom-ref': item['purl'], 'name': item['name'], 'purl': item['purl'],
            'properties': [{'name': 'sentricode:manifest', 'value': item['file']}, {'name': 'sentricode:constraint', 'value': item['constraint']}, {'name': 'sentricode:resolved', 'value': str(item['resolved']).lower()}]}
        if item['version']:
            component['version'] = item['version']
        components.append(component)
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'serialNumber': 'urn:uuid:'+str(uuid.uuid4()), 'version': 1,
        'metadata': {'timestamp': datetime.now(timezone.utc).isoformat(), 'tools': [{'vendor': 'SentriCode', 'name': 'SentriCode', 'version': '0.1.0'}]}, 'components': components}


def cvss_v3(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score. Other vector versions remain unknown."""
    try:
        if not vector.startswith(('CVSS:3.0/', 'CVSS:3.1/')):
            return None
        fields = dict(part.split(':') for part in vector.split('/')[1:])
        changed = fields['S'] == 'C'
        iss = 1 - math.prod(1-{'N': 0, 'L': .22, 'H': .56}[fields[key]] for key in ('C', 'I', 'A'))
        impact = 7.52*(iss-.029)-3.25*(iss-.02)**15 if changed else 6.42*iss
        if impact <= 0:
            return 0.0
        exploit = 8.22 * {'N': .85, 'A': .62, 'L': .55, 'P': .2}[fields['AV']] * {'L': .77, 'H': .44}[fields['AC']] * ({'N': .85, 'L': .68, 'H': .5} if changed else {'N': .85, 'L': .62, 'H': .27})[fields['PR']] * {'N': .85, 'R': .62}[fields['UI']]
        return math.ceil(round(min(10, (impact+exploit)*(1.08 if changed else 1)), 5)*10)/10
    except (ValueError, KeyError):
        return None


def osv_finding(dep: dict, advisory: dict) -> dict:
    cvss = next((score for s in advisory.get('severity', []) if (score := cvss_v3(s.get('score', ''))) is not None), None)
    severity = advisory.get('database_specific', {}).get('severity', '').lower()
    known_severity = severity in ('critical', 'high', 'medium', 'low')
    if cvss is not None:
        severity = 'critical' if cvss >= 9 else 'high' if cvss >= 7 else 'medium' if cvss >= 4 else 'low'
    elif not known_severity:
        severity = 'medium'
    aliases = advisory.get('aliases', []) + [advisory.get('id', '')]
    cve = next((alias for alias in aliases if re.fullmatch(r'CVE-\d{4}-\d{4,}', alias)), None)
    fixes = []
    for affected in advisory.get('affected', []):
        if affected.get('package', {}).get('name', '').lower() != dep['name'].lower():
            continue
        for ranges in affected.get('ranges', []):
            fixes.extend(event['fixed'] for event in ranges.get('events', []) if 'fixed' in event)
    identifier = advisory['id']
    return finding('OSV-'+identifier, advisory.get('summary') or f'Advisory for {dep["name"]}', severity, 'dependencies', dep['file'], 1,
        f'{dep["name"]}=={dep["version"]} ({identifier})', (advisory.get('details') or 'An advisory matches this exact package version.')[:6000],
        ('Review the advisory and upgrade to an appropriate fixed release. Reported fixed versions: '+', '.join(sorted(set(fixes))) if fixes else 'Review the upstream advisory for mitigation or a fixed version; no fixed release was supplied.'),
        scanner='OSV', cwe=None, confidence=0.99, cve=cve, cvss=cvss, package=dep,
        references=['https://osv.dev/vulnerability/'+quote(identifier, safe='')] + [r['url'] for r in advisory.get('references', []) if r.get('url', '').startswith('https://')][:8],
        owasp='A03:2025 Software Supply Chain Failures', severity_source='CVSS v3' if cvss is not None else 'Advisory severity' if known_severity else 'Unrated advisory; medium review priority', fixed_versions=sorted(set(fixes)))


def enrich(packages: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    """Only names, exact versions and CVE IDs leave the machine. No code is sent."""
    import httpx
    results, engines, warnings = [], [], []
    candidates = [item for item in packages if item['resolved']]
    unresolved = len(packages) - len(candidates)
    if unresolved:
        warnings.append(f'{unresolved} dependencies have unresolved version constraints and were not queried. Commit lockfiles for accurate matching.')
    if not candidates:
        return [], [{'name': 'OSV', 'status': 'skipped', 'findings': 0, 'message': 'No exact package versions available.'}], warnings
    if len(candidates) > 1000:
        warnings.append('Online inventory limited to 1,000 packages; remaining packages were not queried.')
        candidates = candidates[:1000]
    def fetch(client, method, url, **kwargs):
        with client.stream(method, url, **kwargs) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 16*1024*1024:
                    raise ValueError('intelligence response size limit exceeded')
            return json.loads(data)
    with httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False, headers={'User-Agent': 'SentriCode/0.1'}) as client:
        details = {}
        try:
            for start in range(0, len(candidates), 100):
                batch = candidates[start:start+100]
                queries = [{'package': {'name': p['name'], 'ecosystem': p['ecosystem']}, 'version': p['version']} for p in batch]
                data = fetch(client, 'POST', 'https://api.osv.dev/v1/querybatch', json={'queries': queries})
                if len(data.get('results', [])) != len(batch):
                    raise ValueError('incomplete OSV response')
                for dep, matches in zip(batch, data['results']):
                    if matches.get('next_page_token'):
                        warnings.append(f'OSV returned more advisories for {dep["name"]} than this scan retrieved.')
                    for item in matches.get('vulns', []):
                        identifier = item['id']
                        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', identifier):
                            continue
                        if identifier not in details:
                            if len(details) >= 200:
                                raise ValueError('advisory detail limit reached; partial results')
                            details[identifier] = fetch(client, 'GET', 'https://api.osv.dev/v1/vulns/'+quote(identifier, safe=''))
                        results.append(osv_finding(dep, details[identifier]))
            engines.append({'name': 'OSV', 'status': 'completed', 'findings': len(results), 'message': f'Queried {len(candidates)} exact package versions.'})
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            engines.append({'name': 'OSV', 'status': 'failed', 'findings': len(results), 'message': 'Advisory query incomplete ('+type(exc).__name__+'). Retry with network access; this is not a clean result.'})
        cves = sorted({item['cve'] for item in results if item['cve']})
        if cves:
            try:
                values = {}
                for start in range(0, len(cves), 100):
                    data = fetch(client, 'GET', 'https://api.first.org/data/v1/epss', params={'cve': ','.join(cves[start:start+100])})
                    for item in data.get('data', []):
                        values[item['cve']] = (float(item['epss']), item.get('date'))
                for item in results:
                    if item['cve'] in values:
                        item['epss'], item['epss_date'] = values[item['cve']]
                engines.append({'name': 'EPSS', 'status': 'completed', 'findings': 0, 'message': 'CVE exploit probabilities retrieved; missing scores remain unknown.'})
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                engines.append({'name': 'EPSS', 'status': 'failed', 'findings': 0, 'message': 'EPSS unavailable; probabilities remain unknown.'})
            try:
                data = fetch(client, 'GET', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
                known = {item['cveID'] for item in data['vulnerabilities']}
                for item in results:
                    if item['cve']:
                        item['kev'] = item['cve'] in known
                        item['kev_catalog_date'] = data.get('dateReleased')
                engines.append({'name': 'CISA KEV', 'status': 'completed', 'findings': 0, 'message': 'Checked against the CISA known exploited vulnerabilities catalog.'})
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                engines.append({'name': 'CISA KEV', 'status': 'failed', 'findings': 0, 'message': 'KEV unavailable; exploitation status remains unknown.'})
    for item in results:
        item['sentri_score'] = score(item)
    return results, engines, warnings
