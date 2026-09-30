import json

import httpx
import pytest

from sentricode.analysis.dependencies import inventory, exact_version, sbom, cvss_v3, enrich
from sentricode.scanner import scan_directory


def test_lockfile_precedence_and_transitive_packages():
    lock = {'lockfileVersion': 3, 'packages': {'': {'dependencies': {'lodash': '^4.17.0'}}, 'node_modules/lodash': {'version': '4.17.20'}, 'node_modules/lodash/node_modules/foo': {'version': '1.0.0'}}}
    packages, warnings = inventory([('package.json', '{"dependencies":{"lodash":"^4.17.0"}}'), ('package-lock.json', json.dumps(lock))])
    assert not warnings
    assert [(p['name'], p['version'], p['direct']) for p in packages] == [('foo', '1.0.0', False), ('lodash', '4.17.20', True)]


@pytest.mark.parametrize('filename,source,expected', [
    ('requirements.txt', 'Flask==2.0.0\nrequests>=2.0\nDjango\n# ignore\n-r other.txt', [('django', None), ('flask', '2.0.0'), ('requests', None)]),
    ('poetry.lock', '[[package]]\nname = "Flask"\nversion = "2.0.0"', [('flask', '2.0.0')]),
    ('uv.lock', 'version = 1\n[[package]]\nname = "requests"\nversion = "2.28.0"', [('requests', '2.28.0')]),
    ('Cargo.lock', 'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.0"', [('serde', '1.0.0')]),
    ('pyproject.toml', '[project]\ndependencies = ["Flask==2.0.0", "requests>=2.0"]', [('flask', '2.0.0'), ('requests', None)]),
    ('pnpm-lock.yaml', 'lockfileVersion: 9\npackages:\n  lodash@4.17.20:\n    resolution: {}', [('lodash', '4.17.20')]),
    ('yarn.lock', '"lodash@^4.17.0":\n  version "4.17.20"', [('lodash', '4.17.20')]),
    ('go.mod', 'module example.com/me\nrequire (\n golang.org/x/text v0.3.5\n)', [('golang.org/x/text', 'v0.3.5')]),
    ('go.sum', 'golang.org/x/text v0.3.5/go.mod h1:fake\ngolang.org/x/text v0.3.5 h1:fake', [('golang.org/x/text', 'v0.3.5')]),
    ('pom.xml', '<project><dependencies><dependency><groupId>org.demo</groupId><artifactId>test</artifactId><version>1.2.3</version></dependency></dependencies></project>', [('org.demo:test', '1.2.3')]),
    ('packages.lock.json', '{"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"}}}}', [('Newtonsoft.Json', '12.0.1')]),
])
def test_inventory_ecosystems(filename, source, expected):
    packages, warnings = inventory([(filename, source)])
    assert not warnings
    assert sorted((p['name'], p['version']) for p in packages) == expected


@pytest.mark.parametrize('value', ['^1.2.3', '~1.2', '>=2.0', '1.2.x', '1.*', '${revision}', 'latest', 'git+https://example.com/repo', '*', ''])
def test_ranges_never_queried_as_exact_versions(value):
    assert not exact_version(value)


def test_cyclonedx_preserves_unresolved_inventory_without_inventing_versions():
    packages, _ = inventory([('package.json', '{"dependencies":{"@scope/pkg":"^1.0.0","fixed":"1.2.3"}}')])
    document = sbom(packages)
    assert document['bomFormat'] == 'CycloneDX'
    scoped = next(c for c in document['components'] if c['name'] == '@scope/pkg')
    assert 'version' not in scoped
    assert scoped['purl'] == 'pkg:npm/%40scope/pkg'
    assert any(p['value'] == 'false' for p in scoped['properties'])


def test_malformed_and_hostile_manifests_warn_without_expanding_xml():
    packages, warnings = inventory([('package-lock.json', '{broken'), ('pom.xml', '<!DOCTYPE a [<!ENTITY b SYSTEM "file:///etc/passwd">]><project>&b;</project>')])
    assert not packages
    assert len(warnings) == 2
    assert 'root:' not in '\n'.join(warnings)


@pytest.mark.parametrize('vector,expected', [
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0),
    ('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0),
    ('CVSS:4.0/AV:N/AC:L', None),
    ('bad', None),
])
def test_cvss_known_vectors(vector, expected):
    assert cvss_v3(vector) == expected


def install_transport(monkeypatch, handler):
    real_client = httpx.Client
    monkeypatch.setattr(httpx, 'Client', lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))


def test_osv_epss_kev_network_pipeline(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        if request.url.path == '/v1/querybatch':
            assert json.loads(request.content) == {'queries': [{'package': {'name': 'lodash', 'ecosystem': 'npm'}, 'version': '4.17.20'}]}
            return httpx.Response(200, json={'results': [{'vulns': [{'id': 'GHSA-test-advisory'}]}]})
        if request.url.path == '/v1/vulns/GHSA-test-advisory':
            return httpx.Response(200, json={'id': 'GHSA-test-advisory', 'aliases': ['CVE-2021-23337'], 'summary': 'Synthetic advisory test', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}], 'affected': [{'package': {'name': 'lodash'}, 'ranges': [{'events': [{'fixed': '4.17.21'}]}]}]})
        if request.url.host == 'api.first.org':
            return httpx.Response(200, json={'data': [{'cve': 'CVE-2021-23337', 'epss': '0.25', 'date': '2026-09-28'}]})
        if request.url.host == 'www.cisa.gov':
            return httpx.Response(200, json={'vulnerabilities': [{'cveID': 'CVE-2021-23337'}], 'dateReleased': '2026-09-28'})
        raise AssertionError(request.url)
    install_transport(monkeypatch, handler)
    packages, _ = inventory([('package.json', '{"dependencies":{"lodash":"4.17.20","other":"^1.0"}}')])
    findings, engines, warnings = enrich(packages)
    assert len(findings) == 1
    finding = findings[0]
    assert finding['cvss'] == 9.8
    assert finding['epss'] == .25
    assert finding['kev'] is True
    assert finding['fixed_versions'] == ['4.17.21']
    assert all(item['status'] == 'completed' for item in engines)
    assert 'unresolved' in warnings[0]
    assert len(requests) == 4
    assert all('source' not in request.content.decode() for request in requests)


def test_failed_intelligence_does_not_become_a_clean_result(monkeypatch):
    install_transport(monkeypatch, lambda request: httpx.Response(503, json={}))
    packages, _ = inventory([('package.json', '{"dependencies":{"lodash":"4.17.20"}}')])
    findings, engines, warnings = enrich(packages)
    assert not findings
    assert engines[0]['status'] == 'failed'


def test_unrated_advisory_and_missing_exploit_scores_remain_unknown(monkeypatch):
    def handler(request):
        if request.url.path == '/v1/querybatch':
            return httpx.Response(200, json={'results': [{'vulns': [{'id': 'GHSA-test'}]}]})
        if request.url.path.startswith('/v1/vulns/'):
            return httpx.Response(200, json={'id': 'GHSA-test', 'aliases': ['CVE-2026-12345']})
        return httpx.Response(503, json={})
    install_transport(monkeypatch, handler)
    packages, _ = inventory([('requirements.txt', 'flask==1.0')])
    findings, engines, _ = enrich(packages)
    assert findings[0]['epss'] is None
    assert findings[0]['kev'] is None
    assert findings[0]['cvss'] is None
    assert findings[0]['severity_source'].startswith('Unrated')
    assert {e['name'] for e in engines if e['status'] == 'failed'} == {'EPSS', 'CISA KEV'}


def test_offline_scan_never_calls_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Network must be opt-in')
    monkeypatch.setattr(httpx, 'Client', forbidden)
    (tmp_path/'requirements.txt').write_text('flask==1.0')
    report = scan_directory(tmp_path)
    assert not any(item['category'] == 'dependencies' for item in report['findings'])
    assert any(engine['status'] == 'skipped' and 'OSV' in engine['name'] for engine in report['engines'])
