from datetime import timedelta
from io import BytesIO
from pathlib import Path
import stat
from zipfile import ZipFile, ZipInfo

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sentricode.api import create_app
from sentricode.config import Settings
from sentricode.ingestion import IngestionError, extract_zip, parse_github_url
from sentricode.models import Finding, Scan, utcnow
from sentricode.worker import claim_job, process_job

ORIGIN = "http://127.0.0.1:8000"
TOKEN = "a-random-test-owner-token-123456789"


def archive(files: dict[str, str]) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w") as zipped:
        for name, content in files.items():
            zipped.writestr(name, content)
    return output.getvalue()


@pytest.fixture
def client(tmp_path):
    application = create_app(Settings(data_dir=tmp_path, embedded_worker=False))
    with TestClient(application, base_url=ORIGIN, client=("127.0.0.1", 5000), headers={"Origin": ORIGIN}) as test_client:
        yield test_client


def run_next(client):
    database = client.app.state.database
    claim = claim_job(database)
    assert claim is not None
    process_job(database, client.app.state.settings, *claim)
    return client.get(f"/api/v1/scans/{claim[0]}").json()


def upload(client, content, name="my-project"):
    return client.post("/api/v1/scans/upload", files={"file": ("source.zip", archive(content), "application/zip")}, data={"name": name})


def test_upload_report_lifecycle_and_exports(client):
    response = upload(client, {"project/app.py": "import pickle\npickle.loads(data)\nAPI_KEY = 'live_local_secret_83624'\n"})
    assert response.status_code == 202
    scan = run_next(client)
    assert scan["status"] == "completed", scan
    assert scan["files_scanned"] == 1
    assert scan["findings"]
    assert "live_local_secret_83624" not in str(scan)
    assert not (client.app.state.settings.jobs_dir / scan["id"]).exists()
    finding = scan["findings"][0]
    endpoint = f"/api/v1/findings/{finding['id']}"
    assert client.patch(endpoint, json={"status": "accepted_risk", "reason": ""}).status_code == 400
    changed = client.patch(endpoint, json={"status": "accepted_risk", "reason": "Internal test fixture; tracked in issue 12"})
    assert changed.status_code == 200
    assert changed.json()["status"] == "accepted_risk"
    denied = client.post(endpoint + "/analysis", json={"consent": False})
    assert denied.status_code == 400
    guidance = client.post(endpoint + "/analysis", json={"consent": True, "audience": "beginner"})
    assert guidance.status_code == 200
    assert guidance.json()["provider"] == "local"
    for kind in ("json", "sarif", "csv", "sbom"):
        exported = client.get(f"/api/v1/scans/{scan['id']}/export?format={kind}")
        assert exported.status_code == 200
        assert "attachment" in exported.headers["content-disposition"]
        assert "live_local_secret_83624" not in exported.text
    events = client.get("/api/v1/audit").json()
    assert any(event["action"] == "finding.status_changed" for event in events)
    assert client.delete(f"/api/v1/scans/{scan['id']}").status_code == 200
    assert client.get(f"/api/v1/scans/{scan['id']}").status_code == 404


def test_scan_compare_tracks_new_and_disappeared_findings(client):
    assert upload(client, {"app.py": "import pickle\npickle.loads(data)\n"}).status_code == 202
    first = run_next(client)
    assert upload(client, {"app.py": "print('hello')\n"}).status_code == 202
    second = run_next(client)
    diff = client.get(f"/api/v1/scans/{second['id']}/compare?baseline={first['id']}")
    assert diff.status_code == 200
    assert diff.json()["resolved"]
    assert diff.json()["new"] == []
    assert diff.json()["unchanged"] == 0


def test_demo_runs_offline_with_honest_label(client):
    queued = client.post("/api/v1/scans/demo")
    assert queued.status_code == 202
    scan = run_next(client)
    assert scan["status"] == "completed", scan
    assert scan["findings"]
    assert scan["network"] is False
    assert "demo" in scan["repository_name"].lower()
    assert "Intentionally vulnerable" in scan["warnings"][0]


def test_origin_host_and_auth_guards(tmp_path):
    application = create_app(Settings(data_dir=tmp_path, embedded_worker=False, token=TOKEN))
    with TestClient(application, base_url=ORIGIN, client=("127.0.0.1", 5000)) as test_client:
        assert test_client.get("/api/v1/health").status_code == 200
        assert test_client.get("/api/v1/scans").status_code == 401
        assert test_client.get("/api/v1/auth/session").json()["authenticated"] is False
        assert test_client.post("/api/v1/auth/login", json={"token": TOKEN}).status_code == 403
        assert test_client.post("/api/v1/auth/login", json={"token": TOKEN}, headers={"Origin": "https://evil.example"}).status_code == 403
        login = test_client.post("/api/v1/auth/login", json={"token": TOKEN}, headers={"Origin": ORIGIN})
        assert login.status_code == 200
        assert "HttpOnly" in login.headers["set-cookie"]
        assert "SameSite=strict" in login.headers["set-cookie"]
        assert test_client.get("/api/v1/scans").status_code == 200
        assert test_client.post("/api/v1/scans/demo", headers={"Origin": "https://evil.example"}).status_code == 403
        assert test_client.get("/api/v1/health", headers={"Host": "evil.example"}).status_code == 400
        assert test_client.post("/api/v1/auth/logout", headers={"Origin": ORIGIN}).status_code == 200
        assert test_client.get("/api/v1/scans").status_code == 401
        assert test_client.post("/api/v1/scans/demo", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 202


def test_local_mode_cannot_accidentally_become_public(tmp_path):
    application = create_app(Settings(data_dir=tmp_path, embedded_worker=False))
    with TestClient(application, base_url=ORIGIN, client=("203.0.113.4", 5000)) as test_client:
        assert test_client.get("/api/v1/scans").status_code == 403
    with pytest.raises(ValueError, match="Public hosting"):
        Settings(public_url="http://security.example.com")
    with pytest.raises(ValueError, match="Public hosting"):
        Settings(public_url="https://security.example.com", token="short")


def test_network_consent_and_github_url_constraints(client):
    for url in ("http://github.com/me/repo", "https://evil.example/repo", "https://github.com@localhost/a/b", "https://github.com/a/b/tree/main", "https://github.com:443/a/b", "https://github.com/a/b?next=http://localhost"):
        assert client.post("/api/v1/scans/github", json={"url": url}).status_code == 400
    assert parse_github_url("https://github.com/owner/repo.git") == ("owner", "repo")
    assert client.post("/api/v1/scans/github", json={"url": "https://github.com/owner/repo", "network": True}).status_code == 400
    response = client.post("/api/v1/scans/github", json={"url": "https://github.com/owner/repo"})
    assert response.status_code == 202
    assert response.json()["source"] == "github"
    assert client.delete("/api/v1/scans/" + response.json()["id"]).status_code == 409


def test_archive_traversal_links_and_size_rejected(client, tmp_path):
    for path in ("../escape.py", "/etc/escape.py", "C:\\escape.py", "safe/../../escape.py"):
        rejected = upload(client, {path: "print('unsafe path')"})
        assert rejected.status_code == 400, rejected.text
    output = BytesIO()
    with ZipFile(output, "w") as zipped:
        info = ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zipped.writestr(info, "/etc/passwd")
    rejected = client.post("/api/v1/scans/upload", files={"file": ("source.zip", output.getvalue())})
    assert rejected.status_code == 400
    assert list(client.app.state.settings.jobs_dir.iterdir()) == []
    settings = Settings(data_dir=tmp_path, max_files=1)
    path = tmp_path / "two.zip"
    path.write_bytes(archive({"a.py": "", "b.py": ""}))
    with pytest.raises(IngestionError, match="too many"):
        extract_zip(path, tmp_path / "extracted", settings)


def test_policy_persists_and_validates(client):
    expected = {"fail_on": ["critical"], "max_high": 5, "fail_on_secrets": False}
    assert client.put("/api/v1/policy", json=expected).json() == expected
    assert client.get("/api/v1/policy").json() == expected
    assert client.put("/api/v1/policy", json={"fail_on": ["imaginary"]}).status_code == 422


def test_queue_claim_is_atomic_and_stale_jobs_are_recovered(client):
    queued = client.post("/api/v1/scans/demo").json()
    database = client.app.state.database
    first_claim = claim_job(database)
    assert first_claim[0] == queued["id"]
    assert claim_job(database) is None
    with database.session() as session:
        scan = session.get(Scan, queued["id"])
        scan.heartbeat_at = utcnow() - timedelta(minutes=10)
        session.commit()
    second_claim = claim_job(database)
    assert second_claim[0] == first_claim[0]
    assert second_claim[1] != first_claim[1]
    process_job(database, client.app.state.settings, *first_claim)
    assert client.get("/api/v1/scans/" + queued["id"]).json()["status"] == "running"
    process_job(database, client.app.state.settings, *second_claim)
    assert client.get("/api/v1/scans/" + queued["id"]).json()["status"] == "completed"


def test_upload_rejects_oversized_body_before_spooling(tmp_path):
    application = create_app(Settings(data_dir=tmp_path, embedded_worker=False, max_upload_mb=1))
    with TestClient(application, base_url=ORIGIN, client=("127.0.0.1", 5000), headers={"Origin": ORIGIN}) as test_client:
        response = upload(test_client, {"big.txt": "z" * 1200000})
        assert response.status_code == 413
        assert list(application.state.settings.jobs_dir.iterdir()) == []


def test_oauth_is_off_unless_restricted_owner_configured(client):
    assert client.get("/api/v1/auth/github/start").status_code == 503
    assert client.get("/api/v1/auth/github/callback?code=untrusted&state=bad").status_code == 400


def test_login_throttles_bruteforce(tmp_path):
    application = create_app(Settings(data_dir=tmp_path, embedded_worker=False, token=TOKEN))
    with TestClient(application, base_url=ORIGIN, client=("127.0.0.1", 5000), headers={"Origin": ORIGIN}) as test_client:
        for _ in range(8):
            assert test_client.post("/api/v1/auth/login", json={"token": "wrong"}).status_code == 401
        assert test_client.post("/api/v1/auth/login", json={"token": "wrong"}).status_code == 429


def test_policy_is_applied_from_submission_snapshot(client):
    policy = {"fail_on": ["critical", "high", "medium", "low"], "max_high": 0, "fail_on_secrets": True}
    client.put("/api/v1/policy", json=policy)
    upload(client, {"app.py": "import pickle\npickle.loads(data)\n"})
    client.put("/api/v1/policy", json={"fail_on": [], "max_high": 10, "fail_on_secrets": False})
    result = run_next(client)
    assert result["policy"]["config"] == policy
    assert result["policy"]["passed"] is False
    assert result["policy"]["violations"]


def test_queued_upload_survives_restart_and_embedded_worker_processes_it(tmp_path):
    import time
    settings = Settings(data_dir=tmp_path, embedded_worker=False)
    with TestClient(create_app(settings), base_url=ORIGIN, client=("127.0.0.1", 5100), headers={"Origin": ORIGIN}) as first:
        queued = upload(first, {"app.py": "import pickle\npickle.loads(data)\n"}).json()
    settings.embedded_worker = True
    with TestClient(create_app(settings), base_url=ORIGIN, client=("127.0.0.1", 5100)) as second:
        for _ in range(50):
            report = second.get("/api/v1/scans/" + queued["id"]).json()
            if report["status"] in {"completed", "failed"}:
                break
            time.sleep(0.05)
        assert report["status"] == "completed", report
        assert report["findings"]
        assert not (settings.jobs_dir / queued["id"]).exists()


def test_malformed_github_url_returns_validation_error(client):
    response = client.post("/api/v1/scans/github", json={"url": "https://[invalid/owner/project"})
    assert response.status_code == 400


def test_concurrent_submission_keeps_queue_cap_and_one_repository(client):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda _: client.post("/api/v1/scans/demo"), range(15)))
    assert sum(response.status_code == 202 for response in responses) == 10
    assert all(response.status_code in {202, 429} for response in responses)
    assert len(client.get("/api/v1/repositories").json()) == 1
    assert len(client.get("/api/v1/scans").json()) == 10


def test_source_directory_failure_ends_worker_heartbeat(client, monkeypatch):
    import threading
    queued = client.post("/api/v1/scans/demo").json()
    database = client.app.state.database
    claim = claim_job(database)
    original = Path.mkdir
    expected = client.app.state.settings.jobs_dir / queued["id"]

    def fail(path, *args, **kwargs):
        if path == expected:
            raise OSError("Simulated full disk")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail)
    process_job(database, client.app.state.settings, *claim)
    scan = client.get("/api/v1/scans/" + queued["id"]).json()
    assert scan["status"] == "failed"
    assert not any(thread.name == "scan-heartbeat-" + queued["id"][:8] for thread in threading.enumerate())


def test_corrupt_compressed_archive_returns_400(client):
    from zipfile import ZIP_DEFLATED
    import struct
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as zipped:
        zipped.writestr("app.py", "print('hello')\n" * 50)
    payload = bytearray(output.getvalue())
    filename_length, extra_length = struct.unpack_from("<HH", payload, 26)
    payload[30 + filename_length + extra_length] = 0xFF
    response = client.post("/api/v1/scans/upload", files={"file": ("source.zip", bytes(payload))})
    assert response.status_code == 400
    assert list(client.app.state.settings.jobs_dir.iterdir()) == []
