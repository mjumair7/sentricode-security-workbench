import asyncio
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from sentricode.ai import analyze
from sentricode.api import create_app
from sentricode.config import Settings
from sentricode.ingestion import IngestionError, download_github

ORIGIN = "http://127.0.0.1:8000"
TOKEN = "a-random-test-owner-token-123456789"


def test_ai_sends_only_redacted_finding_with_storage_disabled(monkeypatch, tmp_path):
    captured = []
    original = httpx.AsyncClient

    def handler(request):
        import json
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"output": [{"type": "message", "content": [{"type": "output_text", "text": "Use a parameterized query and test it."}]}]})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    finding = {"category": "sast", "title": "Query construction", "file": "/private/sensitive-name.py", "evidence": 'password = "q3Yx_Secret-that-must-not-leave"', "description": "Unsafe SQL concatenation", "remediation": "Parameterize values"}
    settings = Settings(data_dir=tmp_path, openai_key="provider-key", embedded_worker=False)
    result = asyncio.run(analyze(finding, "developer", settings))
    assert result["provider"] == "openai"
    assert captured[0]["store"] is False
    assert "tools" not in captured[0]
    assert "q3Yx_Secret-that-must-not-leave" not in captured[0]["input"]
    assert "sensitive-name" not in captured[0]["input"]
    finding["category"] = "secrets"
    finding["evidence"] = "some-special-secret-format"
    asyncio.run(analyze(finding, "security", settings))
    assert "some-special-secret-format" not in captured[-1]["input"]


def test_no_provider_key_never_contacts_network(monkeypatch, tmp_path):
    def fail(**kwargs):
        raise AssertionError("Network must not be called")
    monkeypatch.setattr(httpx, "AsyncClient", fail)
    result = asyncio.run(analyze({"title": "Unsafe SQL", "remediation": "Use parameters"}, "beginner", Settings(data_dir=tmp_path, openai_key="")))
    assert result["provider"] == "local"
    assert "Use parameters" in result["analysis"]


def test_oauth_owner_restriction_and_state(monkeypatch, tmp_path):
    original = httpx.AsyncClient
    login = {"value": "workspace-owner"}
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.url.host == "github.com":
            return httpx.Response(200, json={"access_token": "temporary-github-token"})
        return httpx.Response(200, json={"login": login["value"]})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    settings = Settings(data_dir=tmp_path, token=TOKEN, embedded_worker=False, github_client_id="client", github_client_secret="secret", github_owner="workspace-owner")
    with TestClient(create_app(settings), base_url=ORIGIN, client=("127.0.0.1", 5100), follow_redirects=False) as client:
        response = client.get("/api/v1/auth/github/start")
        assert response.status_code == 307
        state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        assert client.get("/api/v1/auth/github/callback?code=code&state=wrong").status_code == 400
        assert client.get("/api/v1/auth/github/callback", params={"code": "code", "state": "invalid-☃"}).status_code == 400
        assert calls == []
        login["value"] = "intruder"
        assert client.get(f"/api/v1/auth/github/callback?code=code&state={state}").status_code == 403
        assert client.get("/api/v1/scans").status_code == 401
        login["value"] = "workspace-owner"
        assert client.get(f"/api/v1/auth/github/callback?code=code&state={state}").status_code == 307
        assert client.get("/api/v1/scans").status_code == 200


def test_github_download_rejects_redirect_to_arbitrary_host(monkeypatch, tmp_path):
    original = httpx.Client
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://127.0.0.1/private"})

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    with pytest.raises(IngestionError, match="unexpected archive location"):
        download_github("https://github.com/owner/repo", "main", tmp_path / "repo.zip", Settings(data_dir=tmp_path, github_token="private-token"))
    assert len(calls) == 1
    assert calls[0].startswith("https://api.github.com/")
