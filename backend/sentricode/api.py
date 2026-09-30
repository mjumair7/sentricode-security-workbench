"""Single-owner HTTP interface for the SentriCode workbench."""
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import ipaddress
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Literal
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, ai
from .auth import COOKIE, authenticated, require_owner, seal, set_session, unseal
from .config import Settings
from .db import Database
from .ingestion import IngestionError, extract_zip, parse_github_url, validate_ref
from .models import Audit, Finding, Preference, Repository, Scan, uid, utcnow
from .worker import clean_job, run_worker

PREFIX = "/api/v1"
VERSION = __version__
POLICY = {"fail_on": ["critical", "high"], "max_high": 0, "fail_on_secrets": True}
Mode = Literal["quick", "standard", "deep"]


class LoginBody(BaseModel):
    token: str = Field(min_length=1, max_length=1024)


class GithubBody(BaseModel):
    url: str = Field(max_length=400)
    ref: str | None = Field(None, max_length=200)
    mode: Mode = "standard"
    network: bool = False


class StatusBody(BaseModel):
    status: Literal["open", "confirmed", "in_progress", "resolved", "accepted_risk", "false_positive"]
    reason: str = Field("", max_length=2000)


class AnalysisBody(BaseModel):
    audience: Literal["developer", "beginner", "security"] = "developer"
    consent: bool = False


class PolicyBody(BaseModel):
    fail_on: list[Literal["critical", "high", "medium", "low", "info"]] = Field(default_factory=lambda: ["critical", "high"], max_length=5)
    max_high: int = Field(0, ge=0, le=10000)
    fail_on_secrets: bool = True


def timestamp(value):
    if value is None:
        return None
    result = value.isoformat()
    return result if value.tzinfo else result + "+00:00"


def finding_json(finding: Finding) -> dict:
    return {**finding.data, "id": finding.id, "fingerprint": finding.fingerprint, "scan_id": finding.scan_id, "repository_id": finding.repository_id, "status": finding.status, "reason": finding.reason, "updated_at": timestamp(finding.updated_at)}


def scan_json(scan: Scan, session=None, full: bool = False) -> dict:
    report = {key: value for key, value in (scan.report or {}).items() if full or key not in {"sbom", "dependencies", "findings"}}
    result = {**report, "id": scan.id, "repository_id": scan.repository_id, "repository_name": scan.repository_name, "status": scan.status, "mode": scan.mode, "created_at": timestamp(scan.created_at), "started_at": timestamp(scan.started_at), "completed_at": timestamp(scan.completed_at), "stage": scan.stage, "error": scan.error, "network": bool(scan.options.get("network")), "source": scan.options.get("source"), "ref": scan.options.get("ref")}
    if full and session:
        result["findings"] = [finding_json(finding) for finding in session.scalars(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.created_at))]
    return result


def audit(session, action: str, resource: str, detail: dict | None = None):
    session.add(Audit(action=action, resource=resource, detail=detail or {}))


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    database = Database(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        stop = threading.Event()
        worker = None
        if settings.embedded_worker:
            worker = threading.Thread(target=run_worker, args=(database, settings, stop), daemon=True, name="sentricode-worker")
            worker.start()
        yield
        stop.set()
        if worker:
            await run_in_threadpool(worker.join, 5)
        database.close()

    app = FastAPI(title="SentriCode", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.database = database
    allowed_hosts = {urlparse(origin).hostname for origin in settings.origins}
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts), www_redirect=False)
    attempts: dict[str, deque] = defaultdict(deque)
    enqueue_lock = threading.Lock()

    @app.middleware("http")
    async def safety_headers(request: Request, call_next):
        if not settings.token:
            try:
                local = ipaddress.ip_address(request.client.host).is_loopback
            except (ValueError, AttributeError):
                local = False
            if not local:
                return JSONResponse({"detail": "Remote access requires SENTRICODE_TOKEN. See the deployment guide."}, status_code=403)
        public_routes = {PREFIX + "/health", PREFIX + "/auth/session", PREFIX + "/auth/login", PREFIX + "/auth/logout", PREFIX + "/auth/github/start", PREFIX + "/auth/github/callback"}
        if request.url.path.startswith(PREFIX + "/") and request.url.path not in public_routes and not authenticated(request, settings):
            return JSONResponse({"detail": "Sign in with your owner token to continue"}, status_code=401)
        unsafe = request.method not in {"GET", "HEAD", "OPTIONS"}
        if unsafe:
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") not in settings.origins:
                return JSONResponse({"detail": "Request origin is not allowed"}, status_code=403)
            if not origin and not request.headers.get("authorization", "").startswith("Bearer ") and request.headers.get("x-sentricode-client") != "cli":
                return JSONResponse({"detail": "Send an allowed Origin header, Bearer token, or X-Sentricode-Client: cli"}, status_code=403)
            kind = "login" if request.url.path == PREFIX + "/auth/login" else "mutation"
            key = f"{request.client.host if request.client else 'unknown'}:{kind}"
            now = time.monotonic()
            if len(attempts) > 4096:
                for old_key in list(attempts):
                    if not attempts[old_key] or attempts[old_key][-1] < now - 60:
                        del attempts[old_key]
                if len(attempts) > 4096 and key not in attempts:
                    return JSONResponse({"detail": "Server is busy; try again shortly"}, status_code=429)
            queue = attempts[key]
            while queue and queue[0] < now - 60:
                queue.popleft()
            if len(queue) >= (8 if kind == "login" else 30):
                return JSONResponse({"detail": "Too many requests. Try again in a minute."}, status_code=429, headers={"Retry-After": "60"})
            queue.append(now)
            # Bound the complete request before the multipart parser creates spool files.
            limit = (settings.max_upload_mb * 1024 * 1024 + 64 * 1024) if request.url.path == PREFIX + "/scans/upload" else 64 * 1024
            try:
                if int(request.headers.get("content-length", "0")) > limit:
                    return JSONResponse({"detail": "Request exceeds the upload limit"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > limit:
                    return JSONResponse({"detail": "Request exceeds the upload limit"}, status_code=413)
                body.extend(chunk)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith(PREFIX):
            response.headers["Cache-Control"] = "no-store"
        if settings.secure_cookie:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def db_session():
        with database.session() as session:
            yield session

    def get_scan(scan_id: str, session) -> Scan:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        return scan

    def check_capacity(session):
        active = session.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running"])))
        if active >= 10:
            raise HTTPException(429, "The queue has 10 active scans. Wait for one to finish.")

    def add_scan(session, *, scan_id: str, name: str, source: str, mode: str, options: dict, url: str | None = None):
        with enqueue_lock:
            check_capacity(session)
            identity = f"{source}:{url or name.casefold()}"
            repo = session.scalar(select(Repository).where(Repository.identity == identity))
            if not repo:
                repo = Repository(name=name, source=source, url=url, identity=identity)
                session.add(repo)
                session.flush()
            saved_policy = session.get(Preference, "policy")
            policy = saved_policy.value if saved_policy else POLICY
            scan = Scan(id=scan_id, repository_id=repo.id, repository_name=repo.name, mode=mode, options={"source": source, **options, "policy": policy})
            session.add(scan)
            audit(session, "scan.queued", scan_id, {"source": source, "network": bool(options.get("network")), "mode": mode})
            session.commit()
            return scan_json(scan)

    @app.get(PREFIX + "/health")
    def health():
        return {"status": "ok", "version": VERSION}

    @app.get(PREFIX + "/auth/session")
    def auth_session(request: Request):
        signed_in = authenticated(request, settings)
        return {"authenticated": signed_in, "login_required": bool(settings.token), "user": {"name": "Workspace owner", "login": settings.github_owner or "owner"} if signed_in else None, "github_configured": settings.github_configured}

    @app.post(PREFIX + "/auth/login")
    def login(body: LoginBody, session=Depends(db_session)):
        if not settings.token or not secrets.compare_digest(body.token.encode(), settings.token.encode()):
            raise HTTPException(401, "Invalid owner token")
        response = JSONResponse({"authenticated": True})
        set_session(response, settings)
        audit(session, "auth.login", "owner")
        session.commit()
        return response

    @app.post(PREFIX + "/auth/logout")
    def logout():
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(COOKIE, path="/", secure=settings.secure_cookie, httponly=True, samesite="strict")
        return response

    @app.get(PREFIX + "/auth/github/start")
    def github_start():
        if not settings.github_configured:
            raise HTTPException(503, "GitHub OAuth requires a client ID, secret, allowed owner, and owner token")
        state = secrets.token_urlsafe(32)
        redirect_uri = settings.public_url + PREFIX + "/auth/github/callback"
        response = RedirectResponse("https://github.com/login/oauth/authorize?" + urlencode({"client_id": settings.github_client_id, "redirect_uri": redirect_uri, "state": state, "scope": "read:user"}))
        response.set_cookie("sentricode_oauth", seal(settings, {"state": state, "exp": int(time.time()) + 600, "purpose": "oauth"}), secure=settings.secure_cookie, httponly=True, samesite="lax", max_age=600, path=PREFIX + "/auth/github")
        return response

    @app.get(PREFIX + "/auth/github/callback")
    async def github_callback(request: Request, code: str = "", state: str = "", session=Depends(db_session)):
        saved = unseal(settings, request.cookies.get("sentricode_oauth", ""))
        if not settings.github_configured or not saved or saved.get("purpose") != "oauth" or not secrets.compare_digest(saved.get("state", "").encode(), state.encode()) or not code:
            raise HTTPException(400, "GitHub sign-in expired or the state check failed")
        try:
            async with httpx.AsyncClient(timeout=20, trust_env=False) as client:
                token_response = await client.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, json={"client_id": settings.github_client_id, "client_secret": settings.github_client_secret, "code": code, "redirect_uri": settings.public_url + PREFIX + "/auth/github/callback"})
                token_response.raise_for_status()
                access_token = token_response.json().get("access_token")
                if not access_token:
                    raise ValueError("No token")
                owner_response = await client.get("https://api.github.com/user", headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {access_token}"})
                owner_response.raise_for_status()
                owner = owner_response.json().get("login", "")
        except (httpx.HTTPError, ValueError):
            raise HTTPException(502, "GitHub sign-in failed. Try again.") from None
        if owner.casefold() != settings.github_owner.casefold():
            raise HTTPException(403, "This workspace is restricted to its configured GitHub owner")
        response = RedirectResponse("/")
        response.delete_cookie("sentricode_oauth", path=PREFIX + "/auth/github")
        set_session(response, settings, owner)
        audit(session, "auth.github_login", "owner")
        session.commit()
        return response

    protected = [Depends(require_owner)]

    @app.get(PREFIX + "/settings", dependencies=protected)
    def get_settings():
        return {"ai_configured": bool(settings.openai_key), "ai_model": settings.ai_model if settings.openai_key else None, "github_configured": settings.github_configured, "github_import_configured": bool(settings.github_token), "network_enabled": settings.network_enabled, "external_enabled": False, "auth_required": bool(settings.token), "max_upload_mb": settings.max_upload_mb, "max_extracted_mb": settings.max_extracted_mb, "max_files": settings.max_files, "embedded_worker": settings.embedded_worker, "retention": "Source is removed after each scan. Reports remain until you delete them.", "deployment": "single-owner", "version": VERSION}

    @app.get(PREFIX + "/repositories", dependencies=protected)
    def repositories(session=Depends(db_session)):
        output = []
        for repo in session.scalars(select(Repository).order_by(Repository.created_at.desc())):
            latest = session.scalar(select(Scan).where(Scan.repository_id == repo.id).order_by(Scan.created_at.desc()).limit(1))
            count = session.scalar(select(func.count()).select_from(Scan).where(Scan.repository_id == repo.id))
            output.append({"id": repo.id, "name": repo.name, "source": repo.source, "url": repo.url, "created_at": timestamp(repo.created_at), "scan_count": count, "latest_scan": scan_json(latest) if latest else None})
        return output

    @app.get(PREFIX + "/scans", dependencies=protected)
    def scans(session=Depends(db_session)):
        return [scan_json(scan) for scan in session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(500))]

    @app.get(PREFIX + "/scans/{scan_id}", dependencies=protected)
    def scan_detail(scan_id: str, session=Depends(db_session)):
        return scan_json(get_scan(scan_id, session), session, full=True)

    @app.post(PREFIX + "/scans/upload", status_code=202, dependencies=protected)
    async def upload_scan(file: UploadFile = File(...), name: str = Form(""), mode: Mode = Form("standard"), network: bool = Form(False), session=Depends(db_session)):
        check_capacity(session)
        if network and not settings.network_enabled:
            raise HTTPException(400, "Network enrichment is disabled by the server owner")
        if not (file.filename or "").lower().endswith(".zip"):
            raise HTTPException(400, "Upload a .zip source archive")
        project_name = name.strip() or Path(file.filename).stem
        if not project_name or len(project_name) > 120 or any(ord(char) < 32 for char in project_name):
            raise HTTPException(400, "Choose a project name between 1 and 120 characters")
        scan_id = uid()
        job = settings.jobs_dir / scan_id
        job.mkdir(mode=0o700)
        archive = job / "repository.zip"
        try:
            total = 0
            with archive.open("xb") as destination:
                while chunk := await file.read(64 * 1024):
                    total += len(chunk)
                    if total > settings.max_upload_mb * 1024 * 1024:
                        raise HTTPException(413, "Archive exceeds the upload limit")
                    destination.write(chunk)
            root = await run_in_threadpool(extract_zip, archive, job / "source", settings)
            archive.unlink()
            return add_scan(session, scan_id=scan_id, name=project_name, source="upload", mode=mode, options={"root": str(root.relative_to(job)), "network": network})
        except IngestionError as exc:
            clean_job(settings, scan_id)
            raise HTTPException(400, str(exc)) from None
        except Exception:
            clean_job(settings, scan_id)
            raise
        finally:
            await file.close()

    @app.post(PREFIX + "/scans/github", status_code=202, dependencies=protected)
    def github_scan(body: GithubBody, session=Depends(db_session)):
        check_capacity(session)
        if body.network and not settings.network_enabled:
            raise HTTPException(400, "Network enrichment is disabled by the server owner")
        try:
            owner, repo = parse_github_url(body.url)
            ref = validate_ref(body.ref)
        except IngestionError as exc:
            raise HTTPException(400, str(exc)) from None
        url = f"https://github.com/{owner}/{repo}"
        return add_scan(session, scan_id=uid(), name=f"{owner}/{repo}", source="github", mode=body.mode, url=url, options={"url": url, "ref": ref, "network": body.network})

    @app.post(PREFIX + "/scans/demo", status_code=202, dependencies=protected)
    def demo_scan(session=Depends(db_session)):
        check_capacity(session)
        return add_scan(session, scan_id=uid(), name="SentriCode demo · intentionally vulnerable", source="demo", mode="standard", options={"network": False})

    @app.get(PREFIX + "/scans/{scan_id}/findings", dependencies=protected)
    def scan_findings(scan_id: str, session=Depends(db_session)):
        get_scan(scan_id, session)
        return [finding_json(finding) for finding in session.scalars(select(Finding).where(Finding.scan_id == scan_id))]

    @app.patch(PREFIX + "/findings/{finding_id}", dependencies=protected)
    def update_finding(finding_id: str, body: StatusBody, session=Depends(db_session)):
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        if body.status in {"resolved", "accepted_risk", "false_positive"} and not body.reason.strip():
            raise HTTPException(400, "Add a reason when resolving or dismissing a finding")
        previous = finding.status
        from .analysis.common import redact
        reason = redact(body.reason.strip())
        for related in session.scalars(select(Finding).where(Finding.repository_id == finding.repository_id, Finding.fingerprint == finding.fingerprint)):
            related.status = body.status
            related.reason = reason
            related.updated_at = utcnow()
        audit(session, "finding.status_changed", finding_id, {"from": previous, "to": body.status, "reason": reason, "repository_id": finding.repository_id})
        session.commit()
        return finding_json(finding)

    @app.post(PREFIX + "/findings/{finding_id}/analysis", dependencies=protected)
    async def finding_analysis(finding_id: str, body: AnalysisBody, session=Depends(db_session)):
        if not body.consent:
            raise HTTPException(400, "Explicit consent is required before requesting guidance")
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        try:
            result = await ai.analyze(finding_json(finding), body.audience, settings)
        except (httpx.HTTPError, ValueError):
            raise HTTPException(502, "AI guidance is unavailable. Check the provider configuration and try again.") from None
        audit(session, "finding.analysis_requested", finding_id, {"provider": result["provider"], "audience": body.audience, "consent": True})
        session.commit()
        return result

    @app.get(PREFIX + "/scans/{scan_id}/export", dependencies=protected)
    def export_scan(scan_id: str, format: Literal["json", "sarif", "csv", "sbom"] = "json", session=Depends(db_session)):
        scan = get_scan(scan_id, session)
        if scan.status != "completed":
            raise HTTPException(409, "Wait for the scan to finish before exporting")
        from .exports import to_csv, to_sarif
        report = scan_json(scan, session, full=True)
        if format == "csv":
            content, media_type, extension = to_csv(report), "text/csv", "csv"
        else:
            value = to_sarif(report) if format == "sarif" else report.get("sbom", {}) if format == "sbom" else report
            content, media_type, extension = json.dumps(value, indent=2), "application/json", "sarif" if format == "sarif" else "json"
        return Response(content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="sentricode-{scan_id[:8]}-{format}.{extension}"'})

    @app.get(PREFIX + "/scans/{scan_id}/compare", dependencies=protected)
    def compare_scans(scan_id: str, baseline: str, session=Depends(db_session)):
        scan = get_scan(scan_id, session)
        previous = get_scan(baseline, session)
        if scan.repository_id != previous.repository_id:
            raise HTTPException(400, "Compare scans from the same repository")
        if scan.status != "completed" or previous.status != "completed":
            raise HTTPException(409, "Both scans must be completed")
        current = {finding.fingerprint: finding_json(finding) for finding in session.scalars(select(Finding).where(Finding.scan_id == scan_id))}
        old = {finding.fingerprint: finding_json(finding) for finding in session.scalars(select(Finding).where(Finding.scan_id == baseline))}
        return {"new": [current[key] for key in current.keys() - old.keys()], "resolved": [old[key] for key in old.keys() - current.keys()], "unchanged": len(current.keys() & old.keys())}

    @app.delete(PREFIX + "/scans/{scan_id}", dependencies=protected)
    def delete_scan(scan_id: str, session=Depends(db_session)):
        scan = get_scan(scan_id, session)
        if scan.status in {"queued", "running"}:
            raise HTTPException(409, "Wait for an active scan to finish before deleting it")
        session.execute(delete(Finding).where(Finding.scan_id == scan_id))
        session.delete(scan)
        audit(session, "scan.deleted", scan_id)
        session.commit()
        clean_job(settings, scan_id)
        return {"deleted": True}

    @app.get(PREFIX + "/audit", dependencies=protected)
    def audit_log(session=Depends(db_session)):
        return [{"id": event.id, "action": event.action, "resource": event.resource, "created_at": timestamp(event.created_at), "detail": event.detail} for event in session.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(200))]

    @app.get(PREFIX + "/policy", dependencies=protected)
    def get_policy(session=Depends(db_session)):
        value = session.get(Preference, "policy")
        return value.value if value else POLICY

    @app.put(PREFIX + "/policy", dependencies=protected)
    def put_policy(body: PolicyBody, session=Depends(db_session)):
        policy = body.model_dump()
        policy["fail_on"] = list(dict.fromkeys(policy["fail_on"]))
        preference = session.get(Preference, "policy")
        if preference:
            preference.value = policy
        else:
            session.add(Preference(key="policy", value=policy))
        audit(session, "policy.updated", "workspace", policy)
        session.commit()
        return policy

    static = Path(__file__).parent / "static"
    if static.is_dir():
        app.mount("/", StaticFiles(directory=static, html=True), name="frontend")
    else:
        @app.get("/")
        def welcome():
            return {"name": "SentriCode", "message": "API is running. Start the frontend dev server or build frontend/out into backend/sentricode/static.", "health": PREFIX + "/health"}
    return app


app = create_app()
