"""Small single-owner auth; no registration or multi-tenant authorization."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from fastapi import HTTPException, Request
from .config import Settings

COOKIE = "sentricode_session"
SESSION_SECONDS = 12 * 60 * 60


def seal(settings: Settings, data: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(settings.token.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def unseal(settings: Settings, value: str) -> dict | None:
    try:
        payload, signature = value.rsplit(".", 1)
        expected = hmac.new(settings.token.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return data if data.get("exp", 0) > time.time() else None
    except (ValueError, TypeError, KeyError):
        return None


def authenticated(request: Request, settings: Settings) -> bool:
    if not settings.token:
        return True
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer ") and secrets.compare_digest(authorization[7:].encode(), settings.token.encode()):
        return True
    session = unseal(settings, request.cookies.get(COOKIE, ""))
    return bool(session and session.get("purpose") == "session")


def require_owner(request: Request):
    if not authenticated(request, request.app.state.settings):
        raise HTTPException(401, "Sign in with your owner token to continue")


def set_session(response, settings: Settings, login: str = "owner"):
    response.set_cookie(COOKIE, seal(settings, {"purpose": "session", "exp": int(time.time()) + SESSION_SECONDS, "login": login}), httponly=True, secure=settings.secure_cookie, samesite="strict", max_age=SESSION_SECONDS, path="/")
