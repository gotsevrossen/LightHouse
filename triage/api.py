from __future__ import annotations

import logging
import os
import platform
import shutil
import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import Database, PasswordTooLongError, default_db_path
from .schema import AlertDetailOwner, AlertStatus

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12
# bcrypt's own limit. Values above it are rejected, never silently truncated.
MAX_PASSWORD_LENGTH = 72
ALL_ROLES = ("owner", "analyst", "admin")


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() not in ("", "0", "false", "no", "off")


db = Database(default_db_path())
db.initialize()

# The schema, the route table and the version string are only published when the
# operator explicitly asks for them. A LAN scanner gets nothing.
_dev_mode = _flag("LIGHTHOUSE_DEV")
app = FastAPI(
    title="LightHouse Local API",
    version="0.1.0",
    docs_url="/docs" if _dev_mode else None,
    redoc_url="/redoc" if _dev_mode else None,
    openapi_url="/openapi.json" if _dev_mode else None,
)

# Production serves the dashboard same-origin, so no CORS middleware is installed
# at all unless LIGHTHOUSE_CORS_ORIGINS names the origins that need it.
CORS_ORIGINS = [origin.strip() for origin in os.getenv("LIGHTHOUSE_CORS_ORIGINS", "").split(",") if origin.strip()]
if CORS_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

security = HTTPBearer()


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    role: str


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class Setting(BaseModel): key: str; value: str
class StatusChange(BaseModel): status: AlertStatus


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """Anything unexpected becomes one identical, detail-free 500.

    Without this, a failure that only occurs for a real account (an over-long
    password reaching bcrypt, for instance) is itself an account-existence oracle.
    """
    logger.exception("Unhandled error serving %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def current_user(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    user = db.user_for_token(credentials.credentials)
    if not user: raise HTTPException(401, "Invalid or expired session")
    return user


def active_user(user=Depends(current_user)):
    """A user who still owes a password change may not use the appliance.

    Only login, logout, the password change itself and /health skip this, and they
    do so by not depending on it.
    """
    if user["must_change_password"]:
        raise HTTPException(403, "Password change required")
    return user


def require(*roles: str):
    """Role gate. Every route that is not an auth or health route goes through here,
    so it also inherits the must-change-password check via active_user."""
    def check(user=Depends(active_user)):
        if user["role"] not in roles: raise HTTPException(403, "Insufficient role")
        return user
    return check


@app.post("/api/auth/login")
def login(body: Login):
    user = db.authenticate(body.username, body.password)
    if not user: raise HTTPException(401, "Invalid credentials")
    return user


@app.post("/api/auth/logout", status_code=204)
def logout(user=Depends(current_user)):
    db.revoke_token(user["token"])
    return Response(status_code=204)


@app.post("/api/auth/password")
def change_password(body: PasswordChange, user=Depends(current_user)):
    if not db.check_password(user["id"], body.current_password):
        raise HTTPException(401, "Current password is incorrect")
    try:
        db.set_password(user["id"], body.new_password)
    except PasswordTooLongError:
        raise HTTPException(422, f"Password must be at most {MAX_PASSWORD_LENGTH} bytes")
    # Keep this session, drop everywhere else the old password is still logged in.
    db.revoke_user_sessions(user["id"], except_token=user["token"])
    return {"ok": True}


@app.patch("/api/users/{user_id}/password")
def reset_password(user_id: int, body: PasswordReset, user=Depends(require("admin"))):
    try:
        # An admin-chosen password is known to someone other than its owner, so the
        # owner is required to replace it at next login.
        updated = db.set_password(user_id, body.new_password, must_change_password=True)
    except PasswordTooLongError:
        raise HTTPException(422, f"Password must be at most {MAX_PASSWORD_LENGTH} bytes")
    if not updated: raise HTTPException(404, "User not found")
    db.revoke_user_sessions(user_id)
    return {"ok": True}


@app.get("/api/alerts")
def alerts(severity: str | None = None, status: str | None = None, user=Depends(require(*ALL_ROLES))): return db.list_alerts(severity, status)


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: int, user=Depends(require(*ALL_ROLES))):
    result = db.get_alert(alert_id)
    if not result: raise HTTPException(404, "Alert not found")
    if user["role"] == "owner":
        # Raw sensor evidence and analyst reasoning are filtered here, on the
        # server. The dashboard hiding the Advanced tab is presentation, not access
        # control.
        return AlertDetailOwner.from_detail(result)
    return result


@app.patch("/api/alerts/{alert_id}/status")
def change_status(alert_id: int, body: StatusChange, user=Depends(require(*ALL_ROLES))):
    if not db.update_status(alert_id, body.status): raise HTTPException(404, "Alert not found")
    return {"ok": True}


@app.get("/api/trends")
def trends(user=Depends(require(*ALL_ROLES))): return db.trends()


@app.get("/api/preferences")
def preferences(user=Depends(require(*ALL_ROLES))): return db.user_settings(user["username"])


@app.put("/api/preferences")
def set_preference(body: Setting, user=Depends(require(*ALL_ROLES))):
    if body.key not in {"notification_threshold", "alert_sensitivity"}: raise HTTPException(422, "Unsupported preference")
    db.set_user_setting(user["username"], body.key, body.value)
    return {"ok": True}


@app.get("/api/advanced/health")
def health(user=Depends(require("analyst", "admin"))):
    return {"database": "available", "model": os.getenv("LIGHTHOUSE_MODEL", "qwen3:8b"), "platform": platform.platform(), "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None, "disk_free_bytes": shutil.disk_usage(".").free}


@app.get("/api/advanced/devices")
def devices(user=Depends(require("analyst", "admin"))): return db.devices()


@app.get("/api/users")
def users(user=Depends(require("admin"))):
    return db.users()


@app.post("/api/users", status_code=201)
def create_user(body: UserCreate, user=Depends(require("admin"))):
    if body.role not in set(ALL_ROLES): raise HTTPException(422, "Invalid role")
    try:
        # The admin choosing this password knows it, so the owner of the account must
        # replace it at first login — same rule as an admin-driven password reset.
        db.create_user(body.username, body.password, body.role, must_change_password=True)
    except sqlite3.IntegrityError:
        # Only a constraint violation is a name collision. A full disk or a locked
        # database must not be reported as one.
        raise HTTPException(409, "Username already exists")
    except PasswordTooLongError:
        raise HTTPException(422, f"Password must be at most {MAX_PASSWORD_LENGTH} bytes")
    return {"ok": True}


@app.get("/health")
def healthcheck(): return {"ok": True}


# Mounted last so it can never shadow an /api route. In production the built
# dashboard is served from here, same-origin, instead of exposing the Vite dev
# server on the LAN. Absent in development, where the directory does not exist.
STATIC_DIR = Path(os.getenv("LIGHTHOUSE_STATIC_DIR", "dashboard/dist"))
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="dashboard")
