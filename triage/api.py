from __future__ import annotations

import os
import platform
import shutil
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

from .db import Database
from .schema import AlertStatus

db = Database(os.getenv("GUARD_DB_PATH", "guard.db"))
db.initialize()
app = FastAPI(title="GUARD Local API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer()

class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("password")
    @classmethod
    def bcrypt_length(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 UTF-8 bytes")
        return value

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    password: str = Field(min_length=12, max_length=256)
    role: str

    @field_validator("password")
    @classmethod
    def bcrypt_length(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 UTF-8 bytes")
        return value
class Setting(BaseModel): key: str; value: str
class StatusChange(BaseModel): status: AlertStatus

def current_user(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    user = db.user_for_token(credentials.credentials)
    if not user: raise HTTPException(401, "Invalid or expired session")
    return user

def require(*roles: str):
    def check(user=Depends(current_user)):
        if user["role"] not in roles: raise HTTPException(403, "Insufficient role")
        return user
    return check

@app.post("/api/auth/login")
def login(body: Login):
    user = db.authenticate(body.username, body.password)
    if not user: raise HTTPException(401, "Invalid credentials")
    return user

@app.post("/api/auth/logout", status_code=204)
def logout(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    db.delete_session(credentials.credentials)

@app.get("/api/alerts")
def alerts(severity: str | None = None, status: str | None = None, user=Depends(require("owner", "analyst", "admin"))): return db.list_alerts(severity, status)

@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: int, user=Depends(require("owner", "analyst", "admin"))):
    result = db.get_alert(alert_id)
    if not result: raise HTTPException(404, "Alert not found")
    return result

@app.patch("/api/alerts/{alert_id}/status")
def change_status(alert_id: int, body: StatusChange, user=Depends(require("owner", "analyst", "admin"))):
    if not db.update_status(alert_id, body.status): raise HTTPException(404, "Alert not found")
    return {"ok": True}

@app.get("/api/trends")
def trends(user=Depends(require("owner", "analyst", "admin"))): return db.trends()

@app.get("/api/preferences")
def preferences(user=Depends(require("owner", "analyst", "admin"))): return db.user_settings(user["username"])

@app.put("/api/preferences")
def set_preference(body: Setting, user=Depends(require("owner", "analyst", "admin"))):
    if body.key not in {"notification_threshold", "alert_sensitivity"}: raise HTTPException(422, "Unsupported preference")
    db.set_user_setting(user["username"], body.key, body.value)
    return {"ok": True}

@app.get("/api/advanced/health")
def health(user=Depends(require("analyst", "admin"))):
    return {"database": "available", "model": os.getenv("GUARD_MODEL", "qwen3:8b"), "platform": platform.platform(), "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None, "disk_free_bytes": shutil.disk_usage(".").free}

@app.get("/api/advanced/devices")
def devices(user=Depends(require("analyst", "admin"))): return db.devices()

@app.get("/api/users")
def users(user=Depends(require("admin"))):
    return db.users()

@app.post("/api/users", status_code=201)
def create_user(body: UserCreate, user=Depends(require("admin"))):
    if body.role not in {"owner", "analyst", "admin"}: raise HTTPException(422, "Invalid role")
    try: db.create_user(body.username, body.password, body.role)
    except Exception: raise HTTPException(409, "Username already exists")
    return {"ok": True}

@app.get("/health")
def healthcheck(): return {"ok": True}
