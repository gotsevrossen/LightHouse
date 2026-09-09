from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import sqlite3
from typing import Any

import bcrypt

from .dedupe import fingerprint
from .schema import AlertDetail, AlertStatus, NormalizedAlert, Severity, TriageResult

_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"invalid-password", bcrypt.gensalt())


class Database:
    def __init__(self, path: str = "guard.db"):
        self.path = path

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def initialize(self) -> None:
        with self.connect() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, source TEXT NOT NULL, source_event_id TEXT,
              timestamp TEXT NOT NULL, title TEXT NOT NULL, source_ip TEXT, destination_ip TEXT, device TEXT,
              rule_id TEXT, mitre TEXT NOT NULL, raw TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
              duplicate_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_alerts_filter ON alerts(timestamp DESC, status, source);
            CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint, timestamp DESC);
            CREATE TABLE IF NOT EXISTS triage_results (alert_id INTEGER PRIMARY KEY REFERENCES alerts(id), severity TEXT NOT NULL,
              explanation TEXT NOT NULL, recommended_action TEXT NOT NULL, reasoning TEXT, model TEXT, latency_ms INTEGER);
            CREATE TABLE IF NOT EXISTS alert_occurrences (id INTEGER PRIMARY KEY, alert_id INTEGER REFERENCES alerts(id),
              seen_at TEXT NOT NULL, raw TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('owner','analyst','admin')));
            CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS user_settings (user_id INTEGER NOT NULL REFERENCES users(id), key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(user_id,key));
            """)
            if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
                con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", ("admin", bcrypt.hashpw(b"change-me-now", bcrypt.gensalt()), "admin"))

    def is_duplicate(self, alert: NormalizedAlert, window_minutes: int = 30) -> int | None:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
        with self.connect() as con:
            row = con.execute("SELECT id FROM alerts WHERE fingerprint=? AND timestamp>=? ORDER BY timestamp DESC LIMIT 1", (fingerprint(alert), cutoff)).fetchone()
            return int(row["id"]) if row else None

    def store(self, alert: NormalizedAlert, triage: TriageResult, model: str | None = None, latency_ms: int | None = None) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as con:
            cur = con.execute("""INSERT INTO alerts(source,source_event_id,timestamp,title,source_ip,destination_ip,device,rule_id,mitre,raw,fingerprint,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (alert.source, alert.source_event_id, alert.timestamp.isoformat(), alert.title, alert.source_ip,
              alert.destination_ip, alert.device, alert.rule_id, json.dumps(alert.mitre), json.dumps(alert.raw), fingerprint(alert), now))
            alert_id = cur.lastrowid
            con.execute("INSERT INTO triage_results VALUES(?,?,?,?,?,?,?)", (alert_id, triage.severity, triage.explanation, triage.recommended_action, triage.reasoning, model, latency_ms))
            return int(alert_id)

    def suppress(self, alert_id: int, raw: dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute("INSERT INTO alert_occurrences(alert_id,seen_at,raw) VALUES(?,?,?)", (alert_id, datetime.now(timezone.utc).isoformat(), json.dumps(raw)))
            con.execute("UPDATE alerts SET duplicate_count=duplicate_count+1 WHERE id=?", (alert_id,))

    def list_alerts(self, severity: str | None = None, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        clauses, params = [], []
        if severity: clauses.append("t.severity=?"); params.append(severity)
        if status: clauses.append("a.status=?"); params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as con:
            rows = con.execute(f"SELECT a.id,a.source,a.timestamp,a.title,a.source_ip,a.destination_ip,a.device,a.status,a.duplicate_count,t.severity,t.explanation,t.recommended_action FROM alerts a JOIN triage_results t ON t.alert_id=a.id {where} ORDER BY a.timestamp DESC LIMIT ?", (*params, limit)).fetchall()
            return [dict(row) for row in rows]

    def get_alert(self, alert_id: int) -> AlertDetail | None:
        with self.connect() as con:
            row = con.execute("SELECT a.*,t.severity,t.explanation,t.recommended_action,t.reasoning FROM alerts a LEFT JOIN triage_results t ON t.alert_id=a.id WHERE a.id=?", (alert_id,)).fetchone()
        if not row: return None
        triage = TriageResult(severity=row["severity"], explanation=row["explanation"], recommended_action=row["recommended_action"], reasoning=row["reasoning"]) if row["severity"] else None
        return AlertDetail(id=row["id"], source=row["source"], timestamp=row["timestamp"], title=row["title"], source_ip=row["source_ip"], destination_ip=row["destination_ip"], device=row["device"], rule_id=row["rule_id"], mitre=json.loads(row["mitre"]), raw=json.loads(row["raw"]), status=row["status"], duplicate_count=row["duplicate_count"], triage=triage)

    def update_status(self, alert_id: int, status: AlertStatus) -> bool:
        with self.connect() as con:
            return con.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id)).rowcount == 1

    def trends(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            return [dict(r) for r in con.execute("SELECT substr(a.timestamp,1,10) AS day,t.severity,COUNT(*) AS count FROM alerts a JOIN triage_results t ON t.alert_id=a.id GROUP BY day,t.severity ORDER BY day")]

    def devices(self) -> list[dict[str, Any]]:
        """Activity summary; Zeek records normally populate device with origin host."""
        with self.connect() as con:
            return [dict(r) for r in con.execute("SELECT COALESCE(device,source_ip,'Unknown') AS device, COUNT(*) AS events, MAX(timestamp) AS last_seen FROM alerts GROUP BY COALESCE(device,source_ip,'Unknown') ORDER BY events DESC LIMIT 50")]

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT id,username,password_hash,role FROM users WHERE username=?", (username,)).fetchone()
            password_matches = bcrypt.checkpw(password.encode(), row["password_hash"] if row else _DUMMY_PASSWORD_HASH)
            if not row or not password_matches: return None
            token = secrets.token_urlsafe(32)
            expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
            con.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (token, row["id"], expires))
            return {"token": token, "username": row["username"], "role": row["role"]}

    def user_for_token(self, token: str) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as con:
            con.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
            row = con.execute("SELECT u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (token,)).fetchone()
            return dict(row) if row else None

    def delete_session(self, token: str) -> None:
        with self.connect() as con:
            con.execute("DELETE FROM sessions WHERE token=?", (token,))

    def users(self) -> list[dict[str, Any]]:
        with self.connect() as con: return [dict(r) for r in con.execute("SELECT id,username,role FROM users ORDER BY username")]

    def create_user(self, username: str, password: str, role: str) -> None:
        with self.connect() as con: con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()), role))

    def user_settings(self, username: str) -> dict[str, str]:
        with self.connect() as con:
            return {r["key"]: r["value"] for r in con.execute("SELECT s.key,s.value FROM user_settings s JOIN users u ON u.id=s.user_id WHERE u.username=?", (username,))}

    def set_user_setting(self, username: str, key: str, value: str) -> None:
        with self.connect() as con:
            con.execute("INSERT INTO user_settings(user_id,key,value) SELECT id,?,? FROM users WHERE username=? ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value", (key, value, username))
