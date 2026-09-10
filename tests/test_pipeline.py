import asyncio
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from triage import api
from triage.db import Database
from triage.llm import FixtureTriageModel
from triage.schema import NormalizedAlert, Source
from triage.service import TriageService


def test_dedupe_and_persistence(tmp_path):
    db = Database(str(tmp_path / "test.db")); db.initialize()
    service = TriageService(db, FixtureTriageModel())
    alert = NormalizedAlert(source=Source.SURICATA, timestamp=datetime.now(timezone.utc), title="Nmap scan", source_ip="10.0.0.2", raw={"alert": {}})
    alert_id, duplicate = asyncio.run(service.process(alert))
    assert not duplicate
    same_id, duplicate = asyncio.run(service.process(alert))
    assert duplicate and same_id == alert_id
    stored = db.get_alert(alert_id)
    assert stored and stored.duplicate_count == 1 and stored.triage.severity == "high"

def test_role_session(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    # initialize() returns the generated admin password once, on the run that
    # creates the account. There is no fixed default credential any more.
    seeded_password = db.initialize()
    assert seeded_password
    session = db.authenticate("admin", seeded_password)
    assert session and db.user_for_token(session["token"])["role"] == "admin"


def test_admin_user_validation_and_logout(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "test.db"))
    seeded_password = db.initialize()
    monkeypatch.setattr(api, "db", db)
    client = TestClient(api.app)
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": seeded_password},
    )
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    weak = client.post(
        "/api/users",
        headers=headers,
        json={"username": "new user", "password": "short", "role": "owner"},
    )
    assert weak.status_code == 422

    oversized = client.post(
        "/api/users",
        headers=headers,
        json={"username": "unicode", "password": "🔒" * 20, "role": "owner"},
    )
    assert oversized.status_code == 422

    created = client.post(
        "/api/users",
        headers=headers,
        json={"username": "new-owner", "password": "long-demo-passphrase", "role": "owner"},
    )
    assert created.status_code == 201

    owner_login = client.post(
        "/api/auth/login",
        json={"username": "new-owner", "password": "long-demo-passphrase"},
    )
    owner_headers = {"Authorization": f"Bearer {owner_login.json()['token']}"}
    forbidden = client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "escalated", "password": "another-passphrase", "role": "admin"},
    )
    assert forbidden.status_code == 403

    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/users", headers=headers).status_code == 401
