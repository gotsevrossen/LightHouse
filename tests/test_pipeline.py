import asyncio
from datetime import datetime, timezone

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
