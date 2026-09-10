"""Behavior that only the desktop build has, and that the appliance must not gain.

Every test here pins one of the two directions: something the desktop build does
(relocated database, password handoff, in-process ingestion) or something the
appliance must keep doing exactly as before.
"""

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def isolate_triage_modules():
    """Keep this file's re-imports from leaking into the rest of the suite.

    These tests need triage.paths and triage.db re-evaluated under different
    environments. importlib.reload is the wrong tool: it re-executes in the
    existing module namespace, which rebinds PasswordTooLongError to a brand-new
    class while triage.api still holds the old one, and its `except` clause then
    silently stops matching. Fresh imports into a restored sys.modules leave the
    original module objects untouched.
    """
    saved = {name: module for name, module in sys.modules.items()
             if name == "triage" or name.startswith("triage.")}
    yield
    for name in [n for n in sys.modules if n == "triage" or n.startswith("triage.")]:
        del sys.modules[name]
    sys.modules.update(saved)


def fresh(name: str):
    """Import triage.<name> anew, picking up the current environment."""
    for existing in [n for n in sys.modules if n == "triage" or n.startswith("triage.")]:
        del sys.modules[existing]
    return importlib.import_module(f"triage.{name}")


@pytest.fixture
def desktop_env(monkeypatch, tmp_path):
    """A clean desktop-mode process with its data directory under tmp_path."""
    monkeypatch.setenv("LIGHTHOUSE_DESKTOP", "1")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.delenv("LIGHTHOUSE_DB_PATH", raising=False)
    monkeypatch.delenv("LIGHTHOUSE_FIRST_RUN_DIR", raising=False)
    for source in ("SURICATA", "ZEEK", "WAZUH"):
        monkeypatch.delenv(f"LIGHTHOUSE_{source}_PATH", raising=False)
    return tmp_path


@pytest.fixture
def appliance_env(monkeypatch):
    monkeypatch.delenv("LIGHTHOUSE_DESKTOP", raising=False)
    monkeypatch.delenv("LIGHTHOUSE_DB_PATH", raising=False)


def reload_api(monkeypatch, tmp_path):
    """Import triage.api anew; it opens the database at import time."""
    monkeypatch.setenv("LIGHTHOUSE_STATIC_DIR", str(tmp_path / "no-dashboard-build"))
    return fresh("api")


# --- database location -------------------------------------------------------


def test_desktop_database_lands_in_the_user_data_directory(desktop_env):
    db = fresh("db")
    assert db.default_db_path() == str(desktop_env / "lighthouse" / "lighthouse.db")


def test_appliance_database_path_is_unchanged(appliance_env):
    db = fresh("db")
    # The relative default the appliance has always used. A desktop-mode change
    # that leaked into the appliance would silently relocate a live database.
    assert db.default_db_path() == "lighthouse.db"


def test_explicit_db_path_wins_over_desktop_mode(desktop_env, monkeypatch, tmp_path):
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "chosen.db"))
    db = fresh("db")
    assert db.default_db_path() == str(tmp_path / "chosen.db")


# --- first-run password handoff ----------------------------------------------


def test_first_run_password_is_written_once_and_consumed_once(desktop_env, tmp_path):
    db_module = fresh("db")
    paths = sys.modules["triage.paths"]

    database = db_module.Database(str(tmp_path / "seed.db"))
    password = database.initialize()
    assert password, "the first run must generate a password"

    handoff = paths.first_run_password_path()
    assert handoff.read_text(encoding="utf-8").strip() == password

    desktop = importlib.import_module("triage.desktop")
    assert desktop.take_first_run_password() == password
    # Shown exactly once: the same guarantee the stdout banner makes.
    assert not handoff.exists()
    assert desktop.take_first_run_password() is None


def test_second_start_generates_no_password_and_no_handoff_file(desktop_env, tmp_path):
    db_module = fresh("db")
    paths = sys.modules["triage.paths"]

    database = db_module.Database(str(tmp_path / "seed.db"))
    database.initialize()
    paths.first_run_password_path().unlink()

    assert database.initialize() is None
    assert not paths.first_run_password_path().exists()


def test_appliance_never_writes_the_password_to_disk(appliance_env, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    db_module = fresh("db")
    paths = sys.modules["triage.paths"]

    db_module.Database(str(tmp_path / "seed.db")).initialize()
    # The appliance's operator reads it from the journal. Writing it to a file
    # there would put a plaintext credential on disk for nobody's benefit.
    assert not (tmp_path / "lighthouse" / paths.FIRST_RUN_PASSWORD_FILE).exists()


def test_handoff_directory_can_be_redirected_for_the_packaged_service(desktop_env, tmp_path, monkeypatch):
    # The service and the window run as different accounts when installed, so the
    # package points both at a shared handoff directory.
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    monkeypatch.setenv("LIGHTHOUSE_FIRST_RUN_DIR", str(handoff))
    paths = fresh("paths")
    assert paths.first_run_password_path().parent == handoff


# --- health endpoint ---------------------------------------------------------


def test_api_health_is_unauthenticated(desktop_env, monkeypatch, tmp_path):
    api = reload_api(monkeypatch, tmp_path)
    with TestClient(api.app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_api_health_discloses_nothing_beyond_liveness(desktop_env, monkeypatch, tmp_path):
    api = reload_api(monkeypatch, tmp_path)
    with TestClient(api.app) as client:
        body = client.get("/api/health").json()
    # The fingerprintable view (platform, model, disk) stays behind a role gate.
    assert set(body) == {"ok"}


def test_advanced_health_still_requires_authentication(desktop_env, monkeypatch, tmp_path):
    # Adding an unauthenticated /api/health must not have loosened the detailed
    # one beside it. No bearer token is a 401 from the security scheme.
    api = reload_api(monkeypatch, tmp_path)
    with TestClient(api.app) as client:
        assert client.get("/api/advanced/health").status_code == 401
        assert client.get("/api/advanced/health", headers={"Authorization": "Bearer nonsense"}).status_code == 401


# --- ingestion placement -----------------------------------------------------


def test_desktop_starts_ingestion_in_process(desktop_env, monkeypatch, tmp_path):
    api = reload_api(monkeypatch, tmp_path)
    started = []

    async def spy():
        started.append(True)

    monkeypatch.setattr(api, "_ingestion_task", spy)
    with TestClient(api.app) as client:
        client.get("/api/health")
    assert started == [True]


def test_appliance_does_not_start_ingestion_in_process(appliance_env, monkeypatch, tmp_path):
    api = reload_api(monkeypatch, tmp_path)
    started = []

    async def spy():
        started.append(True)

    monkeypatch.setattr(api, "_ingestion_task", spy)
    with TestClient(api.app) as client:
        client.get("/api/health")
    # The appliance runs `python -m triage.main tail` as its own unit. Starting it
    # here too would double-ingest every record.
    assert started == []


def test_failing_ingestion_leaves_the_api_serving_and_shutting_down_cleanly(
    desktop_env, monkeypatch, tmp_path
):
    api = reload_api(monkeypatch, tmp_path)
    main_module = importlib.import_module("triage.main")

    def exploding(*args, **kwargs):
        raise RuntimeError("simulated sensor parsing bug")

    monkeypatch.setattr(main_module, "configured_sources", exploding)

    # The whole `with` block matters: the API must answer while running AND the
    # lifespan must exit without re-raising what ingestion threw.
    with TestClient(api.app) as client:
        assert client.get("/api/health").status_code == 200
        assert client.post("/api/auth/login", json={"username": "admin", "password": "no"}).status_code == 401


def test_unreadable_sensor_log_does_not_stop_the_api(desktop_env, monkeypatch, tmp_path):
    # The CLI treats this as a startup failure; the desktop build must not, because
    # the dashboard is still worth showing and there is no terminal to read on.
    monkeypatch.setenv("LIGHTHOUSE_SURICATA_PATH", str(tmp_path / "absent" / "eve.json"))
    api = reload_api(monkeypatch, tmp_path)
    with TestClient(api.app) as client:
        assert client.get("/api/health").status_code == 200


# --- frozen-build path resolution --------------------------------------------


def test_bundle_dir_follows_the_pyinstaller_extraction_directory(monkeypatch, tmp_path):
    paths = fresh("paths")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert paths.bundle_dir() == tmp_path
    # A frozen build is the desktop app whether or not the flag was set.
    monkeypatch.delenv("LIGHTHOUSE_DESKTOP", raising=False)
    assert paths.is_desktop()


def test_bundle_dir_is_the_working_directory_from_source(monkeypatch):
    paths = fresh("paths")
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    assert paths.bundle_dir() == pytest.importorskip("pathlib").Path.cwd()
