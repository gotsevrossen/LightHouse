import pytest


@pytest.fixture(autouse=True)
def no_real_web_search(tmp_path, monkeypatch):
    """No test may reach Brave: point the key at a file that does not exist (a
    developer's machine may have a real one), and start every test with an empty
    search cache and no failure pause."""
    monkeypatch.setenv("LIGHTHOUSE_BRAVE_KEY_FILE", str(tmp_path / "no-brave-key.bin"))
    from triage import web_search
    web_search._cache.clear()
    monkeypatch.setattr(web_search, "_paused_until", 0.0)
    monkeypatch.setattr(web_search, "_last_request", 0.0)
