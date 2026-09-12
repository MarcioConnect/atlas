from pathlib import Path

from atlas.database import Database
from atlas.sessions import SessionManager, safe_command_metadata


def test_command_metadata_is_conservative():
    executable, detail, action = safe_command_metadata("curl https://user:password@example.com --token abc123")
    assert executable == "curl"
    assert "password" not in detail
    assert "abc123" not in detail
    assert "[REDACTED]" in detail
    assert action == "command:curl"


def test_session_detects_file_change(tmp_path: Path, monkeypatch):
    database = Database(tmp_path / "db.sqlite")
    manager = SessionManager(database)
    monkeypatch.setattr("atlas.sessions.services", list)
    monkeypatch.setattr("atlas.sessions.docker_inspect", list)
    tracked = tmp_path / "tracked"
    tracked.mkdir()
    operation = manager.create(tracked, "test")
    (tracked / "new.txt").write_text("new", encoding="utf-8")
    completed = manager.stop(operation.id)
    assert completed is not None
    assert completed.status == "completed"
    detail = database.session_detail(operation.id)
    assert detail is not None
    assert any(event.kind == "file" and event.detail == "created" for event in detail.events)
