from atlas.code_watch import CodeWatchdog
from atlas.database import Database


def test_database_start_failure_releases_lock(tmp_path, monkeypatch):
    db = Database(tmp_path / "history.db")
    watcher = CodeWatchdog(tmp_path, db)
    original = db.begin_code_scan

    def unavailable(*args, **kwargs):
        raise OSError("database temporarily unavailable")

    monkeypatch.setattr(db, "begin_code_scan", unavailable)
    watcher.scan_now()
    assert watcher.state.status == "ERROR"
    assert not watcher._scan_lock.locked()
    monkeypatch.setattr(db, "begin_code_scan", original)
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda name: None)
    watcher.scan_now()
    assert watcher.state.status == "SAFE"


def test_closed_ui_does_not_stop_scanning(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda name: None)

    def closed_ui(state):
        raise RuntimeError("UI closed")

    watcher = CodeWatchdog(tmp_path, Database(tmp_path / "history.db"), on_update=closed_ui)
    watcher.scan_now()
    assert watcher.state.status == "SAFE"
    assert not watcher._scan_lock.locked()


def test_database_finish_failure_does_not_escape_worker(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda name: None)
    db = Database(tmp_path / "history.db")

    def unavailable(*args, **kwargs):
        raise OSError("database temporarily unavailable")

    monkeypatch.setattr(db, "finish_code_scan", unavailable)
    watcher = CodeWatchdog(tmp_path, db)
    watcher.scan_now()
    assert watcher.state.status == "ERROR"
    assert not watcher._scan_lock.locked()
