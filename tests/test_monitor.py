from pathlib import Path

from watchdog.events import FileCreatedEvent

from atlas.database import Database
from atlas.monitor import ChangeHandler, MonitorService, _atlas_command


def test_frozen_monitor_relaunches_the_atlas_executable(monkeypatch):
    monkeypatch.setattr("atlas.monitor.sys.frozen", True, raising=False)
    monkeypatch.setattr("atlas.monitor.sys.executable", r"C:\Apps\ATLAS-Security-Agent.exe")
    assert _atlas_command("_monitor-run") == [r"C:\Apps\ATLAS-Security-Agent.exe", "_monitor-run"]


def test_monitor_records_file_metadata_without_content(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("atlas.monitor.SKIP_PARTS", set())
    database = Database(tmp_path / "monitor.sqlite")
    handler = ChangeHandler(database)
    target = tmp_path / "app.py"
    target.write_text("private sample data", encoding="utf-8")
    handler.on_any_event(FileCreatedEvent(str(target)))
    events = database.recent_monitor_events()
    assert len(events) == 1
    assert events[0].kind == "file"
    assert events[0].detail == "created"
    assert "do-not-store" not in events[0].component
    assert "do-not-store" not in events[0].detail


def test_monitor_masks_sensitive_filename(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("atlas.monitor.SKIP_PARTS", set())
    database = Database(tmp_path / "monitor.sqlite")
    handler = ChangeHandler(database)
    target = tmp_path / ".env"
    handler.on_any_event(FileCreatedEvent(str(target)))
    event = database.recent_monitor_events()[0]
    assert event.severity == "HIGH"
    assert event.component.endswith("[SENSITIVE_FILE]")


def test_monitor_records_firewall_profile_change(tmp_path: Path, monkeypatch):
    database = Database(tmp_path / "firewall.sqlite")
    service = MonitorService([tmp_path], database)
    monkeypatch.setattr("atlas.monitor.os.name", "nt")
    states = iter([
        '[{"Name":"Public","Enabled":true}]',
        '[{"Name":"Public","Enabled":false}]',
    ])
    class Result:
        returncode = 0
        stderr = ""
        def __init__(self, stdout):
            self.stdout = stdout
    monkeypatch.setattr("atlas.monitor.subprocess.run", lambda *a, **k: Result(next(states)))
    service._snapshot_firewall(initial=True)
    service._snapshot_firewall()
    events = database.recent_monitor_events()
    assert events and events[0].kind == "firewall"
    assert events[0].severity == "HIGH"


def test_monitor_records_persistence_changes_without_storing_command(tmp_path: Path, monkeypatch):
    database = Database(tmp_path / "persistence.sqlite")
    service = MonitorService([tmp_path], database)
    snapshots = iter([
        [{"kind": "registry-run", "name": "HKCU Run: Demo", "fingerprint": "a" * 64}],
        [{"kind": "registry-run", "name": "HKCU Run: Demo", "fingerprint": "b" * 64}],
    ])
    monkeypatch.setattr("atlas.threats.persistence_snapshot", lambda: next(snapshots))
    service._snapshot_persistence(initial=True)
    service._snapshot_persistence()
    event = database.recent_monitor_events()[0]
    assert event.kind == "persistence"
    assert event.detail == "entrada de inicialização modificada"
    assert "a" * 64 not in event.detail and "b" * 64 not in event.detail
