"""Windows filesystem events through the native scanner and SQLite."""

import threading
import time

import pytest

from atlas.code_scanners import LocalCodeScanners
from atlas.code_watch import CodeWatchdog
from atlas.config import Settings
from atlas.database import Database


def wait_until(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.025)
    assert predicate(), "Watchdog did not complete the expected transition"


@pytest.fixture
def live_watch(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    settings = Settings(notifications_enabled=False)
    monkeypatch.setattr("atlas.code_scanners.Settings.load", lambda: settings)
    monkeypatch.setattr("atlas.code_watch.Settings.load", lambda: settings)
    project = tmp_path / "Projeto com espaços"
    project.mkdir()
    watcher = CodeWatchdog(project, Database(tmp_path / "history.sqlite"), debounce_seconds=0.15)
    yield watcher
    watcher.stop()
    watcher.database.engine.dispose()


def completed_scan(watcher, after=0):
    scan = watcher.database.latest_code_scan(str(watcher.project))
    return scan if scan and scan.id > after and scan.completed_at is not None else None


def active_eval_findings(watcher):
    return [item for item in watcher.database.code_findings(str(watcher.project))
            if item.rule_id == "python-eval" and item.state != "RESOLVED"]


def test_live_native_watch_detects_deduplicates_and_confirms_fix(live_watch):
    watcher = live_watch
    target = watcher.project / "app.py"
    target.write_text("value = user_input\n", encoding="utf-8")
    watcher.start()
    wait_until(lambda: completed_scan(watcher))
    assert active_eval_findings(watcher) == []

    target.write_text("value = eval(user_input)\n", encoding="utf-8")
    wait_until(lambda: active_eval_findings(watcher))
    initial = active_eval_findings(watcher)[0]
    assert initial.state == "NEW"
    wait_until(lambda: completed_scan(watcher))
    previous_scan = completed_scan(watcher).id

    target.write_text("# unrelated header\nvalue = eval(user_input)\n", encoding="utf-8")
    wait_until(lambda: completed_scan(watcher, previous_scan))
    findings = active_eval_findings(watcher)
    assert len(findings) == 1
    assert findings[0].fingerprint == initial.fingerprint
    assert findings[0].line == 2
    assert findings[0].state == "EXISTING"

    target.write_text("value = user_input\n", encoding="utf-8")
    wait_until(lambda: not active_eval_findings(watcher))
    assert any(item.fingerprint == initial.fingerprint and item.state == "RESOLVED"
               for item in watcher.database.code_findings(str(watcher.project)))


@pytest.mark.parametrize("destination", ["renamed.py", "node_modules/renamed.py"])
def test_live_native_watch_reconciles_both_paths_on_rename(live_watch, destination):
    watcher = live_watch
    original = watcher.project / "app.py"
    renamed = watcher.project / destination
    renamed.parent.mkdir(parents=True, exist_ok=True)
    original.write_text("eval(user_input)\n", encoding="utf-8")
    watcher.start()
    wait_until(lambda: completed_scan(watcher))
    assert active_eval_findings(watcher)[0].state == "EXISTING"
    previous_scan = completed_scan(watcher).id

    original.rename(renamed)
    wait_until(lambda: completed_scan(watcher, previous_scan))
    findings = active_eval_findings(watcher)
    expected = [] if "node_modules" in renamed.parts else [str(renamed.resolve())]
    assert [item.file_path for item in findings] == expected
    assert any(item.file_path == str(original.resolve()) and item.state == "RESOLVED"
               for item in watcher.database.code_findings(str(watcher.project)))


def test_live_native_watch_detects_file_moved_into_analyzed_scope(live_watch):
    watcher = live_watch
    dependency = watcher.project / "node_modules" / "sample.py"
    dependency.parent.mkdir()
    dependency.write_text("eval(user_input)\n", encoding="utf-8")
    target = watcher.project / "app.py"
    watcher.start()
    wait_until(lambda: completed_scan(watcher))
    assert active_eval_findings(watcher) == []

    dependency.rename(target)
    wait_until(lambda: active_eval_findings(watcher))
    assert active_eval_findings(watcher)[0].file_path == str(target.resolve())
    assert active_eval_findings(watcher)[0].state == "NEW"


def test_live_native_watch_confirms_deleted_source(live_watch):
    watcher = live_watch
    target = watcher.project / "app.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    watcher.start()
    wait_until(lambda: completed_scan(watcher))
    previous_scan = completed_scan(watcher).id
    target.unlink()
    wait_until(lambda: completed_scan(watcher, previous_scan))
    assert active_eval_findings(watcher) == []
    assert watcher.state.scan_scope == "FULL"


def test_live_native_watch_handles_editor_atomic_save(live_watch):
    watcher = live_watch
    target = watcher.project / "app.py"
    staged = watcher.project / "editor-save.tmp"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    watcher.start()
    wait_until(lambda: completed_scan(watcher))
    previous_scan = completed_scan(watcher).id
    staged.write_text("value = user_input\n", encoding="utf-8")
    staged.replace(target)
    wait_until(lambda: completed_scan(watcher, previous_scan))
    assert active_eval_findings(watcher) == []


def test_live_native_watch_retains_changes_received_during_scan(live_watch):
    watcher = live_watch
    target = watcher.project / "app.py"
    target.write_text("value = user_input\n", encoding="utf-8")
    entered = threading.Event()
    release = threading.Event()
    calls = []
    simultaneous = []
    in_scan = threading.Lock()

    class SlowFirstScan(LocalCodeScanners):
        def scan(self, changed=None, changed_lines=None):
            acquired = in_scan.acquire(blocking=False)
            simultaneous.append(not acquired)
            assert acquired, "Conflicting scans executed concurrently"
            try:
                result = super().scan(changed, changed_lines=changed_lines)
                calls.append(changed)
                if len(calls) == 1:
                    entered.set()
                    assert release.wait(timeout=8), "Test scan was not released"
                return result
            finally:
                in_scan.release()

    watcher.scanner_factory = SlowFirstScan
    watcher.start()
    try:
        assert entered.wait(timeout=8)
        target.write_text("eval(user_input)\n", encoding="utf-8")
        wait_until(lambda: watcher.state.changes > 0)
        conflict = watcher.scan_now([target])
        assert conflict == {"NEW": [], "EXISTING": [], "RESOLVED": []}
        assert len(calls) == 1
        release.set()
        wait_until(lambda: active_eval_findings(watcher))
        assert active_eval_findings(watcher)[0].state == "NEW"
        assert len(calls) >= 2
        assert not any(simultaneous)
    finally:
        release.set()
