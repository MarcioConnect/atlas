import time
from pathlib import Path

from atlas.code_scanners import CodeScanResult, NormalizedFinding, ScannerAvailability
from atlas.code_watch import CodeWatchdog
from atlas.database import Database


class SequenceScanner:
    batches: list[list[NormalizedFinding]] = []

    def __init__(self, project: Path):
        self.project = project

    def scan(self, _changed=None):
        findings = self.batches.pop(0)
        for item in findings:
            item.finalize(self.project)
        return CodeScanResult(
            findings=findings,
            availability=[ScannerAvailability("Test", True, "")],
            coverage={"Test": None},
            files_analyzed=1,
        )


def issue(project: Path) -> NormalizedFinding:
    return NormalizedFinding("HIGH", "Test", "RULE", str(project / "app.py"), 4, "Issue", "safe evidence", "Fix")


def test_new_existing_and_resolved_lifecycle_with_space_path(tmp_path: Path):
    project = tmp_path / "Project With Spaces"
    project.mkdir()
    (project / "app.py").write_text("pass", encoding="utf-8")
    SequenceScanner.batches = [[issue(project)], [issue(project)], []]
    watcher = CodeWatchdog(project, Database(tmp_path / "watch.sqlite"), scanner_factory=SequenceScanner)

    first = watcher.scan_now(None)
    second = watcher.scan_now(None)
    third = watcher.scan_now(None)

    assert len(first["NEW"]) == 1
    assert len(second["EXISTING"]) == 1
    assert len(third["RESOLVED"]) == 1
    assert watcher.database.code_findings(str(project), "RESOLVED")[0].state == "RESOLVED"


def test_debounce_coalesces_repeated_changes(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "app.py"
    target.write_text("pass", encoding="utf-8")
    SequenceScanner.batches = [[]]
    watcher = CodeWatchdog(
        project, Database(tmp_path / "watch.sqlite"), debounce_seconds=0.1, scanner_factory=SequenceScanner
    )
    watcher.start(initial_scan=False)
    try:
        watcher.queue(target)
        watcher.queue(target)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            current = watcher.database.latest_code_scan(str(project))
            if current is not None and current.completed_at is not None:
                break
            time.sleep(0.05)
        scans = watcher.database.latest_code_scan(str(project))
        assert scans is not None
        assert scans.changes >= 2
        assert SequenceScanner.batches == []
    finally:
        watcher.stop()


def test_unavailable_scanner_does_not_resolve_old_finding(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    database = Database(tmp_path / "scope.sqlite")
    normalized = issue(project).finalize(project)
    first_scan = database.begin_code_scan(str(project))
    database.reconcile_code_findings(str(project), first_scan.id, [normalized.record()], {"Test": None})
    second_scan = database.begin_code_scan(str(project))
    outcome = database.reconcile_code_findings(str(project), second_scan.id, [], {})
    assert outcome["RESOLVED"] == []
    assert database.code_findings(str(project), "EXISTING")


def test_real_filesystem_event_triggers_scan(tmp_path: Path):
    project = tmp_path / "observed"
    project.mkdir()
    SequenceScanner.batches = [[]]
    watcher = CodeWatchdog(project, Database(tmp_path / "events.sqlite"), debounce_seconds=0.1, scanner_factory=SequenceScanner)
    watcher.start(initial_scan=False)
    try:
        (project / "created.py").write_text("print('ok')", encoding="utf-8")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            current = watcher.database.latest_code_scan(str(project))
            if current is not None and current.completed_at is not None:
                break
            time.sleep(0.05)
        assert watcher.database.latest_code_scan(str(project)) is not None
        assert watcher.state.changes >= 1
    finally:
        watcher.stop()


def test_non_source_file_is_recorded_and_triggers_watch_cycle(tmp_path: Path):
    project = tmp_path / "all-files"
    project.mkdir()
    database = Database(tmp_path / "all-files.sqlite")
    SequenceScanner.batches = [[]]
    watcher = CodeWatchdog(project, database, debounce_seconds=0.1, scanner_factory=SequenceScanner)
    watcher.start(initial_scan=False)
    try:
        target = project / "notes.txt"
        target.write_text("documentation only", encoding="utf-8")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if any(event.component.endswith("notes.txt") for event in database.recent_monitor_events()):
                break
            time.sleep(0.05)
        assert any(event.component.endswith("notes.txt") for event in database.recent_monitor_events())
    finally:
        watcher.stop()


def test_native_scanner_end_to_end_lifecycle(tmp_path: Path, monkeypatch):
    project = tmp_path / "native-project"
    project.mkdir()
    target = project / "app.py"
    dynamic_call = "ev" + "al"
    target.write_text("result = " + dynamic_call + "(user_input)", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    watcher = CodeWatchdog(project, Database(tmp_path / "native.sqlite"))

    first = watcher.scan_now(None)
    second = watcher.scan_now(None)
    target.write_text("result = user_input", encoding="utf-8")
    third = watcher.scan_now([target])

    assert any(item.rule_id == "python-eval" for item in first["NEW"])
    assert any(item.rule_id == "python-eval" for item in second["EXISTING"])
    assert any(item.rule_id == "python-eval" for item in third["RESOLVED"])


def test_full_scan_seeds_incremental_line_snapshot(tmp_path: Path, monkeypatch):
    project = tmp_path / "snapshot"
    project.mkdir()
    target = project / "app.py"
    target.write_text("first = 1\nsecond = 2\n", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    watcher = CodeWatchdog(project, Database(tmp_path / "snapshot.sqlite"))
    watcher.scan_now(None)
    target.write_text("first = 1\nsecond = 3\n", encoding="utf-8")
    changed = watcher._changed_line_map([target])
    assert changed == {str(target.resolve()).casefold(): {2}}


def test_unrelated_edit_does_not_resolve_live_issue(tmp_path, monkeypatch):
    monkeypatch.setattr('atlas.code_scanners.shutil.which', lambda name: None)
    target = tmp_path / 'app.py'
    target.write_text('eval(user_input)\ncount = 1\n')
    watcher = CodeWatchdog(tmp_path, Database(tmp_path / 'watch.db'))
    assert any(f.rule_id == 'python-eval' for f in watcher.scan_now()['NEW'])
    target.write_text('eval(user_input)\ncount = 2\n')
    result = watcher.scan_now([target])
    assert not result['RESOLVED']
    assert any(f.rule_id == 'python-eval' for f in result['EXISTING'])
    target.write_text('value = user_input\ncount = 2\n')
    assert any(f.rule_id == 'python-eval' for f in watcher.scan_now([target])['RESOLVED'])


def test_oversized_file_is_not_falsely_marked_resolved(tmp_path, monkeypatch):
    monkeypatch.setattr('atlas.code_scanners.shutil.which', lambda name: None)
    target = tmp_path / 'app.py'
    target.write_text('eval(user_input)\n')
    watcher = CodeWatchdog(tmp_path, Database(tmp_path / 'watch.db'))
    watcher.scan_now()
    target.write_text('eval(user_input)\n#' + 'x' * 2_000_000)
    result = watcher.scan_now([target])
    assert not any(f.rule_id == 'python-eval' for f in result['RESOLVED'])


def test_initial_baseline_does_not_report_preexisting_findings_as_new(tmp_path: Path):
    project = tmp_path / "baseline"
    project.mkdir()
    (project / "app.py").write_text("pass", encoding="utf-8")
    SequenceScanner.batches = [[issue(project)]]
    watcher = CodeWatchdog(project, Database(tmp_path / "baseline.sqlite"), scanner_factory=SequenceScanner)
    result = watcher.scan_now(None, baseline=True)
    assert result["NEW"] == []
    assert len(result["EXISTING"]) == 1
    assert watcher.database.code_findings(str(project), "NEW") == []


def test_ai_enabled_watch_does_not_review_or_send_findings_automatically(tmp_path: Path, monkeypatch):
    project = tmp_path / "no-auto-ai"
    project.mkdir()
    SequenceScanner.batches = [[issue(project)]]
    watcher = CodeWatchdog(project, Database(tmp_path / "no-auto-ai.sqlite"), scanner_factory=SequenceScanner,
                           ai_enabled=True)
    monkeypatch.setattr("atlas.ollama_ai.OllamaReviewer.review", lambda *_args: (_ for _ in ()).throw(AssertionError("unexpected AI call")))
    result = watcher.scan_now(None)
    assert len(result["NEW"]) == 1
