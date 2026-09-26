import json
import subprocess
from pathlib import Path

import pytest

from atlas.code_scanners import LocalCodeScanners, NormalizedFinding
from atlas.code_watch import CodeWatchdog
from atlas.database import Database
from atlas.report import render_json_report


@pytest.mark.parametrize(
    ("scan_output", "exit_code", "expected_status"),
    [
        ('{"error":"network unavailable"}', 1, "FAILED"),
        ('{"results":[],"errors":[{"message":"incomplete"}],"paths":{"scanned":[]}}', 0, "FAILED"),
        ('{"results":[],"paths":{"scanned":[]}}', 1, "TIMEOUT"),
    ],
)
def test_semgrep_failure_never_resolves_prior_finding(
    tmp_path: Path, monkeypatch, scan_output: str, exit_code: int, expected_status: str,
):
    project = tmp_path / "Project With Spaces"
    project.mkdir()
    target = project / "app.py"
    target.write_text('print("safe")\n', encoding="utf-8")
    database = Database(tmp_path / "health.sqlite")
    old = NormalizedFinding("HIGH", "Semgrep", "test-rule", str(target), 1,
                            "Prior finding", "Matched code omitted", "Review").finalize(project)
    previous_scan = database.begin_code_scan(str(project))
    database.reconcile_code_findings(
        str(project), previous_scan.id, [old.record()],
        {"Semgrep": {str(target.resolve()).casefold()}}, {"Semgrep": "SUCCESS"},
    )
    database.finish_code_scan(previous_scan.id, files_analyzed=1, changes=0, status="FINDINGS", scanners="[]")

    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda name: "semgrep" if name == "semgrep" else None)

    def fake_run(command, _cwd, _timeout=120):
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, "1.0\n", "")
        return subprocess.CompletedProcess(command, exit_code, scan_output,
                                           "TimeoutExpired" if expected_status == "TIMEOUT" else "")

    monkeypatch.setattr("atlas.code_scanners._run", fake_run)
    watcher = CodeWatchdog(project, database)
    result = watcher.scan_now(None)
    assert result["RESOLVED"] == []
    assert database.code_findings(str(project), "UNVERIFIED")
    assert watcher.state.health == "PARTIAL"
    semgrep = next(item for item in watcher.state.availability if item.name == "Semgrep")
    assert semgrep.status == expected_status
    report = json.loads(render_json_report(database, project))["projects"][0]["scan"]
    assert report["complete"] is False
    assert any("Semgrep" in gap for gap in report["coverage_gaps"])


def test_failed_scanner_can_only_resolve_after_successful_file_coverage(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "app.py"
    target.write_text("pass\n", encoding="utf-8")
    database = Database(tmp_path / "lifecycle.sqlite")
    finding = NormalizedFinding("HIGH", "Test", "R1", str(target), 1,
                                "Issue", "safe evidence", "Fix").finalize(project)
    first = database.begin_code_scan(str(project))
    database.reconcile_code_findings(str(project), first.id, [finding.record()],
                                     {"Test": {str(target.resolve()).casefold()}}, {"Test": "SUCCESS"})
    failed = database.begin_code_scan(str(project))
    outcome = database.reconcile_code_findings(str(project), failed.id, [],
                                               {"Test": {str(target.resolve()).casefold()}},
                                               {"Test": "PARTIAL"})
    assert not outcome["RESOLVED"]
    assert len(outcome["UNVERIFIED"]) == 1
    unrelated = database.begin_code_scan(str(project))
    outcome = database.reconcile_code_findings(str(project), unrelated.id, [],
                                               {"Test": {str(project / "other.py").casefold()}},
                                               {"Test": "SUCCESS"})
    assert not outcome["RESOLVED"]
    verified = database.begin_code_scan(str(project))
    outcome = database.reconcile_code_findings(str(project), verified.id, [],
                                               {"Test": {str(target.resolve()).casefold()}},
                                               {"Test": "SUCCESS"})
    assert len(outcome["RESOLVED"]) == 1


def test_missing_execution_status_does_not_prove_resolution(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "app.py"
    target.write_text("pass\n", encoding="utf-8")
    database = Database(tmp_path / "missing-status.sqlite")
    finding = NormalizedFinding("HIGH", "Test", "R1", str(target), 1,
                                "Issue", "safe evidence", "Fix").finalize(project)
    first = database.begin_code_scan(str(project))
    database.reconcile_code_findings(str(project), first.id, [finding.record()],
                                     {"Test": {str(target.resolve()).casefold()}}, {"Test": "SUCCESS"})
    second = database.begin_code_scan(str(project))
    outcome = database.reconcile_code_findings(str(project), second.id, [],
                                               {"Test": {str(target.resolve()).casefold()}})
    assert outcome["RESOLVED"] == []
    assert len(outcome["UNVERIFIED"]) == 1


def test_scanner_internal_typeerror_is_not_retried(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    calls = []

    class BrokenScanner:
        def __init__(self, _project):
            pass

        def scan(self, _changed=None, changed_lines=None):
            calls.append(changed_lines)
            raise TypeError("internal parser bug")

    watcher = CodeWatchdog(project, Database(tmp_path / "broken.sqlite"), scanner_factory=BrokenScanner)
    watcher.scan_now(None)
    assert len(calls) == 1
    assert watcher.state.status == "ERROR"
    assert watcher.database.latest_code_scan(str(project)).health == "FAILED"


def test_unexpected_scan_failure_preserves_old_finding_as_unverified(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "app.py"
    target.write_text("pass\n", encoding="utf-8")
    database = Database(tmp_path / "unexpected.sqlite")
    finding = NormalizedFinding("HIGH", "Test", "R1", str(target), 1,
                                "Issue", "safe evidence", "Fix").finalize(project)
    first = database.begin_code_scan(str(project))
    database.reconcile_code_findings(str(project), first.id, [finding.record()],
                                     {"Test": {str(target.resolve()).casefold()}}, {"Test": "SUCCESS"})

    class BrokenScanner:
        def __init__(self, _project):
            pass

        def scan(self, _changed=None, changed_lines=None):
            raise RuntimeError("scanner crashed")

    watcher = CodeWatchdog(project, database, scanner_factory=BrokenScanner)
    assert watcher.scan_now(None)["RESOLVED"] == []
    assert len(database.code_findings(str(project), "UNVERIFIED")) == 1
    assert database.latest_code_scan(str(project)).health == "FAILED"


def test_native_full_scan_can_confirm_deleted_source(tmp_path: Path, monkeypatch):
    project = tmp_path / "source"
    project.mkdir()
    target = project / "app.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    watcher = CodeWatchdog(project, Database(tmp_path / "deleted.sqlite"))
    assert watcher.scan_now(None)["NEW"]
    target.unlink()
    outcome = watcher.scan_now(None)
    assert any(item.rule_id == "python-eval" for item in outcome["RESOLVED"])


def test_scanner_availability_is_not_execution_success(tmp_path: Path, monkeypatch):
    target = tmp_path / "package.json"
    target.write_text('{"name":"sample","version":"1.0.0"}', encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda name: "npm" if name == "npm" else None)
    monkeypatch.setattr("atlas.code_scanners._run", lambda command, cwd, timeout=120:
                        subprocess.CompletedProcess(command, 1, '{"error":"registry failure"}', ""))
    result = LocalCodeScanners(tmp_path).scan()
    npm = next(item for item in result.availability if item.name == "npm audit")
    assert npm.available is True
    assert npm.status == "FAILED"
    assert "npm audit" not in result.coverage
    assert result.health == "PARTIAL"
