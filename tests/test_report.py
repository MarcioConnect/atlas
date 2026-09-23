from datetime import UTC, datetime

from atlas.database import Database
from atlas.models import CodeFinding, Finding, MonitorEvent, Scan
from atlas.report import (
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    render_json_report,
)


def test_report_contains_system_and_watchdog_findings(tmp_path):
    db = Database(tmp_path / "atlas.sqlite")
    db.save_scan(Scan(hostname="test-host", score=72, findings=[Finding(
        check_id="secret", title="Credential exposed", severity="HIGH",
        evidence="to" + "ken=super-" + "secret-value", risk="Account takeover", component="config.py",
        recommendation="Rotate token", fingerprint="abc"),]))
    code_scan = db.begin_code_scan(str((tmp_path / "Project With Spaces").resolve()))
    db.finish_code_scan(code_scan.id, files_analyzed=2, changes=1, status="SAFE", scanners='{"Bandit":"available"}')
    with db.session() as session:
        session.add(CodeFinding(
            project_path=str((tmp_path / "Project With Spaces").resolve()), fingerprint="def", scanner="Bandit",
            rule_id="B602", file_path="src/auth.py", line=87, severity="HIGH",
            description="Possible command injection", evidence="pass" + "word=hidden", recommendation="Use safe API", state="NEW"))
        session.commit()
    output = tmp_path / "Downloads"
    generated = datetime(2026, 9, 12, 10, 30, tzinfo=UTC)
    path = generate_markdown_report(db, tmp_path / "Project With Spaces", output, generated)
    content = path.read_text(encoding="utf-8")
    assert path.name == "atlas-report-2026-09-12.md"
    assert "Gerado em:" in content
    assert generated.astimezone().strftime("%d/%m/%Y %H:%M:%S") in content
    assert "Security Score" in content and "72/100" in content
    assert "Watchdog — NEW" in content and "src/auth.py:87" in content
    assert "super-secret-value" not in content and "[REDACTED]" in content


def test_report_without_scan_still_creates_file_and_avoids_overwrite(tmp_path):
    db = Database(tmp_path / "atlas.sqlite")
    output = tmp_path / "Downloads"
    generated = datetime(2026, 9, 12, 10, 30, tzinfo=UTC)
    first = generate_markdown_report(db, output_dir=output, now=generated)
    second = generate_markdown_report(db, output_dir=output, now=generated)
    assert first.exists() and second.exists() and first != second
    assert "Nenhum scan de sistema disponível" in first.read_text(encoding="utf-8")


def test_html_report_is_standalone(tmp_path):
    db = Database(tmp_path / "atlas.sqlite")
    generated = datetime(2026, 9, 12, 10, 30, tzinfo=UTC)
    path = generate_html_report(db, output_dir=tmp_path, now=generated)
    content = path.read_text(encoding="utf-8")
    assert "<!doctype html>" in content
    assert "⚕ ATLAS" in content
    assert "ATLAS Security Report" in content
    assert "FINDINGS POR SEVERIDADE" in content
    assert "cards" in content and "Relat" in content
    assert "@media print" in content


def test_json_report_includes_coverage_lifecycle_and_redacted_evidence(tmp_path):
    import json

    db = Database(tmp_path / "json.sqlite")
    project = (tmp_path / "Project With Spaces").resolve()
    scan = db.begin_code_scan(str(project))
    db.finish_code_scan(scan.id, files_analyzed=1, changes=0, status="FINDINGS",
                        scanners='[{"name":"ATLAS Native","available":true},{"name":"Semgrep","available":false}]')
    with db.session() as session:
        session.add(CodeFinding(project_path=str(project), fingerprint="f" * 64, scanner="ATLAS Native",
                                rule_id="hardcoded-secret", file_path=str(project / "app.py"), line=3,
                                severity="HIGH", category="credentials", confidence=91,
                                description="Possible secret", evidence="password=[REDACTED]",
                                recommendation="Rotate credential", state="NEW"))
        session.commit()
    output = generate_json_report(db, project, tmp_path / "reports")
    payload = json.loads(output.read_text(encoding="utf-8"))
    item = payload["projects"][0]["findings"][0]
    assert item["category"] == "credentials" and item["confidence"] == 91
    assert payload["projects"][0]["scan"]["complete"] is False
    assert payload["projects"][0]["scan"]["unavailable_scanners"] == ["Semgrep"]
    assert payload["projects"][0]["scan"]["coverage_gaps"] == ["Optional scanner unavailable: Semgrep"]


def test_report_marks_large_file_skips_as_incomplete_coverage(tmp_path):
    import json

    db = Database(tmp_path / "partial.sqlite")
    project = (tmp_path / "Project").resolve()
    scan = db.begin_code_scan(str(project))
    db.finish_code_scan(scan.id, files_analyzed=2, files_skipped_large=1, changes=1, status="SAFE",
                        scanners='[{"name":"ATLAS Native","available":true}]')
    payload = json.loads(render_json_report(db, project))
    coverage = payload["projects"][0]["scan"]
    assert coverage["complete"] is False
    assert coverage["files_skipped_large"] == 1
    assert coverage["coverage_gaps"] == ["1 eligible source file(s) exceeded the 2 MB limit"]


def test_incremental_scan_is_not_reported_as_project_complete(tmp_path):
    import json

    db = Database(tmp_path / "incremental.sqlite")
    project = (tmp_path / "Project").resolve()
    scan = db.begin_code_scan(str(project), str(project / "app.py"))
    db.finish_code_scan(scan.id, files_analyzed=1, changes=1, status="SAFE",
                        scanners='[{"name":"ATLAS Native","available":true}]')

    result = json.loads(render_json_report(db, project))["projects"][0]["scan"]

    assert result["scope"] == "incremental"
    assert result["complete"] is False
    assert result["coverage_gaps"] == [
        "Incremental scan covers changed files only; project-wide coverage was not refreshed"
    ]


def test_html_report_escapes_untrusted_finding_text(tmp_path):
    db = Database(tmp_path / "xss.sqlite")
    scan = db.begin_code_scan(str(tmp_path.resolve()))
    db.finish_code_scan(scan.id, files_analyzed=1, changes=0, status="FINDINGS", scanners="[]")
    with db.session() as session:
        session.add(CodeFinding(project_path=str(tmp_path.resolve()), fingerprint="x" * 64, scanner="Test",
                                rule_id="xss", file_path="app.py", severity="HIGH",
                                description="<script>alert(1)</script>", evidence="safe",
                                recommendation="review", state="NEW"))
        session.commit()
    page = generate_html_report(db, tmp_path.resolve(), tmp_path / "html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_consolidated_report_lists_projects_and_file_changes(tmp_path, monkeypatch):
    db = Database(tmp_path / "consolidated.sqlite")
    first = (tmp_path / "Project One").resolve()
    second = (tmp_path / "Project Two").resolve()
    first.mkdir()
    second.mkdir()
    for project in (first, second):
        scan = db.begin_code_scan(str(project))
        db.finish_code_scan(scan.id, files_analyzed=1, changes=1, status="SAFE", scanners="[]")
    db.add_monitor_event(MonitorEvent(
        kind="file", severity="INFO", component=str(first / "README.txt"), detail="modified",
        risk="Mudanca observada", fingerprint="project-one-change",
    ))
    monkeypatch.setattr("atlas.report.Settings.load", lambda: type("S", (), {"watch_paths": []})())
    path = generate_markdown_report(db, output_dir=tmp_path / "reports")
    content = path.read_text(encoding="utf-8")
    assert "ATLAS Consolidated Security Report" in content
    assert str(first) in content and str(second) in content
    assert "README.txt" in content and "MODIFIED" in content
