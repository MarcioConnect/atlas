import sqlite3
from pathlib import Path

from atlas.database import Database
from atlas.models import Scan, Severity
from atlas.security import finding


def test_scan_round_trip(tmp_path: Path):
    database = Database(tmp_path / "atlas.db")
    scan = Scan(
        hostname="test-host",
        score=85,
        findings=[finding("test", "Teste", Severity.HIGH, "evidencia", "risco", "componente", "corrigir")],
    )
    database.save_scan(scan)
    loaded = database.latest_scan()
    assert loaded is not None
    assert loaded.score == 85
    assert loaded.findings[0].severity == "HIGH"


def test_code_finding_lifecycle_preserves_suppression_and_confidence(tmp_path: Path):

    database = Database(tmp_path / "lifecycle.sqlite")
    scan = database.begin_code_scan(str(tmp_path))
    result = database.reconcile_code_findings(str(tmp_path), scan.id, [{
        "fingerprint": "a" * 64, "scanner": "ATLAS Native", "rule_id": "python-eval",
        "file_path": str(tmp_path / "app.py"), "line": 1, "severity": "HIGH",
        "description": "Dynamic execution", "evidence": "source omitted", "recommendation": "Use parser",
        "category": "code", "confidence": 80, "suppressed": True, "suppression_reason": "Validated parser input",
    }], {"ATLAS Native": None})
    assert len(result["SUPPRESSED"]) == 1
    stored = database.code_findings(str(tmp_path))[0]
    assert stored.state == "SUPPRESSED"
    assert stored.suppression_reason == "Validated parser input"
    assert stored.confidence == 80


def test_database_additively_migrates_legacy_code_findings(tmp_path: Path):
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("""CREATE TABLE code_findings (
            id INTEGER PRIMARY KEY, project_path TEXT NOT NULL, fingerprint VARCHAR(64) NOT NULL,
            scanner VARCHAR(40) NOT NULL, rule_id VARCHAR(255) NOT NULL, file_path TEXT NOT NULL,
            line INTEGER, severity VARCHAR(10) NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL,
            recommendation TEXT NOT NULL, state VARCHAR(10) NOT NULL, first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL, resolved_at DATETIME, last_scan_id INTEGER
        )""")
        connection.execute("""INSERT INTO code_findings
            (project_path, fingerprint, scanner, rule_id, file_path, severity, description, evidence,
             recommendation, state, first_seen, last_seen)
            VALUES ('project', 'legacy', 'old', 'rule', 'app.py', 'LOW', 'old', 'safe', 'review',
                    'EXISTING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""")
    Database(path)
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(code_findings)")}
        row = connection.execute("SELECT category, confidence, suppressed, suppression_reason FROM code_findings").fetchone()
    assert {"category", "confidence", "suppressed", "suppression_reason"}.issubset(columns)
    assert row == ("code", 70, 0, "")


def test_database_additively_migrates_legacy_code_scans(tmp_path: Path):
    path = tmp_path / "legacy-scans.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("""CREATE TABLE code_scans (
            id INTEGER PRIMARY KEY, project_path TEXT NOT NULL, started_at DATETIME NOT NULL,
            completed_at DATETIME, trigger_file TEXT, files_analyzed INTEGER NOT NULL DEFAULT 0,
            changes INTEGER NOT NULL DEFAULT 0, status VARCHAR(20) NOT NULL DEFAULT 'SCANNING',
            scanners TEXT NOT NULL DEFAULT ''
        )""")
        connection.execute("""INSERT INTO code_scans
            (project_path, started_at, files_analyzed, status)
            VALUES ('project', CURRENT_TIMESTAMP, 4, 'SAFE')""")
    Database(path)
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(code_scans)")}
        row = connection.execute("SELECT files_analyzed, files_skipped_large FROM code_scans").fetchone()
    assert "files_skipped_large" in columns
    assert row == (4, 0)


def test_successfully_completed_stopped_scan_still_anchors_baseline(tmp_path: Path):
    database = Database(tmp_path / "stopped.sqlite")
    project = str((tmp_path / "project").resolve())
    scan = database.begin_code_scan(project)

    database.finish_code_scan(scan.id, files_analyzed=1, changes=0, status="STOPPED",
                               scanners='[{"name":"ATLAS Native","available":true}]')

    assert database.has_completed_code_scan(project)
