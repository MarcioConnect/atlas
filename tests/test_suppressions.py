import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from atlas.cli import app
from atlas.config import Settings
from atlas.database import Database
from atlas.models import CodeFinding
from atlas.suppressions import active_suppressions, add_suppression, expires_in_days, remove_suppression

runner = CliRunner()


def _add_finding(database: Database, project: Path, *, fingerprint: str, rule: str, file_path: str) -> None:
    with database.session() as session:
        session.add(CodeFinding(
            project_path=str(project), fingerprint=fingerprint, scanner="ATLAS Native", rule_id=rule,
            file_path=str(project / file_path), line=3, severity="HIGH", category="code",
            description="Dynamic execution", evidence="omitted", recommendation="review", state="NEW",
        ))
        session.commit()


def test_add_and_remove_suppression_round_trip():
    settings = Settings()
    entry = add_suppression(settings, "a" * 64, "falso positivo revisado", 15)
    assert entry["fingerprint"] == "a" * 64
    assert entry["reason"] == "falso positivo revisado"
    assert active_suppressions(settings) == [entry]
    assert expires_in_days(entry) in {14, 15}
    assert remove_suppression(settings, "a" * 64)
    assert settings.finding_suppressions == []


def test_add_suppression_requires_valid_input():
    settings = Settings()
    with pytest.raises(ValueError):
        add_suppression(settings, "short", "motivo", 30)
    with pytest.raises(ValueError):
        add_suppression(settings, "b" * 64, "   ", 30)


def test_expired_suppression_is_not_active():
    settings = Settings(finding_suppressions=[{
        "fingerprint": "c" * 64, "reason": "antigo", "expires_at": "2000-01-01T00:00:00+00:00",
    }])
    assert active_suppressions(settings) == []


def test_database_resolves_latest_finding_by_rule_and_file(tmp_path):
    database = Database(tmp_path / "resolve.sqlite")
    project = tmp_path
    _add_finding(database, project, fingerprint="d" * 64, rule="python-eval", file_path="app.py")
    _add_finding(database, project, fingerprint="e" * 64, rule="python-eval", file_path="other.py")

    assert database.latest_code_finding_by_rule("python-eval").fingerprint in {"d" * 64, "e" * 64}
    assert database.latest_code_finding_by_rule("python-eval", "other.py").fingerprint == "e" * 64
    assert database.latest_code_finding_by_rule("python-eval", "missing.py") is None


def test_apply_suppression_marks_stored_findings(tmp_path):
    database = Database(tmp_path / "apply.sqlite")
    _add_finding(database, tmp_path, fingerprint="f" * 64, rule="python-eval", file_path="app.py")
    assert database.apply_suppression("f" * 64, "aceito temporariamente") == 1
    stored = database.code_findings(str(tmp_path))[0]
    assert stored.suppressed is True
    assert stored.state == "SUPPRESSED"
    assert stored.suppression_reason == "aceito temporariamente"


def test_config_suppress_rule_and_list(monkeypatch, tmp_path):
    project = tmp_path / "Project"
    project.mkdir()
    database = Database(tmp_path / "cli.sqlite")
    _add_finding(database, project, fingerprint="g" * 64, rule="python-eval", file_path="app.py")
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    monkeypatch.setattr("atlas.cli.Database", lambda: database)

    result = runner.invoke(app, [
        "config", "--suppress-rule", "python-eval", "--file", "app.py", "--days", "10", "--reason", "revisado",
    ])
    assert result.exit_code == 0, result.stdout
    saved = json.loads((tmp_path / "config" / "ATLAS" / "settings.json").read_text(encoding="utf-8"))
    assert saved["finding_suppressions"][0]["fingerprint"] == "g" * 64

    listing = runner.invoke(app, ["config", "--list-suppressions"])
    assert listing.exit_code == 0, listing.stdout
    assert "python-eval" in listing.stdout
    assert "revisado" in listing.stdout


def test_config_suppress_rule_without_match_errors(monkeypatch, tmp_path):
    database = Database(tmp_path / "cli-empty.sqlite")
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    monkeypatch.setattr("atlas.cli.Database", lambda: database)
    result = runner.invoke(app, ["config", "--suppress-rule", "missing-rule"])
    assert result.exit_code != 0
    assert "Nenhum finding" in result.output
