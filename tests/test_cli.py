import json

import pytest
from typer.testing import CliRunner

from atlas import __version__
from atlas.cli import app

runner = CliRunner()


@pytest.mark.parametrize("realtime, expected, exit_code", [
    (True, "Defender ACTIVE", 0),
    (False, "Defender protection incomplete", 0),
    (None, "Defender protection status unknown", 1),
    ("true", "Defender protection status unknown", 1),
])
def test_defender_cli_requires_real_protection_values(monkeypatch, realtime, expected, exit_code):
    from atlas.threats import DefenderSnapshot

    status = {"AMServiceEnabled": True, "AntivirusEnabled": True, "AntispywareEnabled": True,
              "RealTimeProtectionEnabled": realtime}
    monkeypatch.setattr("atlas.threats.defender_snapshot", lambda: DefenderSnapshot(True, status, []))
    result = runner.invoke(app, ["malware", "status"])
    assert result.exit_code == exit_code
    assert expected in result.stdout


def test_defender_cli_does_not_claim_protection_with_missing_telemetry(monkeypatch):
    from atlas.threats import DefenderSnapshot

    monkeypatch.setattr("atlas.threats.defender_snapshot", lambda: DefenderSnapshot(True, {}, []))
    result = runner.invoke(app, ["malware", "status"])
    assert result.exit_code == 1
    assert "Defender protection status unknown" in result.stdout


def test_defender_cli_explains_unavailable_threat_history(monkeypatch):
    from atlas.threats import DefenderSnapshot

    status = dict.fromkeys(("AMServiceEnabled", "AntivirusEnabled", "AntispywareEnabled",
                            "RealTimeProtectionEnabled"), True)
    detail = "Threat history unavailable: PermissionError"
    monkeypatch.setattr("atlas.threats.defender_snapshot", lambda: DefenderSnapshot(True, status, [], detail))
    result = runner.invoke(app, ["malware", "status"])
    assert result.exit_code == 0
    assert detail in result.stdout
    assert "Detections in Defender history: 0" not in result.stdout


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_watch_ai_help_requires_explicit_review():
    result = runner.invoke(app, ["watch", "--help"])
    assert result.exit_code == 0
    assert "revisao explicita" in result.stdout


def test_history_empty(monkeypatch, tmp_path):
    monkeypatch.setattr("atlas.cli.Database", lambda: __import__("atlas.database", fromlist=["Database"]).Database(tmp_path / "db.sqlite"))
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "Historico" in result.stdout


def test_bare_atlas_opens_native_tui(monkeypatch):
    opened = []
    monkeypatch.setattr("atlas.tui.run_tui", lambda: opened.append(True))

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert opened == [True]


def test_agent_opens_integrated_panel_with_legacy_alias(monkeypatch):
    opened = []
    monkeypatch.setattr("atlas.panel.AtlasPanel.run", lambda self: opened.append(True))
    result = runner.invoke(app, ["agent", "--advanced"])
    assert result.exit_code == 0
    assert opened == [True]


def test_agent_model_reaches_chat_and_watch(monkeypatch):
    opened = []
    monkeypatch.setattr('atlas.panel.AtlasPanel.run', lambda self: opened.append(
        (self.assistant.model, self.watchdog.ai_model)))
    result = runner.invoke(app, ['agent', '--model', 'local-test:3b'])
    assert result.exit_code == 0
    assert opened == [('local-test:3b', 'local-test:3b')]


def test_config_adds_project_and_risk_override(monkeypatch, tmp_path):
    project = tmp_path / "Project With Spaces"
    project.mkdir()
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    result = runner.invoke(app, ["config", "--add-path", str(project), "--risk", "python-eval=critical"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert str(project.resolve()) in payload["watch_paths"]
    assert payload["risk_overrides"]["python-eval"] == "CRITICAL"


def test_watch_without_path_uses_configured_projects(monkeypatch, tmp_path):
    project = tmp_path / "configured project"
    project.mkdir()
    monkeypatch.setattr("atlas.multi_watch.Settings.load", lambda: type("S", (), {"watch_paths": [str(project)]})())
    opened = []
    monkeypatch.setattr("atlas.watch_tui.run_multi_watch_tui", lambda paths: opened.append(paths))
    result = runner.invoke(app, ["watch"])
    assert result.exit_code == 0
    assert opened == [[project.resolve()]]


def test_scan_command_runs_one_local_project_scan(tmp_path, monkeypatch):
    from atlas.config import Settings
    from atlas.database import Database

    project = tmp_path / "Project With Spaces"
    project.mkdir()
    (project / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    database = Database(tmp_path / "atlas.sqlite")
    monkeypatch.setattr("atlas.cli.Database", lambda: database)
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    monkeypatch.setattr("atlas.code_watch.Settings.load", lambda: Settings())
    monkeypatch.setattr("atlas.code_scanners.Settings.load", lambda: Settings())

    result = runner.invoke(app, ["scan", str(project)])

    assert result.exit_code == 0, result.stdout
    assert "ATLAS SCAN" in result.stdout
    findings = database.code_findings(str(project.resolve()))
    assert any(item.rule_id == "python-eval" for item in findings)


def test_scan_command_supports_json_and_reports_partial_coverage(tmp_path, monkeypatch):
    from atlas.config import Settings
    from atlas.database import Database

    project = tmp_path / "json project"
    project.mkdir()
    (project / "clean.py").write_text("print('hello')\n", encoding="utf-8")
    database = Database(tmp_path / "atlas-json.sqlite")
    monkeypatch.setattr("atlas.cli.Database", lambda: database)
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    monkeypatch.setattr("atlas.code_watch.Settings.load", lambda: Settings())
    monkeypatch.setattr("atlas.code_scanners.Settings.load", lambda: Settings())

    result = runner.invoke(app, ["scan", str(project), "--format", "json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["projects"][0]["scan"]["complete"] is False
    assert payload["projects"][0]["scan"]["unavailable_scanners"]
