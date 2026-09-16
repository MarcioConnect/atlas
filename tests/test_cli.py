import json

from typer.testing import CliRunner

from atlas import __version__
from atlas.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_history_empty(monkeypatch, tmp_path):
    monkeypatch.setattr("atlas.cli.Database", lambda: __import__("atlas.database", fromlist=["Database"]).Database(tmp_path / "db.sqlite"))
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "Historico" in result.stdout


def test_bare_atlas_opens_native_tui_not_hermes(monkeypatch):
    opened = []
    monkeypatch.setattr("atlas.tui.run_tui", lambda: opened.append(True))
    monkeypatch.setattr(
        "atlas.agent_backend.launch_agent",
        lambda: (_ for _ in ()).throw(AssertionError("Hermes must not start")),
    )

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert opened == [True]


def test_agent_opens_advanced_atlas_conversation_when_available(monkeypatch):
    opened = []
    monkeypatch.setattr("atlas.panel.AtlasPanel.run", lambda self: opened.append(True))

    result = runner.invoke(app, ["agent"])

    assert result.exit_code == 0
    assert len(opened) == 1


def test_agent_falls_back_to_portable_local_ui(monkeypatch):
    opened = []
    monkeypatch.setattr("atlas.panel.AtlasPanel.run", lambda self: opened.append(True))
    result = runner.invoke(app, ["agent"])
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
