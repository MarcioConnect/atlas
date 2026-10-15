import json

from typer.testing import CliRunner

from atlas.cli import app
from atlas.config import Settings
from atlas.onboarding import add_watch_paths, discover_git_projects

runner = CliRunner()


def _make_git_project(path):
    path.mkdir(parents=True, exist_ok=True)
    (path / ".git").mkdir(exist_ok=True)
    return path


def test_discover_git_projects_respects_depth(tmp_path):
    _make_git_project(tmp_path / "proj_a")
    _make_git_project(tmp_path / "proj_b")
    _make_git_project(tmp_path / "group" / "proj_c")
    (tmp_path / "not_project").mkdir()

    found = {path.name for path in discover_git_projects(bases=[tmp_path], max_depth=3)}
    assert found == {"proj_a", "proj_b", "proj_c"}


def test_discover_git_projects_limits_results(tmp_path):
    for index in range(5):
        _make_git_project(tmp_path / f"proj_{index}")
    found = discover_git_projects(bases=[tmp_path], max_depth=2, limit=2)
    assert len(found) == 2


def test_add_watch_paths_merges_without_duplicates(tmp_path):
    project = tmp_path / "Project"
    project.mkdir()
    settings = Settings(watch_paths=[str(project.resolve())])
    added = add_watch_paths(settings, [project, tmp_path / "Project"])
    assert added == []
    assert settings.watch_paths == [str(project.resolve())]


def test_init_command_saves_paths_without_prompt(monkeypatch, tmp_path):
    project = tmp_path / "My Project"
    project.mkdir()
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))

    result = runner.invoke(app, ["init", "--path", str(project), "--yes", "--no-scan"])

    assert result.exit_code == 0, result.stdout
    saved = json.loads((tmp_path / "config" / "ATLAS" / "settings.json").read_text(encoding="utf-8"))
    assert str(project.resolve()) in saved["watch_paths"]


def test_init_command_runs_first_scan(monkeypatch, tmp_path):
    project = tmp_path / "My Project"
    project.mkdir()
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    scanned = []

    class FakeState:
        new = []
        existing = []
        files_analyzed = 0
        health = "COMPLETE"

    class FakeWatchdog:
        state = FakeState()

    def fake_scan(project_path, database):
        scanned.append(project_path)
        return FakeWatchdog()

    monkeypatch.setattr("atlas.cli._scan_once", fake_scan)

    result = runner.invoke(app, ["init", "--path", str(project), "--yes"])

    assert result.exit_code == 0, result.stdout
    assert scanned == [project.resolve()]
    assert "Scan concluído" in result.stdout


def test_init_command_requires_a_project(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    monkeypatch.setattr("atlas.onboarding.discover_git_projects", lambda **_: [])
    result = runner.invoke(app, ["init", "--yes", "--no-scan"])
    assert result.exit_code != 0
    assert "Nenhum projeto" in result.stdout
