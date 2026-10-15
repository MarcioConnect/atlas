from typer.testing import CliRunner

from atlas.cli import app
from atlas.hooks import hook_script, install_pre_commit_hook

runner = CliRunner()


def _git_repo(tmp_path):
    project = tmp_path / "repo"
    (project / ".git" / "hooks").mkdir(parents=True)
    return project


def test_install_hook_creates_executable_script(tmp_path):
    project = _git_repo(tmp_path)
    installed, _detail = install_pre_commit_hook(project, "HIGH", force=False)
    assert installed
    hook = project / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    content = hook.read_text(encoding="utf-8")
    assert "atlas scan . --fail-on HIGH" in content
    assert "ATLAS" in content


def test_install_hook_refuses_to_overwrite_foreign_hook(tmp_path):
    project = _git_repo(tmp_path)
    hook = project / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
    installed, detail = install_pre_commit_hook(project, "HIGH")
    assert not installed
    assert "--force" in detail
    assert "echo custom" in hook.read_text(encoding="utf-8")

    forced, _ = install_pre_commit_hook(project, "HIGH", force=True)
    assert forced
    assert "atlas scan" in hook.read_text(encoding="utf-8")


def test_install_hook_without_git_repository(tmp_path, monkeypatch):
    project = tmp_path / "plain"
    project.mkdir()
    monkeypatch.setattr("atlas.hooks.subprocess.run", lambda *a, **k: type("R", (), {"returncode": 128})())
    installed, detail = install_pre_commit_hook(project)
    assert not installed
    assert "Git" in detail


def test_hook_script_uses_python_module_invocation():
    script = hook_script("CRITICAL")
    assert "-m atlas scan . --fail-on CRITICAL" in script
    assert script.startswith("#!/bin/sh")


def test_install_hook_command(tmp_path):
    project = _git_repo(tmp_path)
    result = runner.invoke(app, ["install-hook", "--project", str(project), "--fail-on", "MEDIUM"])
    assert result.exit_code == 0, result.stdout
    assert (project / ".git" / "hooks" / "pre-commit").exists()


def test_install_hook_command_errors_without_git(tmp_path, monkeypatch):
    project = tmp_path / "plain"
    project.mkdir()
    monkeypatch.setattr("atlas.hooks.subprocess.run", lambda *a, **k: type("R", (), {"returncode": 128})())
    result = runner.invoke(app, ["install-hook", "--project", str(project)])
    assert result.exit_code == 1
    assert "Git" in result.output
