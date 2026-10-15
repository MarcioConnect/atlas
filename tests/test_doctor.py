from typer.testing import CliRunner

from atlas import doctor
from atlas.cli import app
from atlas.doctor import Check

runner = CliRunner()


def test_scanner_checks_flag_missing_tools(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: r"C:\tools\ruff.exe" if name == "ruff" else None)
    checks = {check.name: check for check in doctor._scanner_checks()}
    assert checks["Scanner nativo ATLAS"].ok
    assert checks["Scanner opcional: Ruff"].ok
    assert not checks["Scanner opcional: Trivy"].ok
    assert checks["Scanner opcional: Trivy"].warning
    assert "winget" in checks["Scanner opcional: Trivy"].fix


def test_ollama_check_reports_states(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    monkeypatch.setattr(doctor.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    not_installed = doctor._ollama_check()
    assert not not_installed.ok and not_installed.warning

    monkeypatch.setattr(doctor.shutil, "which", lambda name: r"C:\ollama.exe")

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(doctor.socket, "create_connection", lambda *a, **k: FakeSocket())
    running = doctor._ollama_check()
    assert running.ok


def test_login_task_check_uses_schtasks(monkeypatch):
    monkeypatch.setattr(doctor.os, "name", "nt")

    class Result:
        returncode = 0

    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: Result())
    assert doctor._login_task_check().ok

    Result.returncode = 1
    missing = doctor._login_task_check()
    assert not missing.ok and "atlas monitor install" in missing.fix


def test_database_check_reports_size(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.database.DB_PATH", tmp_path / "atlas.db")
    monkeypatch.setattr("atlas.doctor.DB_PATH", tmp_path / "atlas.db")
    check = doctor._database_check()
    assert check.ok


def test_doctor_command_exit_codes(monkeypatch):
    monkeypatch.setattr(doctor, "collect_checks", lambda: [Check("Python", True, "ok")])
    result = runner.invoke(app, ["doctor", "--no-fix"])
    assert result.exit_code == 0, result.stdout
    assert "Python" in result.stdout

    monkeypatch.setattr(doctor, "collect_checks", lambda: [Check("Banco de dados local", False, "quebrado")])
    failing = runner.invoke(app, ["doctor", "--no-fix"])
    assert failing.exit_code == 1
