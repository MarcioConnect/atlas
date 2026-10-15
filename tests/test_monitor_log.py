from pathlib import Path

from typer.testing import CliRunner

from atlas import monitor
from atlas.cli import app

runner = CliRunner()


def _patch_log_paths(monkeypatch, tmp_path: Path):
    log_dir = tmp_path / "logs"
    monkeypatch.setattr(monitor, "LOG_DIR", log_dir)
    monkeypatch.setattr(monitor, "MONITOR_LOG", log_dir / "monitor.log")
    monkeypatch.setattr(monitor, "MONITOR_LOG_OLD", log_dir / "monitor.log.old")


def test_log_monitor_redacts_and_reads_back(tmp_path, monkeypatch):
    _patch_log_paths(monkeypatch, tmp_path)
    monitor.log_monitor("token=abcdef1234567890exposto")
    monitor.log_monitor("monitor iniciado")

    lines = monitor.read_monitor_log()
    assert len(lines) == 2
    assert "abcdef1234567890exposto" not in lines[0]
    assert "[REDACTED]" in lines[0]
    assert lines[1].endswith("monitor iniciado")
    assert monitor.read_monitor_log(limit=1) == [lines[1]]


def test_rotate_monitor_log_keeps_single_old_copy(tmp_path, monkeypatch):
    _patch_log_paths(monkeypatch, tmp_path)
    monitor.LOG_DIR.mkdir(parents=True)
    monitor.MONITOR_LOG.write_text("x" * 2048, encoding="utf-8")

    monitor.rotate_monitor_log(max_bytes=1024)

    assert monitor.MONITOR_LOG_OLD.exists()
    assert not monitor.MONITOR_LOG.exists()
    assert monitor.read_monitor_log()[0].startswith("xxx")


def test_read_monitor_log_without_file(tmp_path, monkeypatch):
    _patch_log_paths(monkeypatch, tmp_path)
    assert monitor.read_monitor_log() == []


def test_monitor_logs_command_prints_recent_lines(tmp_path, monkeypatch):
    _patch_log_paths(monkeypatch, tmp_path)
    monitor.log_monitor("primeira linha")
    monitor.log_monitor("segunda linha")
    monkeypatch.setattr("atlas.cli.time.sleep", lambda *_: None)

    result = runner.invoke(app, ["monitor", "logs", "--limit", "5"])

    assert result.exit_code == 0, result.stdout
    assert "primeira linha" in result.stdout
    assert "segunda linha" in result.stdout


def test_monitor_logs_command_without_log(tmp_path, monkeypatch):
    _patch_log_paths(monkeypatch, tmp_path)
    result = runner.invoke(app, ["monitor", "logs"])
    assert result.exit_code == 0
    assert "Nenhum log" in result.stdout
