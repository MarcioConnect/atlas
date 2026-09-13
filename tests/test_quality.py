from atlas.code_scanners import LocalCodeScanners
from atlas.code_watch import CodeWatchdog
from atlas.database import Database


def test_syntax_lifecycle_without_optional_tools(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda name: None)
    project = tmp_path / "Project With Spaces"
    project.mkdir()
    path = project / "config.json"
    path.write_text('{"enabled": }')
    watcher = CodeWatchdog(project, Database(tmp_path / "history.db"))
    watcher.scan_now(None)
    assert any(f.rule_id == "syntax-json" for f in watcher.state.new)
    path.write_text('{"enabled": true}')
    watcher.scan_now(None)
    assert any(f.rule_id == "syntax-json" for f in watcher.state.resolved)


def test_python_is_parsed_without_execution(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda name: None)
    marker = tmp_path / "must-not-exist"
    path = tmp_path / "app.py"
    path.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    result = LocalCodeScanners(tmp_path).scan([path])
    assert not marker.exists()
    assert not any(f.scanner == "ATLAS Syntax" for f in result.findings)
    path.write_text("def broken(:\n")
    result = LocalCodeScanners(tmp_path).scan([path])
    assert any(f.rule_id == "syntax-py" for f in result.findings)
