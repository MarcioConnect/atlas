from pathlib import Path

from atlas.code_scanners import LocalCodeScanners, NormalizedFinding, is_ignored, is_priority_file
from atlas.config import Settings


def test_html_is_priority_file(tmp_path: Path):
    assert is_priority_file(tmp_path / "index.html")


def test_third_party_and_documentation_are_ignored(tmp_path: Path):
    assert is_ignored(tmp_path / "node_modules" / "pkg.py", tmp_path)
    assert is_ignored(tmp_path / "docs" / "example.py", tmp_path)
    assert is_ignored(tmp_path / "vendor" / "lib.py", tmp_path)


def test_fingerprint_is_stable_and_evidence_is_redacted(tmp_path: Path):
    project = tmp_path / "Project With Spaces"
    project.mkdir()
    target = project / "app.py"
    target.write_text("print('ok')", encoding="utf-8")
    first_secret = "very-" + "secret-value"
    second_secret = "another-" + "secret"
    first = NormalizedFinding("HIGH", "Test", "RULE-1", str(target), 7, "Issue", "to" + "ken=" + first_secret, "Fix").finalize(project)
    second = NormalizedFinding("HIGH", "Test", "RULE-1", str(target), 7, "Changed wording", "pass" + "word=" + second_secret, "Fix").finalize(project)
    assert first.fingerprint == second.fingerprint
    assert "very-secret-value" not in first.evidence
    assert "[REDACTED]" in first.evidence


def test_missing_optional_scanners_do_not_break(monkeypatch, tmp_path: Path):
    (tmp_path / "safe.py").write_text("print('safe')", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    result = LocalCodeScanners(tmp_path).scan()
    assert any(item.name == "Semgrep" and not item.available for item in result.availability)
    assert any(item.name == "ATLAS Native" and item.available for item in result.availability)
    assert "ATLAS Native" in result.coverage


def test_native_scanner_never_persists_secret(tmp_path: Path):
    sample_value = "ultra-" + "private-value-123"
    key_name = "API_" + "KEY"
    target = tmp_path / "settings.py"
    target.write_text(key_name + "='" + sample_value + "'", encoding="utf-8")
    result = LocalCodeScanners(tmp_path).scan([target])
    assert result.findings
    serialized = " ".join(item.evidence + item.description + item.recommendation for item in result.findings)
    assert sample_value not in serialized
    assert "[REDACTED]" in serialized


def test_incremental_native_scan_only_checks_changed_lines(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text("eval(user_input)\nprint('safe')\n", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    result = LocalCodeScanners(tmp_path).scan([target], changed_lines={str(target.resolve()).casefold(): {2}})
    assert not any(item.rule_id == "python-eval" for item in result.findings)


def test_native_python_rules_ignore_strings_and_comments(tmp_path: Path, monkeypatch):
    target = tmp_path / "docs_example.py"
    target.write_text("example = 'eval(user_input)'\n# exec(payload)\n", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    result = LocalCodeScanners(tmp_path).scan([target])
    assert not any(item.rule_id == "python-eval" for item in result.findings)


def test_rule_ignores_and_severity_overrides(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    monkeypatch.setattr("atlas.code_scanners.Settings.load", lambda: Settings(
        ignored_rules=[], risk_overrides={"python-eval": "CRITICAL"}))
    result = LocalCodeScanners(tmp_path).scan([target])
    assert result.findings[0].severity == "CRITICAL"
