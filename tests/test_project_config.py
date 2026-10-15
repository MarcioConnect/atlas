from atlas.code_scanners import LocalCodeScanners
from atlas.config import Settings
from atlas.project_config import load_project_overrides, project_config_path


def test_missing_project_config_returns_empty(tmp_path):
    assert load_project_overrides(tmp_path) == {}


def test_valid_project_config_is_parsed(tmp_path):
    (tmp_path / ".atlas.toml").write_text(
        '[scan]\nignored_rules = ["python-eval", "B602"]\n'
        'risk_overrides = { python-eval = "LOW" }\n',
        encoding="utf-8",
    )
    overrides = load_project_overrides(tmp_path)
    assert overrides["ignored_rules"] == ["python-eval", "B602"]
    assert overrides["risk_overrides"] == {"python-eval": "LOW"}


def test_invalid_project_config_is_ignored(tmp_path):
    (tmp_path / ".atlas.toml").write_text("this is not = = toml\n", encoding="utf-8")
    assert load_project_overrides(tmp_path) == {}
    assert project_config_path(tmp_path).name == ".atlas.toml"


def _scan_project(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    monkeypatch.setattr("atlas.code_scanners.Settings.load", lambda: Settings())
    return LocalCodeScanners(tmp_path).scan()


def test_project_config_ignores_rule(tmp_path, monkeypatch):
    (tmp_path / ".atlas.toml").write_text('[scan]\nignored_rules = ["python-eval"]\n', encoding="utf-8")
    result = _scan_project(tmp_path, monkeypatch)
    assert not any(item.rule_id == "python-eval" for item in result.findings)


def test_project_config_downgrades_risk(tmp_path, monkeypatch):
    (tmp_path / ".atlas.toml").write_text('[scan]\nrisk_overrides = { python-eval = "LOW" }\n', encoding="utf-8")
    result = _scan_project(tmp_path, monkeypatch)
    matches = [item for item in result.findings if item.rule_id == "python-eval"]
    assert matches and all(item.severity == "LOW" for item in matches)


def test_without_project_config_rule_is_reported(tmp_path, monkeypatch):
    result = _scan_project(tmp_path, monkeypatch)
    assert any(item.rule_id == "python-eval" for item in result.findings)
