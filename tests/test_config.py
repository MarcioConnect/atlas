import json

from atlas.config import Settings


def test_settings_reject_malformed_values_without_crashing(tmp_path, monkeypatch):
    config = tmp_path / "ATLAS"
    config.mkdir()
    (config / "settings.json").write_text(json.dumps({
        "watch_paths": "C:/unexpected",
        "ignored_rules": ["rule", 4],
        "risk_overrides": ["not", "a", "mapping"],
        "finding_suppressions": [{"fingerprint": "short", "reason": "bad"}, "invalid"],
        "watchdog_debounce_seconds": "not-a-number",
        "notifications_enabled": "yes",
    }), encoding="utf-8")
    monkeypatch.setattr("atlas.config.config_dir", lambda: config)
    settings = Settings.load()
    assert settings.watch_paths == []
    assert settings.ignored_rules == ["rule"]
    assert settings.risk_overrides == {}
    assert settings.finding_suppressions == []
    assert settings.watchdog_debounce_seconds == 2.0
    assert settings.notifications_enabled is True


def test_settings_save_replaces_configuration_atomically(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.config.config_dir", lambda: tmp_path)
    settings = Settings(watch_paths=[str(tmp_path / "Project With Spaces")])
    settings.save()
    assert json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))["watch_paths"] == settings.watch_paths
    assert list(tmp_path.glob("*.tmp")) == []
