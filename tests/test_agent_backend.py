from pathlib import Path

from atlas import agent_backend


def test_agent_launches_hermes_tui_in_same_terminal(monkeypatch, tmp_path: Path):
    captured = {}
    monkeypatch.setattr(agent_backend, "find_hermes", lambda: "hermes.exe")
    monkeypatch.setattr(agent_backend, "ensure_agent_profile", lambda executable: tmp_path / "profile")
    monkeypatch.setattr(agent_backend, "ensure_monitoring", lambda target: None)

    def fake_call(command, cwd, env, shell):
        captured.update(command=command, cwd=cwd, env=env, shell=shell)
        return 0

    monkeypatch.setattr(agent_backend.subprocess, "call", fake_call)
    assert agent_backend.launch_agent(tmp_path) == 0
    assert captured["shell"] is False
    assert captured["cwd"] == tmp_path
    assert "--tui" in captured["command"]
    assert captured["command"][captured["command"].index("--profile") + 1] == "atlas"
    assert captured["command"][captured["command"].index("--provider") + 1] == "opencode-free"
    assert "deepseek-v4-flash-free" in captured["command"]
    # ATLAS intentionally displays its own branded banner; the legacy Hermes
    # banner is replaced by the ⚕ ATLAS header in the local TUI skin.
    assert captured["env"]["ATLAS_HIDE_HERMES_BANNER"] == "0"


def test_old_model_name_is_normalized():
    assert agent_backend._normalize_model("opencode/nemotron-3-ultra-free") == "nemotron-3-ultra-free"


def test_missing_backend_is_clear(monkeypatch):
    monkeypatch.setattr(agent_backend, "find_hermes", lambda: None)
    try:
        agent_backend.launch_agent()
    except RuntimeError as exc:
        assert "backend" in str(exc)
    else:
        raise AssertionError("RuntimeError esperado")
