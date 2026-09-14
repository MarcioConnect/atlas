from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_AGENT_MODEL = "deepseek-v4-flash-free"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:3b"


def data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    target = base / "ATLAS"
    target.mkdir(parents=True, exist_ok=True)
    return target


def config_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    target = base / "ATLAS"
    target.mkdir(parents=True, exist_ok=True)
    return target


@dataclass(slots=True)
class Settings:
    watch_paths: list[str] = field(default_factory=list)
    secret_scan_max_files: int = 4000
    secret_scan_max_bytes: int = 1_000_000
    splash_seconds: float = 0.8
    agent_model: str = DEFAULT_AGENT_MODEL
    monitor_interval_seconds: float = 3.0
    monitor_security_interval_seconds: int = 900
    watchdog_debounce_seconds: float = 2.0
    notifications_enabled: bool = True
    silent_mode: bool = False
    ignored_rules: list[str] = field(default_factory=list)
    risk_overrides: dict[str, str] = field(default_factory=dict)
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    ollama_timeout_seconds: float = 45.0

    @classmethod
    def load(cls) -> Settings:
        path = config_dir() / "settings.json"
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            allowed = {key: raw[key] for key in asdict(cls()) if key in raw}
            if allowed.get("agent_model") == "nemotron-3-ultra-free":
                allowed["agent_model"] = DEFAULT_AGENT_MODEL
            return cls(**allowed)
        except (OSError, ValueError, TypeError):
            return cls()

    def save(self) -> None:
        path = config_dir() / "settings.json"
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


DB_PATH = data_dir() / "atlas.db"
