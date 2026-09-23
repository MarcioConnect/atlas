from __future__ import annotations

import json
import os
import uuid
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
    finding_suppressions: list[dict[str, str]] = field(default_factory=list)
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    ollama_timeout_seconds: float = 45.0
    ai_review_enabled: bool = False

    @classmethod
    def load(cls) -> Settings:
        path = config_dir() / "settings.json"
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return cls()
            allowed = {key: raw[key] for key in asdict(cls()) if key in raw}
            if allowed.get("agent_model") == "nemotron-3-ultra-free":
                allowed["agent_model"] = DEFAULT_AGENT_MODEL
            for key in ("watch_paths", "ignored_rules"):
                values = allowed.get(key, [])
                allowed[key] = [item[:2000] for item in values if isinstance(item, str)][:1000] if isinstance(values, list) else []
            overrides = allowed.get("risk_overrides", {})
            allowed["risk_overrides"] = {
                str(key)[:255]: str(value).upper() for key, value in overrides.items()
                if isinstance(overrides, dict) and isinstance(key, str) and isinstance(value, str)
                and value.upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            } if isinstance(overrides, dict) else {}
            suppressions = allowed.get("finding_suppressions", [])
            allowed["finding_suppressions"] = [
                {"fingerprint": item["fingerprint"], "reason": item["reason"][:500], "expires_at": item["expires_at"][:64]}
                for item in suppressions if isinstance(item, dict)
                and isinstance(item.get("fingerprint"), str) and len(item["fingerprint"]) == 64
                and isinstance(item.get("reason"), str) and isinstance(item.get("expires_at"), str)
            ][:10_000] if isinstance(suppressions, list) else []
            for key, default, minimum, maximum in (
                ("secret_scan_max_files", 4000, 1, 100_000),
                ("secret_scan_max_bytes", 1_000_000, 1024, 100_000_000),
                ("monitor_security_interval_seconds", 900, 30, 86_400),
                ("ollama_timeout_seconds", 45.0, 1.0, 300.0),
                ("monitor_interval_seconds", 3.0, 0.5, 60.0),
                ("watchdog_debounce_seconds", 2.0, 0.2, 30.0),
            ):
                value = allowed.get(key, default)
                try:
                    allowed[key] = min(max(float(value), minimum), maximum)
                    if isinstance(default, int):
                        allowed[key] = int(allowed[key])
                except (TypeError, ValueError):
                    allowed[key] = default
            for key, default in (("notifications_enabled", True), ("silent_mode", False), ("ai_review_enabled", False)):
                if not isinstance(allowed.get(key, default), bool):
                    allowed[key] = default
            for key, default in (("agent_model", DEFAULT_AGENT_MODEL), ("ollama_model", DEFAULT_OLLAMA_MODEL)):
                value = allowed.get(key, default)
                allowed[key] = value.strip()[:160] if isinstance(value, str) and value.strip() else default
            return cls(**allowed)
        except (OSError, ValueError, TypeError):
            return cls()

    def save(self) -> None:
        path = config_dir() / "settings.json"
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


DB_PATH = data_dir() / "atlas.db"
