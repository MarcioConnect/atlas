"""Per-project ``.atlas.toml`` overrides.

Lets a repository tune the scanner without touching the user's global settings:

    [scan]
    ignored_rules = ["python-eval", "B602"]
    risk_overrides = { B602 = "LOW" }
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

CONFIG_NAME = ".atlas.toml"


def project_config_path(project: Path) -> Path:
    return project / CONFIG_NAME


def load_project_overrides(project: Path) -> dict[str, Any]:
    """Parse ``.atlas.toml`` defensively; invalid input is ignored, never fatal."""
    path = project_config_path(project)
    if not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    scan = data.get("scan")
    if not isinstance(scan, dict):
        return {}
    overrides: dict[str, Any] = {}
    ignored = scan.get("ignored_rules")
    if isinstance(ignored, list):
        overrides["ignored_rules"] = [str(item) for item in ignored if isinstance(item, str) and item.strip()]
    risk = scan.get("risk_overrides")
    if isinstance(risk, dict):
        overrides["risk_overrides"] = {
            str(rule): str(level) for rule, level in risk.items() if isinstance(level, (str, int, float))
        }
    return overrides
