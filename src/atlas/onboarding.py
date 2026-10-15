"""First-run onboarding: discover git projects and persist watch paths."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from atlas.config import Settings

DEFAULT_MAX_DEPTH = 3
DEFAULT_LIMIT = 50
# Directories that never contain a user project root worth scanning.
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".nox", ".venv", "venv", "node_modules",
    "__pycache__", "AppData", "Library", "site-packages", ".cache", "dist",
    "build", "target", ".idea", ".vscode", "Applications", "Windows",
}


def default_search_roots() -> list[Path]:
    home = Path.home()
    roots = [
        home / "Documents",
        home / "Desktop",
        home / "OneDrive",
        home / "Documents" / "GitHub",
        home / "source" / "repos",
        home,
    ]
    return roots


def discover_git_projects(
    bases: Iterable[Path] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    limit: int = DEFAULT_LIMIT,
) -> list[Path]:
    """Find folders that contain a ``.git`` directory, bounded by depth/count.

    The scan never descends into ``.git`` or heavy cache directories and stops as
    soon as ``limit`` projects were collected.
    """
    roots = list(bases) if bases is not None else default_search_roots()
    found: dict[str, Path] = {}
    seen_roots: set[str] = set()
    for root in roots:
        try:
            root = root.expanduser().resolve()
        except OSError:
            continue
        key = str(root).casefold()
        if key in seen_roots or not root.is_dir():
            continue
        seen_roots.add(key)
        try:
            for dirpath, dirnames, _ in os.walk(root):
                try:
                    depth = len(Path(dirpath).resolve().relative_to(root).parts)
                except (OSError, ValueError):
                    dirnames[:] = []
                    continue
                dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")]
                if _has_git(dirpath):
                    resolved = Path(dirpath).resolve()
                    found.setdefault(str(resolved).casefold(), resolved)
                    if len(found) >= limit:
                        return sorted(found.values(), key=lambda item: str(item).casefold())
                    dirnames[:] = []
                    continue
                if depth >= max_depth:
                    dirnames[:] = []
        except OSError:
            continue
    return sorted(found.values(), key=lambda item: str(item).casefold())


def _has_git(directory: str) -> bool:
    try:
        return (Path(directory) / ".git").exists()
    except OSError:
        return False


def add_watch_paths(settings: Settings, projects: Iterable[Path]) -> list[Path]:
    """Merge ``projects`` into ``settings.watch_paths`` and return what was added."""
    existing = {str(Path(item).expanduser().resolve()).casefold() for item in settings.watch_paths}
    added: list[Path] = []
    for project in projects:
        resolved = project.expanduser().resolve()
        key = str(resolved).casefold()
        if key not in existing:
            added.append(resolved)
            existing.add(key)
    settings.watch_paths = sorted(
        {*settings.watch_paths, *(str(project) for project in added)},
        key=lambda item: str(item).casefold(),
    )
    return added
