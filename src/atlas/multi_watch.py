"""Multi-project orchestration for the local source Watchdog."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from atlas.code_scanners import LocalCodeScanners
from atlas.code_watch import CodeWatchdog, WatchState
from atlas.config import Settings
from atlas.database import Database


class MultiProjectWatchdog:
    """Run one debounced code watchdog for every configured project."""

    def __init__(
        self,
        projects: list[Path],
        database: Database | None = None,
        on_update: Callable[[Path, WatchState], None] | None = None,
        scanner_factory=LocalCodeScanners,
        ai_enabled: bool = False,
        ai_model: str | None = None,
    ) -> None:
        unique: dict[str, Path] = {}
        for project in projects:
            resolved = project.expanduser().resolve()
            if resolved.is_dir():
                unique[str(resolved).casefold()] = resolved
        self.projects = list(unique.values())
        self.database = database or Database()
        self.on_update = on_update
        self.watchdogs = {
            project: CodeWatchdog(
                project,
                self.database,
                on_update=lambda state, path=project: self._updated(path, state),
                scanner_factory=scanner_factory,
                ai_enabled=ai_enabled,
                ai_model=ai_model,
            )
            for project in self.projects
        }

    def _updated(self, project: Path, state: WatchState) -> None:
        if self.on_update:
            self.on_update(project, state)

    @property
    def states(self) -> dict[Path, WatchState]:
        return {path: watcher.state for path, watcher in self.watchdogs.items()}

    def start(self, initial_scan: bool = True) -> None:
        started: list[CodeWatchdog] = []
        try:
            for watcher in self.watchdogs.values():
                watcher.start(initial_scan=initial_scan)
                started.append(watcher)
        except Exception:
            for watcher in reversed(started):
                watcher.stop()
            raise

    def stop(self) -> None:
        for watcher in self.watchdogs.values():
            watcher.stop()

    def scan_now(self) -> None:
        for watcher in self.watchdogs.values():
            watcher.scan_now(None)


PROJECT_MARKERS = {
    ".git", "pyproject.toml", "package.json", "requirements.txt", "Cargo.toml",
    "go.mod", "pom.xml", "composer.json", "Dockerfile", "src",
}
PROFILE_BUCKETS = {"desktop", "documents", "downloads", "onedrive", "appdata", "ideaprojects"}


def _project_like(path: Path) -> bool:
    try:
        return any((path / marker).exists() for marker in PROJECT_MARKERS)
    except OSError:
        return False


def discover_user_projects(base: Path | None = None) -> list[Path]:
    """Discover only shallow project roots, never sweep the whole user profile."""
    root = (base or Path.home()).expanduser().resolve()
    found: dict[str, Path] = {}
    try:
        children = [item for item in root.iterdir() if item.is_dir() and not item.name.startswith(".")]
    except OSError:
        return []
    for child in children[:200]:
        if _project_like(child):
            found[str(child.resolve()).casefold()] = child.resolve()
        if child.name.casefold() in PROFILE_BUCKETS:
            try:
                nested = [item for item in child.iterdir() if item.is_dir() and not item.name.startswith(".")]
            except OSError:
                continue
            for item in nested[:200]:
                if _project_like(item):
                    found[str(item.resolve()).casefold()] = item.resolve()
    return sorted(found.values(), key=lambda item: str(item).casefold())


def configured_projects() -> list[Path]:
    """Return explicit project roots while pruning profile buckets and overlap."""
    candidates: dict[str, Path] = {}
    for item in Settings.load().watch_paths:
        path = Path(item).expanduser()
        if path.is_dir():
            resolved = path.resolve()
            candidates[str(resolved).casefold()] = resolved
    home = Path.home().resolve()
    broad_roots = [
        path for path in candidates.values()
        if path == home or (path.parent == home and path.name.casefold() in PROFILE_BUCKETS)
    ]
    for root in broad_roots:
        for discovered in discover_user_projects(root):
            candidates.setdefault(str(discovered).casefold(), discovered)
    if not candidates:
        for discovered in discover_user_projects(home):
            candidates[str(discovered).casefold()] = discovered
    values = list(candidates.values())
    selected: list[Path] = []
    for path in values:
        broad_profile = path == home or (path.parent == home and path.name.casefold() in PROFILE_BUCKETS)
        contains_configured_child = any(path != other and path in other.parents for other in values)
        if broad_profile or (contains_configured_child and not _project_like(path)):
            continue
        selected.append(path)
    return sorted(selected, key=lambda item: str(item).casefold())
