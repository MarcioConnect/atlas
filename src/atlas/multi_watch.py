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
        for watcher in self.watchdogs.values():
            watcher.start(initial_scan=initial_scan)

    def stop(self) -> None:
        for watcher in self.watchdogs.values():
            watcher.stop()

    def scan_now(self) -> None:
        for watcher in self.watchdogs.values():
            watcher.scan_now(None)


def configured_projects() -> list[Path]:
    """Read configured roots and keep only existing directories."""
    return [Path(item).expanduser().resolve() for item in Settings.load().watch_paths if Path(item).expanduser().is_dir()]
