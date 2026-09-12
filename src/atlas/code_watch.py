from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from atlas.code_scanners import (
    IGNORED_DIRS,
    CodeScanResult,
    LocalCodeScanners,
    ScannerAvailability,
    discover_files,
    is_ignored,
    is_priority_file,
)
from atlas.config import Settings
from atlas.database import Database
from atlas.models import CodeFinding, MonitorEvent, Severity
from atlas.notifications import notify_new_findings
from atlas.security import redact


@dataclass(slots=True)
class WatchState:
    project: Path
    status: str = "STARTING"
    files_analyzed: int = 0
    changes: int = 0
    last_scan_at: datetime | None = None
    new: list[CodeFinding] = field(default_factory=list)
    existing: list[CodeFinding] = field(default_factory=list)
    resolved: list[CodeFinding] = field(default_factory=list)
    availability: list[ScannerAvailability] = field(default_factory=list)
    error: str = ""


class ProjectEventHandler(FileSystemEventHandler):
    def __init__(self, project: Path, callback: Callable[[Path, str], None]) -> None:
        self.project = project
        self.callback = callback

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory or event.event_type not in {"created", "modified", "moved", "deleted"}:
            return
        value = str(getattr(event, "dest_path", "") or event.src_path)
        path = Path(value)
        if is_ignored(path, self.project):
            return
        self.callback(path, str(event.event_type))


class CodeWatchdog:
    """Debounced, token-free source security watcher."""

    def __init__(
        self,
        project: Path,
        database: Database | None = None,
        debounce_seconds: float | None = None,
        on_update: Callable[[WatchState], None] | None = None,
        scanner_factory: Callable[[Path], LocalCodeScanners] = LocalCodeScanners,
    ) -> None:
        self.project = project.expanduser().resolve()
        self.database = database or Database()
        self.debounce_seconds = debounce_seconds if debounce_seconds is not None else Settings.load().watchdog_debounce_seconds
        self.on_update = on_update
        self.scanner_factory = scanner_factory
        self.state = WatchState(project=self.project)
        self._observer: Observer | None = None
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._pending: dict[str, Path] = {}
        self._pending_at = 0.0
        self._lock = threading.RLock()
        self._scan_lock = threading.Lock()
        self._snapshots: dict[str, list[str]] = {}

    def _notify(self) -> None:
        if self.on_update:
            self.on_update(self.state)

    def start(self, initial_scan: bool = True) -> None:
        if self._observer and self._observer.is_alive():
            return
        if not self.project.exists() or not self.project.is_dir():
            raise ValueError(f"Project directory does not exist: {self.project}")
        self._stop.clear()
        self.state.status = "WATCHING"
        handler = ProjectEventHandler(self.project, self.queue)
        self._observer = Observer()
        self._observer.schedule(handler, str(self.project), recursive=True)
        self._observer.start()
        self._worker = threading.Thread(target=self._loop, name="atlas-code-watchdog", daemon=True)
        self._worker.start()
        self._notify()
        if initial_scan:
            threading.Thread(target=self.scan_now, args=(None,), name="atlas-initial-scan", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        observer = self._observer
        if observer:
            observer.stop()
            observer.join(timeout=5)
        worker = self._worker
        if worker and worker is not threading.current_thread():
            worker.join(timeout=5)
        self.state.status = "STOPPED"
        self._notify()

    def queue(self, path: Path, event_type: str = "modified") -> None:
        key = str(path).casefold()
        with self._lock:
            first_pending_event = key not in self._pending
            self._pending[key] = path
            self._pending_at = time.monotonic()
            self.state.changes += 1
        if first_pending_event:
            self._record_file_event(path, event_type)
        self._wake.set()

    def _record_file_event(self, path: Path, event_type: str) -> None:
        """Persist metadata for every observed file without reading its content."""
        name = path.name.casefold()
        sensitive = name == ".env" or any(word in name for word in ("secret", "token", "password", "credential"))
        component = str(path.parent / "[SENSITIVE_FILE]") if sensitive else str(path)
        severity = Severity.MEDIUM if is_priority_file(path) else Severity.INFO
        if sensitive:
            severity = Severity.HIGH
        detail = event_type if event_type in {"created", "modified", "moved", "deleted"} else "changed"
        fingerprint = hashlib.sha256(
            f"file|{self.project}|{component}|{detail}".encode("utf-8", "replace")
        ).hexdigest()
        try:
            self.database.add_monitor_event(MonitorEvent(
                kind="file",
                severity=severity.value,
                component=redact(component)[:255],
                detail=detail,
                risk="Arquivo sensivel alterado; conteudo nao lido." if sensitive else "Mudanca de arquivo observada.",
                fingerprint=fingerprint,
            ))
        except Exception:
            # Monitoring must continue even if persistence is temporarily busy.
            return

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=0.25)
            self._wake.clear()
            while not self._stop.is_set():
                with self._lock:
                    remaining = self.debounce_seconds - (time.monotonic() - self._pending_at)
                if remaining <= 0:
                    break
                self._stop.wait(min(remaining, 0.25))
            if self._stop.is_set():
                return
            with self._lock:
                changed = list(self._pending.values())
                self._pending.clear()
            if changed:
                # A deletion requires a full pass so findings belonging to the
                # removed file can be resolved with trustworthy coverage.
                self.scan_now(None if any(not path.exists() for path in changed) else changed)

    def scan_now(self, changed: list[Path] | None = None) -> dict[str, list[CodeFinding]]:
        if not self._scan_lock.acquire(blocking=False):
            for path in changed or []:
                self.queue(path)
            return {"NEW": [], "EXISTING": [], "RESOLVED": []}
        trigger = str(changed[0]) if changed else None
        scan = self.database.begin_code_scan(str(self.project), trigger)
        self.state.status = "SCANNING"
        self.state.error = ""
        self._notify()
        try:
            changed_lines = self._changed_line_map(changed)
            scanner = self.scanner_factory(self.project)
            try:
                local_result: CodeScanResult = scanner.scan(changed, changed_lines=changed_lines)
            except TypeError:
                # Keep compatibility with custom scanner factories using the v0.1 API.
                local_result = scanner.scan(changed)
            if changed is None:
                self._seed_snapshots()
            reconciled = self.database.reconcile_code_findings(
                str(self.project), scan.id, [item.record() for item in local_result.findings], local_result.coverage
            )
            self.state.new = reconciled["NEW"]
            self.state.existing = self.database.code_findings(str(self.project), "EXISTING")
            self.state.resolved = reconciled["RESOLVED"]
            settings = Settings.load()
            actively_watching = bool(self._observer and self._observer.is_alive())
            if self.state.new and actively_watching and settings.notifications_enabled and not settings.silent_mode:
                notify_new_findings(self.project, self.state.new)
            self.state.files_analyzed = local_result.files_analyzed
            self.state.availability = local_result.availability
            self.state.last_scan_at = datetime.now(UTC)
            current = self.database.code_findings(str(self.project))
            actionable = [item for item in current if item.state != "RESOLVED"]
            self.state.status = "FINDINGS" if actionable else "SAFE"
            scanner_json = json.dumps(
                [{"name": item.name, "available": item.available, "install": item.install} for item in local_result.availability],
                ensure_ascii=True,
            )
            self.database.finish_code_scan(
                scan.id, files_analyzed=local_result.files_analyzed, changes=self.state.changes,
                status=self.state.status, scanners=scanner_json,
            )
            return reconciled
        except Exception as exc:
            self.state.status = "ERROR"
            self.state.error = type(exc).__name__
            self.database.finish_code_scan(
                scan.id, files_analyzed=0, changes=self.state.changes, status="ERROR", scanners="[]"
            )
            return {"NEW": [], "EXISTING": [], "RESOLVED": []}
        finally:
            self._scan_lock.release()
            self._notify()

    def _changed_line_map(self, changed: list[Path] | None) -> dict[str, set[int]] | None:
        """Return changed line numbers using an in-memory previous snapshot.

        The first scan of a file intentionally covers every line; subsequent
        events inspect only added/modified lines for the native scanner.
        """
        if not changed:
            return None
        result: dict[str, set[int]] = {}
        for path in changed:
            key = str(path.resolve()).casefold()
            try:
                current = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._snapshots.pop(key, None)
                continue
            previous = self._snapshots.get(key)
            if previous is None:
                lines = set(range(1, len(current) + 1))
            else:
                lines = {index + 1 for index, value in enumerate(current)
                         if index >= len(previous) or previous[index] != value}
                if len(current) < len(previous):
                    lines.update(range(len(current) + 1, len(previous) + 1))
            self._snapshots[key] = current
            result[key] = lines
        return result

    def _seed_snapshots(self) -> None:
        """Capture the full-scan baseline used by later incremental passes."""
        for path in discover_files(self.project):
            try:
                self._snapshots[str(path.resolve()).casefold()] = path.read_text(
                    encoding="utf-8", errors="replace",
                ).splitlines()
            except OSError:
                continue


def ignored_directory_names() -> set[str]:
    return set(IGNORED_DIRS)
