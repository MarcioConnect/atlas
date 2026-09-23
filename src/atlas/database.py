from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path

from sqlalchemy import create_engine, desc, inspect, select, text, update
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.orm import selectinload

from atlas.config import DB_PATH
from atlas.models import (
    Base,
    CodeFinding,
    CodeScan,
    Event,
    Finding,
    MonitorEvent,
    OperationSession,
    Scan,
    utcnow,
)


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{self.path}", future=True, connect_args={"timeout": 30})
        Base.metadata.create_all(self.engine)
        self._migrate_code_findings()
        self._migrate_code_scans()

    def _migrate_code_scans(self) -> None:
        """Add scan coverage counters without replacing user history."""
        columns = {item["name"] for item in inspect(self.engine).get_columns("code_scans")}
        if "files_skipped_large" not in columns:
            with self.engine.begin() as connection:
                connection.execute(text(
                    "ALTER TABLE code_scans ADD COLUMN files_skipped_large INTEGER NOT NULL DEFAULT 0"
                ))

    def _migrate_code_findings(self) -> None:
        """Additive SQLite migration for databases created by earlier releases."""
        columns = {item["name"] for item in inspect(self.engine).get_columns("code_findings")}
        migrations = {
            "category": "ALTER TABLE code_findings ADD COLUMN category VARCHAR(40) NOT NULL DEFAULT 'code'",
            "confidence": "ALTER TABLE code_findings ADD COLUMN confidence INTEGER NOT NULL DEFAULT 70",
            "suppressed": "ALTER TABLE code_findings ADD COLUMN suppressed BOOLEAN NOT NULL DEFAULT 0",
            "suppression_reason": "ALTER TABLE code_findings ADD COLUMN suppression_reason TEXT NOT NULL DEFAULT ''",
        }
        with self.engine.begin() as connection:
            for column, statement in migrations.items():
                if column not in columns:
                    connection.execute(text(statement))

    def session(self) -> DBSession:
        return DBSession(self.engine, expire_on_commit=False)

    def latest_scan(self) -> Scan | None:
        with self.session() as db:
            return db.scalars(
                select(Scan).options(selectinload(Scan.findings)).order_by(desc(Scan.id)).limit(1)
            ).first()

    def save_scan(self, scan: Scan) -> Scan:
        with self.session() as db:
            db.add(scan)
            db.commit()
            return scan

    def sessions(self, limit: int = 20) -> list[OperationSession]:
        with self.session() as db:
            return list(db.scalars(select(OperationSession).order_by(desc(OperationSession.started_at)).limit(limit)))

    def active_session(self) -> OperationSession | None:
        with self.session() as db:
            return db.scalars(
                select(OperationSession).where(OperationSession.status == "active").order_by(desc(OperationSession.started_at))
            ).first()

    def session_detail(self, session_id: str) -> OperationSession | None:
        with self.session() as db:
            return db.scalars(
                select(OperationSession)
                .options(selectinload(OperationSession.events))
                .where(OperationSession.id == session_id)
            ).first()

    def recent_events(self, limit: int = 30) -> list[Event]:
        with self.session() as db:
            return list(db.scalars(select(Event).order_by(desc(Event.created_at)).limit(limit)))

    def latest_findings(self) -> Iterable[Finding]:
        scan = self.latest_scan()
        return scan.findings if scan else []

    def add_monitor_event(self, event: MonitorEvent) -> MonitorEvent:
        with self.session() as db:
            db.add(event)
            db.commit()
            return event

    def recent_monitor_events(self, limit: int = 100) -> list[MonitorEvent]:
        with self.session() as db:
            return list(db.scalars(select(MonitorEvent).order_by(desc(MonitorEvent.created_at)).limit(limit)))

    def begin_code_scan(self, project_path: str, trigger_file: str | None = None) -> CodeScan:
        with self.session() as db:
            # Recover scans abandoned by a killed terminal/process so the UI never
            # remains permanently in SCANNING.
            cutoff = utcnow() - timedelta(minutes=15)
            db.execute(
                update(CodeScan)
                .where(
                    CodeScan.project_path == project_path,
                    CodeScan.status == "SCANNING",
                    CodeScan.started_at < cutoff,
                )
                .values(status="ERROR", completed_at=utcnow(), scanners="[]")
            )
            scan = CodeScan(project_path=project_path, trigger_file=trigger_file, status="SCANNING")
            db.add(scan)
            db.commit()
            return scan

    def finish_code_scan(
        self, scan_id: int, *, files_analyzed: int, changes: int, status: str, scanners: str,
        files_skipped_large: int = 0,
    ) -> CodeScan | None:
        with self.session() as db:
            scan = db.get(CodeScan, scan_id)
            if scan is None:
                return None
            scan.completed_at = utcnow()
            scan.files_analyzed = files_analyzed
            scan.files_skipped_large = max(0, files_skipped_large)
            scan.changes = changes
            scan.status = status
            scan.scanners = scanners
            db.commit()
            return scan

    def latest_code_scan(self, project_path: str) -> CodeScan | None:
        with self.session() as db:
            return db.scalars(
                select(CodeScan).where(CodeScan.project_path == project_path).order_by(desc(CodeScan.id)).limit(1)
            ).first()

    def has_completed_code_scan(self, project_path: str) -> bool:
        """Return whether the project already has a successful scan to anchor its baseline."""
        with self.session() as db:
            return db.scalars(
                select(CodeScan.id)
                .where(
                    CodeScan.project_path == project_path,
                    CodeScan.completed_at.is_not(None),
                    CodeScan.status.in_(("SAFE", "FINDINGS", "STOPPED")),
                )
                .limit(1)
            ).first() is not None

    def accept_code_baseline(self, project_path: str) -> None:
        """Treat the first measured state as known without hiding future regressions."""
        with self.session() as db:
            db.execute(
                update(CodeFinding)
                .where(CodeFinding.project_path == project_path, CodeFinding.state == "NEW")
                .values(state="EXISTING")
            )
            db.commit()

    def code_projects(self) -> list[str]:
        """Return every project that has produced at least one Watchdog scan."""
        with self.session() as db:
            return list(db.scalars(select(CodeScan.project_path).distinct().order_by(CodeScan.project_path)))

    def code_findings(self, project_path: str, state: str | None = None, limit: int = 1000) -> list[CodeFinding]:
        with self.session() as db:
            query = select(CodeFinding).where(CodeFinding.project_path == project_path)
            if state:
                query = query.where(CodeFinding.state == state)
            return list(db.scalars(query.order_by(desc(CodeFinding.last_seen)).limit(limit)))

    def reconcile_code_findings(
        self,
        project_path: str,
        scan_id: int,
        findings: list[dict],
        coverage: dict[str, set[str] | None],
    ) -> dict[str, list[CodeFinding]]:
        """Reconcile one scan without resolving findings outside its measured scope.

        ``coverage[scanner]`` is ``None`` for a full-project scanner, otherwise it
        contains normalized absolute paths actually inspected by that scanner.
        """
        now = utcnow()
        result: dict[str, list[CodeFinding]] = {"NEW": [], "EXISTING": [], "RESOLVED": [], "SUPPRESSED": []}
        with self.session() as db:
            db.execute(
                update(CodeFinding)
                .where(CodeFinding.project_path == project_path, CodeFinding.state == "NEW")
                .values(state="EXISTING")
            )
            existing = {
                item.fingerprint: item
                for item in db.scalars(select(CodeFinding).where(CodeFinding.project_path == project_path))
            }
            seen: set[str] = set()
            for data in findings:
                fingerprint = str(data["fingerprint"])
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                item = existing.get(fingerprint)
                if item is None:
                    state = "SUPPRESSED" if data.get("suppressed") else "NEW"
                    item = CodeFinding(project_path=project_path, state=state, first_seen=now, **data)
                    db.add(item)
                    result[state].append(item)
                else:
                    reappeared = item.state == "RESOLVED"
                    for key, value in data.items():
                        setattr(item, key, value)
                    item.state = "SUPPRESSED" if item.suppressed else ("NEW" if reappeared else "EXISTING")
                    item.resolved_at = None
                    if reappeared:
                        item.first_seen = now
                    result[item.state].append(item)
                item.last_seen = now
                item.last_scan_id = scan_id

            for item in existing.values():
                if item.fingerprint in seen or item.state == "RESOLVED":
                    continue
                scanner_scope = coverage.get(item.scanner)
                covered = item.scanner in coverage and (
                    scanner_scope is None or str(Path(item.file_path).resolve()).casefold() in scanner_scope
                )
                if covered:
                    item.state = "RESOLVED"
                    item.resolved_at = now
                    item.last_scan_id = scan_id
                    result["RESOLVED"].append(item)
            db.commit()
            for values in result.values():
                for item in values:
                    db.refresh(item)
        return result
