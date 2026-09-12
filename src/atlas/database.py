from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import create_engine, desc, select, update
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
            scan = CodeScan(project_path=project_path, trigger_file=trigger_file, status="SCANNING")
            db.add(scan)
            db.commit()
            return scan

    def finish_code_scan(
        self, scan_id: int, *, files_analyzed: int, changes: int, status: str, scanners: str
    ) -> CodeScan | None:
        with self.session() as db:
            scan = db.get(CodeScan, scan_id)
            if scan is None:
                return None
            scan.completed_at = utcnow()
            scan.files_analyzed = files_analyzed
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
        result: dict[str, list[CodeFinding]] = {"NEW": [], "EXISTING": [], "RESOLVED": []}
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
                    item = CodeFinding(project_path=project_path, state="NEW", first_seen=now, **data)
                    db.add(item)
                    result["NEW"].append(item)
                else:
                    reappeared = item.state == "RESOLVED"
                    for key, value in data.items():
                        setattr(item, key, value)
                    item.state = "NEW" if reappeared else "EXISTING"
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
