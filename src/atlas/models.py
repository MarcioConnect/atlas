from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hostname: Mapped[str] = mapped_column(String(255))
    score: Mapped[int] = mapped_column(Integer)
    findings: Mapped[list[Finding]] = relationship(cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    check_id: Mapped[str] = mapped_column(String(100), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    evidence: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(Text)
    component: Mapped[str] = mapped_column(String(255))
    recommendation: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)


class OperationSession(Base):
    __tablename__ = "operation_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    shell: Mapped[str] = mapped_column(String(40))
    working_directory: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    events: Mapped[list[Event]] = relationship(cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("operation_sessions.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    component: Mapped[str] = mapped_column(String(255), default="system")
    detail: Mapped[str] = mapped_column(Text)
    result: Mapped[str] = mapped_column(String(30), default="observed")


class Snapshot(Base):
    __tablename__ = "snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("operation_sessions.id"), index=True)
    phase: Mapped[str] = mapped_column(String(10))
    category: Mapped[str] = mapped_column(String(30))
    identity: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)


class MonitorEvent(Base):
    __tablename__ = "monitor_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(10), default=Severity.INFO.value, index=True)
    component: Mapped[str] = mapped_column(String(255), default="system")
    detail: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(Text, default="")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)


class CodeScan(Base):
    """One incremental source-code scan performed by ``atlas watch``."""

    __tablename__ = "code_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_path: Mapped[str] = mapped_column(Text, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trigger_file: Mapped[str | None] = mapped_column(Text, nullable=True)
    files_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    changes: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="SCANNING", index=True)
    scanners: Mapped[str] = mapped_column(Text, default="")


class CodeFinding(Base):
    """Current lifecycle state for a normalized local-scanner finding."""

    __tablename__ = "code_findings"
    __table_args__ = (UniqueConstraint("project_path", "fingerprint", name="uq_code_finding_project_fp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_path: Mapped[str] = mapped_column(Text, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    scanner: Mapped[str] = mapped_column(String(40), index=True)
    rule_id: Mapped[str] = mapped_column(String(255), default="unknown")
    file_path: Mapped[str] = mapped_column(Text, index=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(10), default="NEW", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("code_scans.id"), nullable=True, index=True)
