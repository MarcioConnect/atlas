"""Local Markdown report generation for the ATLAS launcher."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Iterable
from datetime import datetime
from html import escape
from pathlib import Path

from atlas.config import Settings
from atlas.database import Database
from atlas.security import redact


def downloads_dir() -> Path:
    """Return the conventional Windows Downloads directory."""
    user_profile = os.environ.get("USERPROFILE")
    base = Path(user_profile) if user_profile else Path.home()
    return base / "Downloads"


def _safe(value: object) -> str:
    return redact(str(value))


def _date(value: datetime | None) -> str:
    return value.astimezone().strftime("%d/%m/%Y %H:%M:%S") if value else "-"


def _section_findings(title: str, findings: Iterable[object]) -> list[str]:
    findings = list(findings)
    lines = [f"## {title}", ""]
    if not findings:
        lines.append("Nenhum finding registrado.")
        lines.append("")
        return lines
    for item in findings:
        severity = _safe(getattr(item, "severity", "INFO"))
        scanner = _safe(getattr(item, "scanner", "ATLAS Security Scanner"))
        rule = _safe(getattr(item, "rule_id", getattr(item, "check_id", "unknown")))
        file_path = _safe(getattr(item, "file_path", getattr(item, "component", "-")))
        line = getattr(item, "line", None)
        location = f"{file_path}:{line}" if line else file_path
        description = _safe(getattr(item, "description", getattr(item, "title", "Finding")))
        evidence = _safe(getattr(item, "evidence", "-"))
        risk = _safe(getattr(item, "risk", "-"))
        recommendation = _safe(getattr(item, "recommendation", "-"))
        state = getattr(item, "state", None)
        state_label = f" · {_safe(state)}" if state else ""
        lines.extend([
            f"### {severity}{state_label} — {description}",
            f"- Scanner: `{scanner}`",
            f"- Regra: `{rule}`",
            f"- Arquivo/componente: `{location}`",
            f"- Evidência: `{evidence}`",
            f"- Risco: {risk}",
            f"- Recomendação: {recommendation}",
            "",
        ])
    return lines


def _section_changes(database: Database, project: Path, limit: int = 500) -> list[str]:
    """Render sanitized file activity belonging to one project."""
    prefix = str(project.resolve()).casefold().rstrip("\\/")
    events = [
        event for event in database.recent_monitor_events(limit=2000)
        if event.kind == "file" and str(event.component).casefold().startswith(prefix)
    ][:limit]
    lines = ["## Alteracoes observadas", ""]
    if not events:
        return lines + ["Nenhuma alteracao de arquivo registrada para este projeto.", ""]
    counts: dict[str, int] = {}
    for event in events:
        counts[event.detail] = counts.get(event.detail, 0) + 1
    lines.extend(["Resumo: " + ", ".join(f"{kind}={amount}" for kind, amount in sorted(counts.items())), ""])
    for event in events:
        try:
            relative = Path(event.component).resolve().relative_to(project.resolve())
        except (OSError, ValueError):
            relative = Path(event.component)
        lines.append(
            f"- `{_date(event.created_at)}` [{_safe(event.detail).upper()}] "
            f"`{_safe(relative)}` ({_safe(event.severity)})"
        )
    lines.append("")
    return lines


def _known_projects(database: Database) -> list[Path]:
    candidates = [*Settings.load().watch_paths, *database.code_projects()]
    unique: dict[str, Path] = {}
    for value in candidates:
        path = Path(value).expanduser().resolve()
        unique[str(path).casefold()] = path
    return list(unique.values())


def render_report(database: Database, project_path: Path | None = None, now: datetime | None = None) -> str:
    generated = now or datetime.now().astimezone()
    scan = database.latest_scan()
    project = project_path.resolve() if project_path else Path.cwd().resolve()
    code_scan = database.latest_code_scan(str(project))
    code_findings = database.code_findings(str(project)) if code_scan else []
    lines = [
        "# ATLAS Security Report",
        "",
        f"- Gerado em: `{generated.astimezone().strftime('%d/%m/%Y %H:%M:%S')}` (horário local pt-BR)",
        f"- Hostname: `{_safe(socket.gethostname())}`",
        f"- Projeto monitorado: `{_safe(project)}`",
        "- Modo: `read-only / local`",
        "",
        "## Security Score",
        "",
        f"**{scan.score}/100**" if scan else "Nenhum scan de sistema disponível.",
        "",
    ]
    lines.extend(_section_findings("Findings do sistema", scan.findings if scan else []))
    if code_scan:
        lines.extend([
            "## Watchdog",
            "",
            f"- Último scan: `{_date(code_scan.completed_at)}`",
            f"- Arquivos analisados: `{code_scan.files_analyzed}`",
            f"- Alterações: `{code_scan.changes}`",
            f"- Status: `{_safe(code_scan.status)}`",
            "",
        ])
        try:
            scanners = json.loads(code_scan.scanners or "{}")
        except (TypeError, ValueError):
            scanners = {}
        if isinstance(scanners, dict) and scanners:
            lines.append("### Scanners")
            lines.extend(f"- `{_safe(name)}`: {_safe(status)}" for name, status in scanners.items())
            lines.append("")
        elif isinstance(scanners, list) and scanners:
            lines.append("### Scanners")
            lines.extend(f"- `{_safe(item)}`" for item in scanners)
            lines.append("")
        for state in ("NEW", "EXISTING", "RESOLVED"):
            lines.extend(_section_findings(f"Watchdog — {state}", [item for item in code_findings if item.state == state]))
    else:
        lines.extend(["## Watchdog", "", "Nenhum scan do Watchdog registrado para este projeto.", ""])
    lines.extend(_section_changes(database, project))
    lines.extend(["---", "", "Relatório gerado localmente pelo ATLAS. A ausência de findings não garante ausência de vulnerabilidades.", ""])
    return "\n".join(lines)


def render_consolidated_report(database: Database, now: datetime | None = None) -> str:
    """Render every configured or previously scanned project in one document."""
    generated = now or datetime.now().astimezone()
    projects = _known_projects(database) or [Path.cwd().resolve()]
    lines = [
        "# ATLAS Consolidated Security Report",
        "",
        f"- Gerado em: `{generated.astimezone().strftime('%d/%m/%Y %H:%M:%S')}` (horario local pt-BR)",
        f"- Hostname: `{_safe(socket.gethostname())}`",
        f"- Projetos: `{len(projects)}`",
        "- Modo: `read-only / local`",
        "",
    ]
    system_scan = database.latest_scan()
    lines.extend([
        "## Security Score da maquina",
        "",
        f"**{system_scan.score}/100**" if system_scan else "Nenhum scan de sistema disponível.",
        "",
    ])
    lines.extend(_section_findings("Findings do sistema", system_scan.findings if system_scan else []))
    for index, project in enumerate(projects, 1):
        lines.extend([f"# Projeto {index}: `{_safe(project)}`", ""])
        project_lines = render_report(database, project, generated).splitlines()
        try:
            project_start = project_lines.index("## Watchdog")
        except ValueError:
            project_start = 0
        try:
            project_end = project_lines.index("---", project_start)
        except ValueError:
            project_end = len(project_lines)
        lines.extend(project_lines[project_start:project_end])
        lines.append("")
    lines.extend([
        "---", "",
        "Relatorio gerado localmente pelo ATLAS. A ausencia de findings nao garante ausencia de vulnerabilidades.",
        "",
    ])
    return "\n".join(lines)


def generate_markdown_report(
    database: Database,
    project_path: Path | None = None,
    output_dir: Path | None = None,
    now: datetime | None = None,
) -> Path:
    generated = now or datetime.now().astimezone()
    destination = output_dir or downloads_dir()
    destination.mkdir(parents=True, exist_ok=True)
    filename = f"atlas-report-{generated:%Y-%m-%d}.md"
    path = destination / filename
    if path.exists():
        path = destination / f"atlas-report-{generated:%Y-%m-%d-%H%M%S}.md"
    report = render_report(database, project_path, generated) if project_path else render_consolidated_report(database, generated)
    path.write_text(report, encoding="utf-8")
    return path


def generate_html_report(
    database: Database,
    project_path: Path | None = None,
    output_dir: Path | None = None,
    now: datetime | None = None,
) -> Path:
    """Write a standalone, sanitized dark-theme HTML report."""
    generated = now or datetime.now().astimezone()
    destination = output_dir or downloads_dir()
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / f"atlas-report-{generated:%Y-%m-%d}.html"
    if path.exists():
        path = destination / f"atlas-report-{generated:%Y-%m-%d-%H%M%S}.html"
    plain_report = render_report(database, project_path, generated) if project_path else render_consolidated_report(database, generated)
    report = escape(plain_report)
    document = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ATLAS Security Report</title><style>
:root {{ color-scheme: dark; }} body {{ margin: 0; background: #050b12; color: #dce8f2;
font: 15px/1.55 Consolas, monospace; }} main {{ max-width: 1100px; margin: 32px auto; padding: 24px;
border: 1px solid #294d69; background: #08121c; }} h1 {{ color: #8fc7ed; letter-spacing: .18em; }}
pre {{ white-space: pre-wrap; word-break: break-word; }} .mark {{ color: #6f9fc4; font-size: 28px; }}
</style></head><body><main><div class="mark">⚕ ATLAS</div><pre>{report}</pre></main></body></html>"""
    path.write_text(document, encoding="utf-8")
    return path
