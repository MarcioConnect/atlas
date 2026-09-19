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
from atlas.security import redact, score_breakdown


def downloads_dir() -> Path:
    """Return the conventional Windows Downloads directory."""
    user_profile = os.environ.get("USERPROFILE")
    base = Path(user_profile) if user_profile else Path.home()
    return base / "Downloads"


def _safe(value: object) -> str:
    return redact(str(value))


def _date(value: datetime | None) -> str:
    return value.astimezone().strftime("%d/%m/%Y %H:%M:%S") if value else "-"


def _summary(database: Database, project_path: Path | None = None) -> dict[str, int]:
    """Return stable counters shared by Markdown and HTML reports."""
    system_scan = database.latest_scan()
    findings = list(system_scan.findings if system_scan else [])
    projects = [project_path.resolve()] if project_path else _known_projects(database)
    for project in projects:
        latest = database.latest_code_scan(str(project))
        if latest:
            findings.extend(database.code_findings(str(project)))
    breakdown = score_breakdown(system_scan.findings) if system_scan else {
        "credentials": 100, "network": 100, "containers": 100, "host": 100, "code": 100, "overall": -1,
    }
    result = {"total": len(findings), "critical": 0, "high": 0, "medium": 0,
              "low": 0, "info": 0, "new": 0, "existing": 0, "resolved": 0,
              "score": int(system_scan.score) if system_scan else -1, **breakdown}
    for finding in findings:
        severity = str(getattr(finding, "severity", "INFO")).casefold()
        state = str(getattr(finding, "state", "")).casefold()
        if severity in result:
            result[severity] += 1
        if state in {"new", "existing", "resolved"}:
            result[state] += 1
    return result


def _summary_markdown(summary: dict[str, int]) -> list[str]:
    score = f"{summary['score']}/100" if summary["score"] >= 0 else "indisponível"
    return [
        "## Resumo executivo", "",
        f"- **Security Score:** `{score}`",
        f"- **Findings totais:** `{summary['total']}` (novos: `{summary['new']}`, existentes: `{summary['existing']}`, resolvidos: `{summary['resolved']}`)",
        f"- **Severidades:** CRITICAL `{summary['critical']}` · HIGH `{summary['high']}` · MEDIUM `{summary['medium']}` · LOW `{summary['low']}` · INFO `{summary['info']}`",
        f"- **Score por domínio:** credenciais {summary['credentials']} · rede {summary['network']} · containers {summary['containers']} · host {summary['host']} · código {summary['code']}",
        "- **Interpretação:** o score considera causas únicas por domínio e limita repetições; findings são sinais para revisão, não prova automática de comprometimento.", "",
    ]


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
    lines.extend(_summary_markdown(_summary(database, project_path)))
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
            lines.append("### Cobertura dos scanners")
            for item in scanners:
                if isinstance(item, dict):
                    state = "disponível" if item.get("available") else "indisponível"
                    line = f"- {_safe(item.get('name', 'scanner'))}: **{state}**"
                    if not item.get("available") and item.get("install"):
                        line += f" · Instalação: {_safe(item['install'])}"
                    lines.append(line)
                else:
                    lines.append(f"- {_safe(item)}")
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
    lines.extend(_summary_markdown(_summary(database)))
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


def _html_dashboard(report: str, summary: dict[str, int], generated: datetime) -> str:
    """Build a standalone responsive report with an executive dashboard."""
    score = f"{summary['score']}/100" if summary["score"] >= 0 else "N/D"
    cards = "".join([
        f'<div class="card score"><span>⚕ ATLAS · Security Score</span><strong>{escape(score)}</strong></div>',
        f'<div class="card"><span>Findings</span><strong>{summary["total"]}</strong></div>',
        f'<div class="card high"><span>High / Critical</span><strong>{summary["high"] + summary["critical"]}</strong></div>',
        f'<div class="card"><span>New / Resolved</span><strong>{summary["new"]} / {summary["resolved"]}</strong></div>',
    ])
    rows = "".join(
        f'<tr><th>{label}</th><td>{summary[key]}</td><td><div class="bar"><i class="{key}" style="width:{min(100, summary[key] * 10)}%"></i></div></td></tr>'
        for key, label in (("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW"), ("info", "INFO"))
    )
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ATLAS Security Report</title><style>
:root {{ color-scheme: dark; }} * {{ box-sizing:border-box; }} body {{ margin:0; background:#050b12; color:#dce8f2; font:14px/1.55 Consolas,ui-monospace,monospace; }} main {{ max-width:1200px; margin:24px auto; padding:24px; border:1px solid #294d69; background:#08121c; }} .header {{ display:flex; justify-content:space-between; border-bottom:1px solid #294d69; padding-bottom:16px; }} .mark,h1,h2 {{ color:#70c7ff; }} .mark {{ font-size:18px; }} .meta {{ color:#8aa3b8; text-align:right; }} h1 {{ letter-spacing:.16em; font-size:25px; }} h2 {{ font-size:16px; }} .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }} .card {{ border:1px solid #294d69; padding:14px; background:#0b1925; }} .card span {{ display:block; color:#8aa3b8; font-size:12px; }} .card strong {{ display:block; font-size:24px; margin-top:4px; }} .card.score strong {{ color:#70c7ff; }} .card.high strong {{ color:#ff9370; }} section {{ border-top:1px solid #294d69; margin-top:22px; padding-top:12px; }} table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:8px; text-align:left; border-bottom:1px solid #1b3448; }} th {{ color:#9fc5df; }} .bar {{ height:8px; background:#122331; max-width:300px; }} .bar i {{ display:block; height:100%; }} .critical {{ background:#ff4d5e; }} .high {{ background:#ff8a55; }} .medium {{ background:#e4bd48; }} .low {{ background:#52a9ed; }} .info {{ background:#9aa9b8; }} details {{ margin-top:18px; }} summary {{ cursor:pointer; color:#8fc7ed; padding:10px 0; }} pre {{ white-space:pre-wrap; word-break:break-word; background:#050b12; border:1px solid #1b3448; padding:18px; overflow:auto; }} footer {{ color:#8aa3b8; margin-top:22px; font-size:12px; }} @media(max-width:760px) {{ main {{ margin:0; border:0; }} .cards {{ grid-template-columns:repeat(2,1fr); }} .header {{ display:block; }} .meta {{ text-align:left; margin-top:8px; }}}} @media print {{ body,main {{ background:#fff; color:#111; }} main {{ border:0; }} pre {{ color:#111; background:#fff; }}}}
</style></head><body><main><header class="header"><div class="mark">ATLAS / SECURITY REPORT</div><div class="meta">Gerado em {escape(_date(generated))}<br>Modo local · read-only</div></header><h1>VISÃO GERAL</h1><div class="cards">{cards}</div><section><h2>FINDINGS POR SEVERIDADE</h2><table><thead><tr><th>Severidade</th><th>Total</th><th>Distribuição</th></tr></thead><tbody>{rows}</tbody></table></section><details open><summary>Relatório detalhado (Markdown)</summary><pre>{escape(report)}</pre></details><footer>Gerado localmente pelo ATLAS. A ausência de findings não garante ausência de vulnerabilidades.</footer></main></body></html>"""


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
    document = _html_dashboard(plain_report, _summary(database, project_path), generated)
    path.write_text(document, encoding="utf-8")
    return path
