from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from atlas import __version__
from atlas.config import Settings
from atlas.database import Database
from atlas.models import Severity
from atlas.security import SecurityScanner, score_breakdown
from atlas.sessions import SessionManager

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

app = typer.Typer(
    name="atlas",
    help="ATLAS - agente defensivo de administracao e seguranca no terminal.",
    no_args_is_help=False,
    invoke_without_command=True,
)
console = Console()
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _exceeds_threshold(fail_on: Severity | None, findings) -> bool:
    """True when any finding's severity is at or above the configured threshold."""
    if not fail_on:
        return False
    threshold = SEVERITY_ORDER.index(fail_on)

    def rank(item) -> int:
        try:
            return SEVERITY_ORDER.index(Severity(item.severity))
        except (ValueError, AttributeError, KeyError):
            return 0

    return any(rank(item) <= threshold for item in findings)


def _monitor_roots(paths: list[Path] | None) -> list[Path]:
    if paths:
        roots = [path.expanduser().resolve() for path in paths]
    else:
        from atlas.multi_watch import configured_projects

        roots = configured_projects()
        if not roots:
            current = Path.cwd().resolve()
            if current == Path.home().resolve():
                raise typer.BadParameter("Nenhum projeto detectado. Use --watch C:\\Projeto ou atlas config --add-path C:\\Projeto.")
            roots = [current]
    missing = [root for root in roots if not root.exists()]
    if missing:
        raise typer.BadParameter(f"Caminho inexistente: {missing[0]}")
    return roots


@app.command()
def malware(
    action: str = typer.Argument("status", help="status, scan, inspect ou yara"),
    path: Path | None = typer.Argument(None, help="Arquivo ou diretorio para scan customizado."),
    rules: Path | None = typer.Option(None, "--rules", help="Diretorio local confiavel de regras YARA."),
) -> None:
    """Consulta o Microsoft Defender ou executa scan sem remediacao automatica."""
    from atlas.threats import defender_snapshot, inspect_executable, scan_with_defender, scan_with_yara

    action = action.casefold()
    if action == "status":
        snapshot = defender_snapshot()
        if not snapshot.available:
            console.print(f"[yellow]Microsoft Defender unavailable:[/] {snapshot.detail}")
            raise typer.Exit(1)
        protection = [snapshot.status.get(key) for key in (
            "AMServiceEnabled", "AntivirusEnabled", "AntispywareEnabled", "RealTimeProtectionEnabled",
        )]
        if all(value is True for value in protection):
            console.print("[green]Defender ACTIVE[/]")
        elif any(value is False for value in protection):
            console.print("[red]Defender protection incomplete[/]")
        else:
            console.print("[yellow]Defender protection status unknown (incomplete telemetry)[/]")
            raise typer.Exit(1)
        if snapshot.detail:
            console.print(f"[yellow]{snapshot.detail}[/]")
        else:
            console.print(f"Detections in Defender history: {len(snapshot.detections)}")
        return
    if action == "inspect" and path is not None:
        target = path.expanduser().resolve()
        if target.suffix.casefold() not in {".exe", ".dll", ".sys", ".ocx", ".scr"}:
            raise typer.BadParameter("inspect aceita executáveis Windows (.exe, .dll, .sys, .ocx, .scr).")
        try:
            console.print_json(json.dumps(inspect_executable(target), ensure_ascii=False))
        except (OSError, ValueError) as exc:
            raise typer.BadParameter(f"Não foi possível inspecionar o arquivo: {type(exc).__name__}") from exc
        return
    if action == "yara" and path is not None and rules is not None:
        try:
            result = scan_with_yara(path, rules)
        except (OSError, ValueError) as exc:
            raise typer.BadParameter(f"Não foi possível executar YARA: {type(exc).__name__}") from exc
        console.print_json(json.dumps(result, ensure_ascii=False))
        if not result.get("available") or not result.get("complete"):
            raise typer.Exit(1)
        return
    if action != "scan" or path is None:
        raise typer.BadParameter("Use malware status, scan CAMINHO, inspect ARQUIVO.exe ou yara CAMINHO --rules DIR")
    target = path.expanduser().resolve()
    console.print("[cyan]Defender custom scan (read-only remediation mode)...[/]")
    clean, detail = scan_with_defender(target)
    console.print(detail)
    if not clean:
        raise typer.Exit(2)


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Mostra a versao."),
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        from atlas.tui import run_tui

        run_tui()


@app.command()
def agent(
    directory: Path = typer.Option(Path.cwd(), "--in", help="Diretorio de trabalho do agente."),
    model: str | None = typer.Option(None, "--model", "-m", help="Modelo Ollama instalado para esta sessão."),
    advanced: bool = typer.Option(False, "--advanced", help="Compatibilidade: abre o painel integrado."),
) -> None:
    """Abre a caixa de conversa do ATLAS no terminal."""
    from atlas.panel import AtlasPanel

    AtlasPanel(project=directory, model=model).run()


@app.command()
def dashboard() -> None:
    """Abre o painel local de seguranca e administracao."""
    from atlas.tui import run_tui

    run_tui()


@app.command()
def doctor(
    fix: bool = typer.Option(True, "--fix/--no-fix", help="Oferece correções interativas quando possível."),
) -> None:
    """Diagnostica o ambiente e aponta correções para problemas comuns."""
    from atlas.doctor import run_doctor

    failures, _ = run_doctor(interactive=fix, console=console)
    if failures:
        raise typer.Exit(1)


@app.command("install-hook")
def install_hook(
    project: Path = typer.Option(Path.cwd(), "--project", "-p", help="Repositório Git; padrão pasta atual."),
    fail_on: Severity = typer.Option(Severity.HIGH, "--fail-on", case_sensitive=False,
                                     help="Severidade que bloqueia o commit."),
    force: bool = typer.Option(False, "--force", help="Substitui um hook existente."),
) -> None:
    """Instala um hook de pre-commit que roda o scan antes de cada commit."""
    from atlas.hooks import install_pre_commit_hook

    installed, detail = install_pre_commit_hook(project, fail_on.value, force)
    if not installed:
        console.print(f"[red]{detail}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Hook de pre-commit instalado:[/] {detail}")
    console.print(f"Commits serão bloqueados com findings de severidade >= [b]{fail_on.value}[/b].")


def _scan_once(project: Path, database: Database):
    from atlas.code_watch import CodeWatchdog

    watchdog = CodeWatchdog(project, database)
    watchdog.scan_now(None, baseline=True)
    return watchdog


def _print_scan_summary(project: Path, watchdog) -> None:
    active = [item for item in watchdog.state.new + watchdog.state.existing if item.state != "RESOLVED"]
    counts: dict[str, int] = {}
    for item in active:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    console.print(
        f"[green]Scan concluído:[/] {project}\n"
        f"  Arquivos analisados: {watchdog.state.files_analyzed} · saúde: {watchdog.state.health}\n"
        f"  Findings: {len(active)} "
        + " · ".join(f"{level}={counts[level]}" for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts.get(level))
    )


@app.command()
def init(
    path: list[Path] | None = typer.Option(None, "--path", "-p", help="Projeto explícito; pode ser repetido."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Aceita os padrões sem perguntar."),
    scan: bool = typer.Option(True, "--scan/--no-scan", help="Executa o primeiro scan dos projetos escolhidos."),
    monitor: bool | None = typer.Option(None, "--monitor/--no-monitor", help="Registra o monitor no login do Windows."),
    depth: int = typer.Option(3, "--depth", min=1, max=6, help="Profundidade da busca por projetos git."),
) -> None:
    """Assistente de primeiro uso: encontra projetos, monitora e faz o primeiro scan."""
    from atlas.onboarding import add_watch_paths, discover_git_projects

    settings = Settings.load()
    projects: list[Path] = []
    if path:
        for item in path:
            resolved = item.expanduser().resolve()
            if not resolved.is_dir():
                raise typer.BadParameter(f"Diretório inexistente: {resolved}")
            projects.append(resolved)
    else:
        console.print("[cyan]Procurando projetos git em Documents, Desktop, OneDrive e no perfil do usuário…[/cyan]")
        projects = discover_git_projects(max_depth=depth)
        if not projects:
            console.print("[yellow]Nenhum projeto git encontrado automaticamente.[/yellow]")
        else:
            table = Table(title=f"{len(projects)} projeto(s) encontrados")
            table.add_column("#")
            table.add_column("Projeto")
            for index, project in enumerate(projects, 1):
                table.add_row(str(index), str(project))
            console.print(table)
        if not yes:
            typed = typer.prompt(
                "Digite um caminho adicional ou pressione Enter para continuar",
                default="", show_default=False,
            ).strip()
            if typed:
                extra = Path(typed).expanduser().resolve()
                if extra.is_dir():
                    projects.append(extra)
                else:
                    console.print(f"[red]Caminho inválido:[/] {extra}")
    if not projects:
        raise typer.BadParameter("Nenhum projeto para monitorar. Informe --path C:\\Projeto ou crie um repositório git.")

    selected = list(projects)
    if not yes and len(projects) > 1:
        answer = typer.prompt(
            "Quais monitorar? Números separados por vírgula, 'a' para todos",
            default="a",
        ).strip()
        if answer and not answer.casefold().startswith("a"):
            chosen: list[Path] = []
            for token in answer.split(","):
                token = token.strip()
                if token.isdigit() and 1 <= int(token) <= len(projects):
                    chosen.append(projects[int(token) - 1])
            if chosen:
                selected = chosen
            else:
                console.print("[yellow]Seleção inválida; usando todos os projetos.[/yellow]")

    added = add_watch_paths(settings, selected)
    settings.save()
    console.print("[green]Projetos salvos em watch_paths:[/] " + ", ".join(str(item) for item in selected))
    if not added:
        console.print("[dim]Todos já estavam configurados.[/dim]")

    if scan:
        database = Database()
        for project in selected:
            with console.status(f"[cyan]ATLAS analisando {project.name}…[/cyan]"):
                watchdog = _scan_once(project, database)
            _print_scan_summary(project, watchdog)

    want_monitor = monitor
    if want_monitor is None and not yes:
        want_monitor = typer.confirm("Registrar o monitor para iniciar no login do Windows?", default=False)
    if want_monitor:
        from atlas.monitor import install_startup

        installed, detail = install_startup(selected)
        if installed:
            console.print("[green]Monitor registrado no login.[/green]")
        else:
            console.print(f"[yellow]Não foi possível registrar no login:[/] {detail}")
    console.print("[bold cyan]Pronto![/] Use [b]atlas[/b] para abrir o painel ou [b]atlas watch[/b] para monitorar.")


@app.command("config")
def configure(
    add_path: Path | None = typer.Option(None, "--add-path", help="Adiciona um projeto ao monitoramento salvo."),
    remove_path: Path | None = typer.Option(None, "--remove-path", help="Remove um projeto salvo."),
    ignore_rule: str | None = typer.Option(None, "--ignore-rule", help="Ignora uma regra ou scanner."),
    unignore_rule: str | None = typer.Option(None, "--unignore-rule", help="Remove uma regra da lista ignorada."),
    suppress_finding: str | None = typer.Option(None, "--suppress-finding", help="Suprime FINGERPRINT=MOTIVO por prazo definido."),
    suppress_rule: str | None = typer.Option(None, "--suppress-rule", help="Suprime a ocorrência ativa mais recente de uma regra."),
    suppress_file: str | None = typer.Option(None, "--file", help="Arquivo/caminho relativo quando usado com --suppress-rule."),
    suppress_reason: str | None = typer.Option(None, "--reason", help="Motivo da supressão por regra."),
    list_suppressions: bool = typer.Option(False, "--list-suppressions", help="Lista supressões em tabela legível."),
    unsuppress_finding: str | None = typer.Option(None, "--unsuppress-finding", help="Remove supressão pela fingerprint."),
    suppression_days: int = typer.Option(30, "--suppression-days", min=1, max=3650, help="Validade da supressão em dias."),
    days: int = typer.Option(30, "--days", min=1, max=3650, help="Validade da supressão por regra, em dias."),
    risk: str | None = typer.Option(None, "--risk", help="Altera severidade no formato REGRA=HIGH."),
) -> None:
    """Mostra ou atualiza a configuração persistente do ATLAS."""
    from atlas.suppressions import add_suppression, remove_suppression

    settings = Settings.load()
    if add_path:
        resolved = add_path.expanduser().resolve()
        if not resolved.is_dir():
            raise typer.BadParameter(f"Diretório inexistente: {resolved}")
        settings.watch_paths = sorted(set(settings.watch_paths).union({str(resolved)}))
    if remove_path:
        resolved = str(remove_path.expanduser().resolve()).casefold()
        settings.watch_paths = [item for item in settings.watch_paths if str(Path(item).resolve()).casefold() != resolved]
    if ignore_rule:
        settings.ignored_rules = sorted(set(settings.ignored_rules).union({ignore_rule}))
    if unignore_rule:
        settings.ignored_rules = [item for item in settings.ignored_rules if item.casefold() != unignore_rule.casefold()]
    if suppress_finding:
        fingerprint, separator, reason = suppress_finding.partition("=")
        fingerprint, reason = fingerprint.strip(), reason.strip()
        if not separator or len(fingerprint) != 64 or not reason:
            raise typer.BadParameter("Use --suppress-finding FINGERPRINT=MOTIVO com justificativa.")
        add_suppression(settings, fingerprint, reason, suppression_days)
        Database().apply_suppression(fingerprint, reason)
    if suppress_rule:
        database = Database()
        finding = database.latest_code_finding_by_rule(suppress_rule, suppress_file)
        if finding is None:
            hint = f" no arquivo '{suppress_file}'" if suppress_file else ""
            raise typer.BadParameter(
                f"Nenhum finding ativo encontrado para a regra '{suppress_rule}'{hint}. Use atlas scan antes."
            )
        reason = (suppress_reason or f"Suprimido por regra via CLI: {suppress_rule}").strip()
        add_suppression(settings, finding.fingerprint, reason, days)
        database.apply_suppression(finding.fingerprint, reason)
        shown = Path(finding.file_path).name
        console.print(
            f"[green]Supressão aplicada:[/] {finding.rule_id} · {shown}:{finding.line or '-'} · {days} dia(s)"
        )
    if unsuppress_finding:
        remove_suppression(settings, unsuppress_finding)
    if risk:
        try:
            rule, severity = (part.strip() for part in risk.split("=", 1))
        except ValueError as exc:
            raise typer.BadParameter("Use REGRA=SEVERIDADE") from exc
        severity = severity.upper()
        if not rule or severity not in {item.value for item in Severity}:
            raise typer.BadParameter("Severidade deve ser CRITICAL, HIGH, MEDIUM, LOW ou INFO")
        settings.risk_overrides[rule] = severity
    changed = any((add_path, remove_path, ignore_rule, unignore_rule, risk, suppress_finding,
                   suppress_rule, unsuppress_finding))
    if changed:
        settings.save()
    if list_suppressions:
        _print_suppressions(settings)
        return
    console.print_json(json.dumps({
        "watch_paths": settings.watch_paths,
        "ignored_rules": settings.ignored_rules,
        "risk_overrides": settings.risk_overrides,
        "finding_suppressions": settings.finding_suppressions,
        "notifications_enabled": settings.notifications_enabled,
        "silent_mode": settings.silent_mode,
        "debounce_seconds": settings.watchdog_debounce_seconds,
    }, ensure_ascii=False))


def _print_suppressions(settings: Settings) -> None:
    from atlas.suppressions import active_suppressions, expires_in_days

    suppressions = active_suppressions(settings)
    if not suppressions:
        console.print("[yellow]Nenhuma supressão ativa.[/yellow]")
        return
    database = Database()
    table = Table(title=f"{len(suppressions)} supressão(ões) ativa(s)")
    for column in ("Regra", "Arquivo", "Motivo", "Expira em"):
        table.add_column(column)
    for entry in suppressions:
        finding = database.latest_code_finding_by_fingerprint(str(entry.get("fingerprint", "")))
        if finding is not None:
            try:
                shown = str(Path(finding.file_path).resolve())
            except OSError:
                shown = finding.file_path
            rule = finding.rule_id
        else:
            rule, shown = "(fingerprint sem finding ativo)", entry.get("fingerprint", "")[:12]
        remaining = expires_in_days(entry)
        expires = f"{remaining} dia(s)" if remaining is not None else "expirada"
        table.add_row(rule, shown, str(entry.get("reason", "")), expires)
    console.print(table)


@app.command()
def report(
    project: Path | None = typer.Option(None, "--project", "-p", help="Projeto específico; omitido inclui todos."),
    output_format: str = typer.Option("md", "--format", "-f", help="Formato: md, html, json ou sarif."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Diretório de destino; padrão Downloads."),
) -> None:
    """Gera um relatório sanitizado do ATLAS."""
    from atlas.report import (
        generate_html_report,
        generate_json_report,
        generate_markdown_report,
        generate_sarif_report,
    )

    normalized = output_format.casefold()
    if normalized not in {"md", "markdown", "html", "json", "sarif"}:
        raise typer.BadParameter("Formato deve ser md, html, json ou sarif")
    generator = {"html": generate_html_report, "json": generate_json_report,
                 "sarif": generate_sarif_report}.get(normalized, generate_markdown_report)
    selected = project.expanduser().resolve() if project else None
    path = generator(Database(), selected, output.expanduser().resolve() if output else None)
    console.print(f"[green]Relatório ATLAS criado:[/] {path}")


@app.command("scan")
def scan_project(
    project: Path = typer.Argument(Path.cwd(), help="Projeto para analisar; padrao: pasta atual."),
    output_format: str = typer.Option("table", "--format", "-f", help="table ou json."),
    fail_on: Severity | None = typer.Option(None, "--fail-on", case_sensitive=False,
                                            help="Retorna código 2 quando houver severidade igual ou maior (uso em CI)."),
) -> None:
    """Executa uma análise local única de um projeto, sem abrir a TUI."""
    from atlas.code_watch import CodeWatchdog
    from atlas.report import render_json_report

    project = project.expanduser().resolve()
    if not project.is_dir():
        raise typer.BadParameter(f"Diretório inexistente: {project}")
    if output_format.casefold() not in {"table", "json"}:
        raise typer.BadParameter("Formato deve ser table ou json")
    database = Database()
    watchdog = CodeWatchdog(project, database)
    with console.status("[cyan]ATLAS analisando o projeto com scanners locais...[/cyan]"):
        watchdog.scan_now(None, baseline=True)
    if watchdog.state.status == "ERROR":
        console.print(f"[red]A análise falhou:[/] {watchdog.state.error}")
        raise typer.Exit(1)
    active = [item for item in database.code_findings(str(project)) if item.state not in {"RESOLVED", "SUPPRESSED"}]
    if output_format.casefold() == "json":
        typer.echo(render_json_report(database, project))
        if _exceeds_threshold(fail_on, active):
            raise typer.Exit(2)
        return

    unavailable = [item for item in watchdog.state.availability if item.status == "NOT_INSTALLED"]
    partial = watchdog.state.health != "COMPLETE" or bool(watchdog.state.files_skipped_large)
    console.print(
        f"[bold cyan]ATLAS SCAN[/] · {'COBERTURA PARCIAL' if partial else 'SCANNERS DISPONÍVEIS EXECUTADOS'}"
    )
    console.print(f"Projeto: {project}\nSaúde do scan: {watchdog.state.health}\nArquivos analisados: {watchdog.state.files_analyzed}")
    console.print(f"Arquivos omitidos por excederem 2 MB: {watchdog.state.files_skipped_large}")
    console.print(f"Arquivos/diretórios inacessíveis: {watchdog.state.files_skipped_unreadable}")
    for item in unavailable:
        console.print(f"[yellow]Scanner indisponível: {item.name}[/yellow] · Instalação: {item.install}")
    for item in watchdog.state.availability:
        if item.status in {"FAILED", "PARTIAL", "TIMEOUT", "CANCELLED"}:
            console.print(f"[red]Scanner {item.name}: {item.status}[/red] · {item.reason or item.detail}")
    findings = [item for item in database.code_findings(str(project)) if item.state != "RESOLVED"]
    if not findings:
        message = "Nenhum finding detectado no escopo analisado." if partial else "Nenhum finding detectado pelos scanners concluídos."
        console.print(f"[yellow]{message}[/] Isso não garante ausência de vulnerabilidades.")
        return
    table = Table(title=f"{len(findings)} finding(s) ativo(s)")
    for column in ("Estado", "Severidade", "Confiança estimada", "Regra", "Arquivo", "Linha", "Descrição", "Scanner"):
        table.add_column(column)
    for item in findings:
        try:
            relative = str(Path(item.file_path).resolve().relative_to(project))
        except (OSError, ValueError):
            relative = Path(item.file_path).name
        table.add_row(item.state, item.severity, f"{item.confidence}/100", item.rule_id, relative,
                      str(item.line or "-"), item.description, item.scanner)
    console.print(table)
    if _exceeds_threshold(fail_on, active):
        raise typer.Exit(2)


@app.command()
def watch(
    project: Path | None = typer.Argument(None, help="Diretorio do projeto; omitido observa todos os caminhos configurados."),
    ai: bool = typer.Option(False, "--ai", help="Habilita revisao explicita de findings com Ollama local."),
    ai_model: str | None = typer.Option(None, "--ai-model", help="Modelo Ollama local; padrao definido nas configuracoes."),
    once: bool = typer.Option(False, "--once", help="Executa um scan local e encerra."),
    all_projects: bool = typer.Option(False, "--all", help="Observa todos os caminhos configurados."),
    silent: bool | None = typer.Option(None, "--silent/--notify", help="Desativa ou reativa notificações do Watchdog."),
    ignore_rule: list[str] | None = typer.Option(None, "--ignore-rule", help="Regra/scanner a ignorar; pode ser repetido."),
) -> None:
    """Observa codigo e avisa somente sobre vulnerabilidades novas."""
    from atlas.multi_watch import MultiProjectWatchdog, configured_projects

    if silent is not None or ignore_rule:
        settings = Settings.load()
        if silent is not None:
            settings.silent_mode = silent
            settings.notifications_enabled = not silent
        if ignore_rule:
            settings.ignored_rules = sorted(set(settings.ignored_rules).union(ignore_rule))
        settings.save()

    multi = all_projects or project is None
    if multi:
        targets = configured_projects()
        if not targets:
            raise typer.BadParameter("Nenhum caminho configurado. Use atlas monitor start --watch C:\\Projeto ou informe um caminho.")
    else:
        target = project.expanduser().resolve()
        if not target.exists() or not target.is_dir():
            raise typer.BadParameter(f"Diretorio inexistente: {target}")
        targets = [target]
    if ai:
        selected_model = ai_model or Settings.load().ollama_model
        console.print(f"[cyan]Ollama AI local ativo:[/] {selected_model}")
    if once:
        manager = MultiProjectWatchdog(targets, ai_enabled=ai, ai_model=ai_model)
        with console.status("[cyan]ATLAS executando scanners locais...[/cyan]"):
            manager.scan_now()
        table = Table(title=f"ATLAS WATCHDOG · {len(targets)} projeto(s)")
        table.add_column("State")
        table.add_column("Severity")
        table.add_column("Project")
        table.add_column("File")
        table.add_column("Line")
        table.add_column("Description")
        table.add_column("Scanner")
        for target in targets:
            watchdog = manager.watchdogs[target]
            for item in watchdog.state.new + watchdog.state.resolved:
                try:
                    shown_path = str(Path(item.file_path).resolve().relative_to(target))
                except (OSError, ValueError):
                    shown_path = Path(item.file_path).name
                table.add_row(item.state, item.severity, target.name, shown_path, str(item.line or "-"), item.description, item.scanner)
            for item in watchdog.state.availability:
                console.print(f"{item.name}: {item.status} ({item.duration_seconds:.2f}s)")
                if item.status == "NOT_INSTALLED":
                    console.print(f"Install: {item.install}")
                if item.reason:
                    console.print(f"Reason: {item.reason}")
        console.print(table)
        return
    from atlas.watch_tui import run_multi_watch_tui, run_watch_tui

    if multi:
        if ai:
            run_multi_watch_tui(targets, ai_enabled=True, ai_model=ai_model)
        else:
            run_multi_watch_tui(targets)
    else:
        if ai:
            run_watch_tui(targets[0], ai_enabled=True, ai_model=ai_model)
        else:
            run_watch_tui(targets[0])


def _show_monitor_logs(read_log, log_path: Path, limit: int, follow: bool) -> None:
    lines = read_log(limit)
    if not lines:
        console.print(f"[yellow]Nenhum log em {log_path} ainda.[/yellow] Inicie com [b]atlas monitor start[/b].")
        return
    console.print(f"[bold cyan]ATLAS Monitor · log[/] ({log_path})")
    for line in lines:
        console.print(line, highlight=False)
    if not follow:
        return
    console.print("[dim]Acompanhando em tempo real — Ctrl+C para sair.[/dim]")
    seen = len(lines)
    try:
        while True:
            time.sleep(0.5)
            current = read_log(0)
            if len(current) > seen:
                for line in current[seen:]:
                    console.print(line, highlight=False)
                seen = len(current)
            elif len(current) < seen:
                seen = len(current)
    except KeyboardInterrupt:
        console.print("\n[dim]Encerrado.[/dim]")


@app.command()
def monitor(
    action: str = typer.Argument("status", help="start, stop, status, events, logs ou install"),
    watch: list[Path] | None = typer.Option(None, "--watch", "-w", help="Caminho observado; pode ser repetido."),
    startup: bool = typer.Option(False, "--startup", help="Instala inicialização automática no login."),
    limit: int = typer.Option(25, "--limit", min=1, max=500),
    follow: bool = typer.Option(False, "--follow", "-f", help="Acompanha o log em tempo real (Ctrl+C para sair)."),
) -> None:
    """Controla o monitor defensivo contínuo."""
    from atlas.monitor import (
        MONITOR_LOG,
        install_startup,
        is_running,
        read_monitor_log,
        read_state,
        start_background,
        stop_background,
    )

    action = action.lower().strip()
    if action == "status":
        state = read_state()
        running = is_running()
        status = "ATIVO" if running else "PARADO"
        console.print(f"[bold cyan]ATLAS Monitor[/] · {status} · pid={state.get('pid') if running else '--'}")
        console.print("Caminhos: " + (", ".join(state.get("roots") or []) or "nenhum"))
        return
    if action == "events":
        table = Table(title="ATLAS · Eventos contínuos")
        table.add_column("Horário")
        table.add_column("Risco")
        table.add_column("Tipo")
        table.add_column("Componente")
        table.add_column("Evento")
        for event in Database().recent_monitor_events(limit):
            table.add_row(f"{event.created_at.astimezone():%d/%m %H:%M:%S}", event.severity,
                          event.kind, event.component, event.detail)
        console.print(table)
        return
    if action == "logs":
        _show_monitor_logs(read_monitor_log, MONITOR_LOG, limit, follow)
        return
    if action == "stop":
        console.print("[green]Monitor finalizado.[/green]" if stop_background() else "[yellow]Monitor não estava ativo.[/yellow]")
        return
    if action not in {"start", "install"}:
        raise typer.BadParameter("Ação deve ser start, stop, status, events, logs ou install")
    roots = _monitor_roots(watch)
    settings = Settings.load()
    settings.watch_paths = [str(root) for root in roots]
    settings.save()
    if action == "install" or startup:
        installed, detail = install_startup(roots)
        if not installed:
            console.print(f"[red]Não foi possível instalar no login:[/] {detail}")
            raise typer.Exit(1)
        console.print("[green]Inicialização automática instalada para o login do Windows.[/green]")
    pid = start_background(roots)
    console.print(f"[green]Monitor ativo em segundo plano[/] · pid={pid}")
    console.print("Observando: " + ", ".join(str(root) for root in roots))


@app.command("_monitor-run", hidden=True)
def monitor_run(
    watch: list[Path] = typer.Option(..., "--watch", "-w"),
) -> None:
    """Processo interno do monitor residente (eventos + análise de código)."""
    from atlas.monitor import MonitorService
    from atlas.multi_watch import MultiProjectWatchdog

    roots = [path.expanduser().resolve() for path in watch]
    code_watchdog = MultiProjectWatchdog(roots)
    code_watchdog.start(initial_scan=True)
    try:
        MonitorService(roots).run()
    finally:
        code_watchdog.stop()


@app.command()
def security(
    path: list[Path] | None = typer.Option(None, "--path", "-p", help="Caminho adicional para permissoes e secrets."),
    output_format: str = typer.Option("table", "--format", help="table ou json"),
    fail_on: Severity | None = typer.Option(None, "--fail-on", case_sensitive=False, help="Retorna codigo 2 quando esta severidade ou maior existir."),
) -> None:
    """Executa uma analise defensiva e somente leitura."""
    roots = [item.expanduser().resolve() for item in path] if path else None
    with console.status("[cyan]ATLAS analisando a maquina...[/cyan]"):
        scan = SecurityScanner().scan(roots)
    ordered = sorted(scan.findings, key=lambda item: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(item.severity))
    if output_format.lower() == "json":
        payload = {
            "hostname": scan.hostname,
            "created_at": scan.created_at.isoformat(),
            "score": scan.score,
            "score_by_domain": score_breakdown(scan.findings),
            "findings": [
                {key: getattr(item, key) for key in ("check_id", "title", "severity", "evidence", "risk", "component", "recommendation")}
                for item in ordered
            ],
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        domains = score_breakdown(scan.findings)
        console.print(
            f"[bold]Score por domínio:[/] credenciais={domains['credentials']} · rede={domains['network']} · "
            f"containers={domains['containers']} · host={domains['host']} · código={domains['code']}"
        )
        table = Table(title=f"ATLAS Security Scan · Score {scan.score}/100", show_lines=True)
        table.add_column("Severidade", style="bold")
        table.add_column("Finding")
        table.add_column("Componente")
        table.add_column("Evidencia")
        table.add_column("Risco")
        table.add_column("Recomendacao")
        colors = {"CRITICAL": "white on red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
        for item in ordered:
            table.add_row(f"[{colors[item.severity]}]{item.severity}[/]", item.title, item.component, item.evidence, item.risk, item.recommendation)
        console.print(table)
    if _exceeds_threshold(fail_on, scan.findings):
        raise typer.Exit(2)


@app.command()
def start(
    watch: Path = typer.Option(Path.cwd(), "--watch", "-w", help="Diretorio observado durante a sessao."),
) -> None:
    """Inicia um subshell instrumentado e uma sessao operacional."""
    watch = watch.expanduser().resolve()
    if not watch.exists():
        raise typer.BadParameter(f"Caminho inexistente: {watch}")
    manager = SessionManager()
    console.print("[bold cyan]ATLAS[/] preparando snapshots e o shell controlado...")
    try:
        manager.run_controlled_shell(watch)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    latest = manager.database.sessions(1)
    if latest and latest[0].summary:
        console.print(f"[green]{latest[0].summary}[/green]")


@app.command()
def stop() -> None:
    """Finaliza a sessao operacional ativa."""
    completed = SessionManager().stop(os.environ.get("ATLAS_SESSION_ID"))
    if not completed:
        console.print("[yellow]Nenhuma sessao ativa.[/yellow]")
        return
    if os.environ.get("ATLAS_SESSION_ID"):
        console.print("[green]Sessao finalizada; encerrando o shell controlado...[/green]")
    else:
        console.print(f"[green]{completed.summary or 'Sessao finalizada.'}[/green]")


@app.command()
def history(
    session_id: str | None = typer.Option(None, "--session", "-s", help="Exibe os eventos de uma sessao."),
    limit: int = typer.Option(20, "--limit", min=1, max=500),
) -> None:
    """Mostra sessoes e eventos registrados."""
    database = Database()
    if session_id:
        detail = database.session_detail(session_id)
        if not detail:
            console.print("[red]Sessao nao encontrada.[/red]")
            raise typer.Exit(1)
        console.print(f"[bold]Sessao {detail.id}[/bold] · {detail.status}\n{detail.summary or ''}")
        table = Table(show_lines=True)
        table.add_column("Horario")
        table.add_column("Tipo")
        table.add_column("Componente")
        table.add_column("Detalhe")
        table.add_column("Resultado")
        for event in sorted(detail.events, key=lambda item: item.created_at):
            table.add_row(event.created_at.astimezone().strftime("%d/%m/%Y %H:%M:%S"), event.kind, event.component, event.detail, event.result)
        console.print(table)
        return
    table = Table(title="ATLAS · Historico")
    table.add_column("ID")
    table.add_column("Inicio")
    table.add_column("Status")
    table.add_column("Shell")
    table.add_column("Diretorio")
    table.add_column("Resumo")
    for item in database.sessions(limit):
        table.add_row(item.id[:8], item.started_at.astimezone().strftime("%d/%m/%Y %H:%M"), item.status, item.shell, item.working_directory, item.summary or "")
    console.print(table)


@app.command("_record-command", hidden=True)
def record_command() -> None:
    try:
        payload = json.loads(sys.stdin.read())
        SessionManager().record_command(str(payload["session_id"]), str(payload["command"]), payload.get("exit_code"))
    except (ValueError, KeyError, TypeError):
        raise typer.Exit(1)


@app.command("_record-env", hidden=True)
def record_env() -> None:
    session_id = os.environ.get("ATLAS_SESSION_ID")
    command = os.environ.get("ATLAS_COMMAND")
    if session_id and command:
        try:
            exit_code = int(os.environ.get("ATLAS_EXIT", "0"))
        except ValueError:
            exit_code = 0
        SessionManager().record_command(session_id, command, exit_code)
