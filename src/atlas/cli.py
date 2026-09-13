from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from atlas import __version__
from atlas.config import Settings
from atlas.database import Database
from atlas.models import Severity
from atlas.security import SecurityScanner
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


def _monitor_roots(paths: list[Path] | None) -> list[Path]:
    if paths:
        roots = [path.expanduser().resolve() for path in paths]
    else:
        configured = Settings.load().watch_paths
        roots = [Path(path).expanduser().resolve() for path in configured] if configured else [Path.home().resolve()]
    missing = [root for root in roots if not root.exists()]
    if missing:
        raise typer.BadParameter(f"Caminho inexistente: {missing[0]}")
    return roots


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
    model: str | None = typer.Option(None, "--model", "-m", help="Modelo gratuito alternativo."),
    continue_session: bool = typer.Option(False, "--continue", "-c", help="Continua a ultima conversa."),
    advanced: bool = typer.Option(False, "--advanced", help="Exige o chat avançado do ATLAS."),
) -> None:
    """Abre a caixa de conversa do ATLAS no terminal."""
    from atlas.agent_backend import find_hermes, launch_agent

    if not find_hermes() and not advanced:
        from atlas.tui import run_agent_tui

        console.print("[yellow]Chat avançado indisponível; iniciando o agente local do ATLAS.[/yellow]")
        run_agent_tui()
        return

    try:
        exit_code = launch_agent(directory, model, continue_session)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    raise typer.Exit(exit_code)


@app.command()
def dashboard() -> None:
    """Abre o painel local de seguranca e administracao."""
    from atlas.tui import run_tui

    run_tui()


@app.command("config")
def configure(
    add_path: Path | None = typer.Option(None, "--add-path", help="Adiciona um projeto ao monitoramento salvo."),
    remove_path: Path | None = typer.Option(None, "--remove-path", help="Remove um projeto salvo."),
    ignore_rule: str | None = typer.Option(None, "--ignore-rule", help="Ignora uma regra ou scanner."),
    unignore_rule: str | None = typer.Option(None, "--unignore-rule", help="Remove uma regra da lista ignorada."),
    risk: str | None = typer.Option(None, "--risk", help="Altera severidade no formato REGRA=HIGH."),
) -> None:
    """Mostra ou atualiza a configuração persistente do ATLAS."""
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
    if risk:
        try:
            rule, severity = (part.strip() for part in risk.split("=", 1))
        except ValueError as exc:
            raise typer.BadParameter("Use REGRA=SEVERIDADE") from exc
        severity = severity.upper()
        if not rule or severity not in {item.value for item in Severity}:
            raise typer.BadParameter("Severidade deve ser CRITICAL, HIGH, MEDIUM, LOW ou INFO")
        settings.risk_overrides[rule] = severity
    if any((add_path, remove_path, ignore_rule, unignore_rule, risk)):
        settings.save()
    console.print_json(json.dumps({
        "watch_paths": settings.watch_paths,
        "ignored_rules": settings.ignored_rules,
        "risk_overrides": settings.risk_overrides,
        "notifications_enabled": settings.notifications_enabled,
        "silent_mode": settings.silent_mode,
        "debounce_seconds": settings.watchdog_debounce_seconds,
    }, ensure_ascii=False))


@app.command()
def report(
    project: Path | None = typer.Option(None, "--project", "-p", help="Projeto específico; omitido inclui todos."),
    output_format: str = typer.Option("md", "--format", "-f", help="Formato: md ou html."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Diretório de destino; padrão Downloads."),
) -> None:
    """Gera um relatório sanitizado do ATLAS."""
    from atlas.report import generate_html_report, generate_markdown_report

    normalized = output_format.casefold()
    if normalized not in {"md", "markdown", "html"}:
        raise typer.BadParameter("Formato deve ser md ou html")
    generator = generate_html_report if normalized == "html" else generate_markdown_report
    selected = project.expanduser().resolve() if project else None
    path = generator(Database(), selected, output.expanduser().resolve() if output else None)
    console.print(f"[green]Relatório ATLAS criado:[/] {path}")


@app.command()
def watch(
    project: Path | None = typer.Argument(None, help="Diretorio do projeto; omitido observa todos os caminhos configurados."),
    ai: bool = typer.Option(False, "--ai", help="Reserva a integracao futura com IA; nao faz chamadas na v0.1."),
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
        console.print("[yellow]--ai esta reservado para uma versao futura; a v0.1 continua 100% local.[/yellow]")
    if once:
        manager = MultiProjectWatchdog(targets)
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
                if not item.available:
                    console.print(f"[yellow]Scanner unavailable: {item.name}[/yellow]")
                    console.print(f"Install: {item.install}")
                    if item.detail:
                        console.print(f"Reason: {item.detail}")
        console.print(table)
        return
    from atlas.watch_tui import run_multi_watch_tui, run_watch_tui

    if multi:
        run_multi_watch_tui(targets)
    else:
        run_watch_tui(targets[0])


@app.command()
def monitor(
    action: str = typer.Argument("status", help="start, stop, status, events ou install"),
    watch: list[Path] | None = typer.Option(None, "--watch", "-w", help="Caminho observado; pode ser repetido."),
    startup: bool = typer.Option(False, "--startup", help="Instala inicialização automática no login."),
    limit: int = typer.Option(25, "--limit", min=1, max=500),
) -> None:
    """Controla o monitor defensivo contínuo."""
    from atlas.monitor import (
        install_startup,
        is_running,
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
    if action == "stop":
        console.print("[green]Monitor finalizado.[/green]" if stop_background() else "[yellow]Monitor não estava ativo.[/yellow]")
        return
    if action not in {"start", "install"}:
        raise typer.BadParameter("Ação deve ser start, stop, status, events ou install")
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
            "findings": [
                {key: getattr(item, key) for key in ("check_id", "title", "severity", "evidence", "risk", "component", "recommendation")}
                for item in ordered
            ],
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
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
    if fail_on:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        threshold = order.index(fail_on)
        if any(order.index(Severity(item.severity)) <= threshold for item in scan.findings):
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
