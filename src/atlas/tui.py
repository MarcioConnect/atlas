from __future__ import annotations

import getpass
import socket
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

from atlas import __version__
from atlas.ask import LocalAtlasProvider
from atlas.code_watch import CodeWatchdog
from atlas.config import Settings
from atlas.database import Database
from atlas.models import Severity
from atlas.report import generate_markdown_report
from atlas.security import SecurityScanner
from atlas.system import docker_inventory, host_overview, services

ATLAS_PORTRAIT = """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⣤⣄⡀⠈⠙⢿⣷⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⠠⢐⣰⣾⣿⣿⣿⣿⣿⣿⣦⠀⠀⠻⣿⣿⣿⣷⠀⠂⠄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⡠⠀⠁⣠⣾⣿⣿⣿⡿⠋⠻⣿⣿⣿⣧⠀⠀⢻⣿⣿⡅⠀⡀⠀⠈⠀⢄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⡠⠊⠀⠀⠰⢟⣿⣿⣿⣿⣿⡜⣷⣿⣿⣿⣿⣇⡀⠈⣿⣿⣿⣆⣿⣆⠀⠀⠀⠑⠄⠀⠀⠀⠀⠀
⠀⠀⠀⠔⠀⠀⠀⢀⣀⣾⣿⣿⣿⠹⣿⣿⣿⣿⣿⣿⣿⣿⡔⠒⠿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠈⢂⠀⠀⠀⠀
⠀⠀⠌⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣆⠙⢿⣿⣿⣿⣿⡝⠁⣴⣶⢷⣮⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⢡⠀⠀⠀
⠀⠐⠀⠀⠀⠀⠸⠻⣿⡿⣿⡷⠝⢓⢴⣶⠟⣿⣿⣿⡇⢸⣿⠏⣀⠻⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠂⠀⠀
⠀⠃⠀⠀⠀⠀⠀⠀⠙⣽⣿⣷⠀⠀⠀⠁⠀⣿⣿⣿⣇⠈⢏⣴⣶⣦⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠐⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣅⠀⠀⠀⠀⠀⢹⣿⣿⠻⣷⣄⣩⣭⣴⣿⣿⣿⢻⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀
⠀⡀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣧⠀⠀⠀⠀⠈⢿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣏⣿⢿⣆⠀⡀⠀⠀⢀⠀⠀
⠀⢀⠀⠀⠀⠀⠀⣠⡾⢁⣿⣿⣿⣷⡀⠀⣀⣤⣾⡿⣧⠉⠛⣮⣿⡿⠿⣿⣿⣿⣿⣎⠻⣧⣘⡦⠀⡈⠀⠀
⠀⠀⢂⠀⠀⢀⣴⠋⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⠧⠜⢓⣋⣭⣴⣶⣶⣶⣭⢻⣿⣿⣷⣌⢿⣧⡐⠀⠀⠀
⠀⠀⠀⢂⢰⣿⣇⣴⣿⣿⣿⠇⣿⣿⣟⢹⣾⡟⢰⡆⣼⣿⣿⣿⣿⣿⡿⠟⠛⠉⠛⠿⣿⣿⣷⣿⣿⣄⠀⠀
⠀⠀⠀⢀⣿⡿⣿⣿⣿⣿⣡⣾⣽⣿⣿⡎⢿⡇⣿⢠⣿⣿⣿⡿⢿⣷⢣⣾⣿⣶⣄⣀⣤⣌⢿⡌⢿⣿⡇⠀
⠀⢠⡇⠘⣿⣧⣙⢿⣿⡟⣹⣿⣿⠟⣿⡷⢘⡴⣡⣿⠿⠋⠁⣠⣿⢃⣾⣿⣿⣿⣿⣿⣿⣿⡌⡇⠸⣹⠇⠀
⠀⠈⢿⠶⠞⠉⠉⠉⠉⠈⠉⠉⠁⠈⠁⠀⠈⠈⠉⠁⠀⠀⠈⠉⠁⠈⠉⠉⠉⠉⠉⠉⠉⠉⠁⠐⢞⠁⠀⠀
⠀⠀⠀⠀⠀⣠⣿⢿⣆⠀⠙⠛⢻⣿⠛⠛⠁⣿⡇⠀⠀⠀⠀⠀⣰⡿⣷⡄⠀⠀⣾⣟⣛⣛⣛⠁⠀⠀⠀⠀
⠀⠀⠀⢀⣼⡟⠁⠈⢻⣧⡀⠀⢸⣿⠀⠀⠀⣿⣇⣀⣀⡀⢀⣼⠟⠁⠈⢿⣆⠀⢈⣉⣉⣉⣻⡷⠀⠀⠀⠀
⠀⠀⠀⠉⠉⠀⠀⠀⠀⠉⠉⠀⠈⠉⠀⠀⠀⠉⠉⠉⠉⠁⠉⠉⠀⠀⠀⠀⠉⠁⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀"""

ATLAS_AGENT_MARK = """   .-========-.
 .'   /\\  /\\   '.
/    /  \\/  \\/    \\
|    \\  AT  /    |
\\     '----'     /
 '.            .'
   '-.______.-'"""

LAUNCH_ITEMS = [
    (">_", "Scan Project", "Analisar código"),
    ("□", "Watch Mode", "Monitorar alterações"),
    ("◇", "Security Audit", "Verificar riscos"),
    ("▤", "Generate Report", "Gerar relatório"),
    ("⚙", "Settings", "Configurar Atlas"),
    ("↪", "Exit", "Sair"),
]

# Keep menu symbols portable across code pages and monochrome terminals.
LAUNCH_ITEMS = [
    (">_", "Scan Project", "Analisar codigo"),
    ("[]", "Watch Mode", "Monitorar alteracoes"),
    ("<> ", "Security Audit", "Verificar riscos"),
    ("#", "Generate Report", "Gerar relatorio"),
    ("*", "Settings", "Configurar Atlas"),
    ("X", "Exit", "Sair"),
]

MENU = ["Overview", "Live Monitor", "Security", "Changes", "Sessions", "Docker", "Services", "Ask Atlas", "Settings"]
SEVERITY_COLORS = {
    Severity.CRITICAL.value: "bold white on #b42318",
    Severity.HIGH.value: "bold #ff5f5f",
    Severity.MEDIUM.value: "bold #f5c451",
    Severity.LOW.value: "#6bdcff",
    Severity.INFO.value: "#8a9baa",
}


class MainScreen(Screen):
    BINDINGS = [
        ("q", "app.quit", "Sair"), ("ctrl+c", "app.quit", "Sair"),
        ("down", "next_button", "Proximo"), ("up", "previous_button", "Anterior"),
        ("enter", "select_button", "Confirmar"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.database = Database()
        target = Path.cwd()
        # Windows commonly denies FILE_LIST_DIRECTORY on the user profile root.
        # Start the home-screen Watch Mode on the accessible ATLAS workspace.
        if target.resolve() == Path.home().resolve() and (Path.home() / "atlas").is_dir():
            target = Path.home() / "atlas"
        self.watchdog = CodeWatchdog(target, self.database)

    def compose(self) -> ComposeResult:
        info = (
            f"[ ATLAS v{__version__} ]\n"
            "AI INFRASTRUCTURE AGENT\n"
            "LOCAL MODE\n"
            "READY."
        )
        host = host_overview()
        system = (
            f"USER       : {getpass.getuser()}\n"
            f"HOST       : {socket.gethostname()}\n"
            f"WORKSPACE  : {Path.cwd()}\n"
            "MODE       : local\n"
            f"CPU/MEM    : {host['cpu_percent']:.0f}% / {host['memory_percent']:.0f}%\n"
            "STATUS     : ready"
        )
        with Vertical(id="home-frame"):
            with Horizontal(id="home-grid"):
                with Vertical(id="identity-pane"):
                    yield Static(ATLAS_AGENT_MARK + "\nATLAS AGENT", id="agent-badge", markup=False)
                    yield Static(info, id="identity", markup=False)
                    yield Static(ATLAS_PORTRAIT, id="portrait", markup=False)
                    yield Static("A T L A S\n>  LOCAL AGENT READY", id="wordmark", markup=False)
                with Vertical(id="command-pane"):
                    yield Static(
                        "INFRASTRUCTURE  /  SECURITY  /  AUTOMATION\n"
                        "DOCUMENTATION  /  MONITORING  /  YOU IN CONTROL",
                        id="manifest",
                        markup=False,
                    )
                    with Vertical(id="launch-menu"):
                        for index, (icon, title, detail) in enumerate(LAUNCH_ITEMS, 1):
                            yield Button(
                                f"{icon}  {index}.  {title:<18}  >  {detail}",
                                id=f"launch-{index}",
                            )
                    yield Static(system, id="system-panel", markup=False)
                    yield Static("ACTION    : READY", id="action-status", markup=False)
                    yield RichLog(id="chat-log", wrap=True, markup=True)
                    yield Input(placeholder="Pergunte ao ATLAS...", id="chat-input")
            yield Static(" ↑/↓  Selecionar      Enter  Confirmar      Ctrl+C  Sair                         ATLAS  ›", id="home-help", markup=False)

    def on_mount(self) -> None:
        self.query_one("#launch-1", Button).focus()
        self.query_one("#chat-log", RichLog).write("[b]ATLAS[/b]  Interface pronta. Escolha uma ação ou escreva uma pergunta.")

    def on_unmount(self) -> None:
        if self.watchdog._observer and self.watchdog._observer.is_alive():
            self.watchdog.stop()

    def _log(self, message: str) -> None:
        self.query_one("#chat-log", RichLog).write(message)

    def _set_action_status(self, status: str) -> None:
        self.query_one("#action-status", Static).update(f"ACTION    : {status}")

    def _scan(self) -> None:
        self.app.call_from_thread(self._set_action_status, "AUDIT SCANNING")
        scan = SecurityScanner(self.database).scan()
        self.app.call_from_thread(
            self._log,
            f"[b]ATLAS[/b]  Auditoria concluída: score {scan.score}/100, {len(scan.findings)} achado(s).",
        )

    def _scan_safe(self) -> None:
        try:
            self._scan()
        except Exception as exc:
            self.app.call_from_thread(self._set_action_status, f"AUDIT ERROR · {type(exc).__name__}")
            self.app.call_from_thread(self._log, f"[b]ATLAS[/b]  Auditoria indisponivel: {type(exc).__name__}.")

    def _watch(self) -> None:
        self.app.call_from_thread(self._set_action_status, "WATCH MODE STARTING")
        observer = self.watchdog._observer
        if observer and observer.is_alive():
            self.watchdog.stop()
            self.app.call_from_thread(self._set_action_status, "WATCH MODE STOPPED")
            self.app.call_from_thread(self._log, "[b]ATLAS[/b]  Watch Mode interrompido.")
            return
        self.watchdog.start(initial_scan=True)
        self.app.call_from_thread(self._set_action_status, "WATCH MODE ACTIVE")
        self.app.call_from_thread(self._log, "[b]ATLAS[/b]  Watch Mode ativo; monitorando alterações.")

    def _watch_safe(self) -> None:
        try:
            self._watch()
        except Exception as exc:
            self.app.call_from_thread(self._set_action_status, f"WATCH ERROR · {type(exc).__name__}")
            self.app.call_from_thread(self._log, f"[b]ATLAS[/b]  Watch Mode indisponivel: {type(exc).__name__}.")

    def _report(self) -> None:
        try:
            path = generate_markdown_report(self.database, self.watchdog.project)
        except Exception as exc:
            self._set_action_status(f"REPORT ERROR · {type(exc).__name__}")
            self._log(f"[b]ATLAS[/b]  Falha ao gerar relatório: {type(exc).__name__}.")
            return
        self._set_action_status("REPORT SAVED")
        self._log(f"[b]ATLAS[/b]  Relatório salvo em Downloads: {path}")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "launch-6":
            self.app.exit()
            return
        index = int(button_id.split("-")[1]) - 1
        title = LAUNCH_ITEMS[index][1]
        self._log(f"[b]ATLAS[/b]  {title} selecionado.")
        self._set_action_status(f"{title.upper()} · STARTING")
        if index == 1:
            from atlas.watch_tui import WatchScreen

            self.app.push_screen(WatchScreen(self.watchdog.project, self.database))
        elif index in {0, 2}:
            self.app.push_screen(DashboardScreen("Security"))
        elif index == 3:
            self._report()
        elif index == 4:
            self.app.push_screen(DashboardScreen("Settings"))
            return
            settings = Settings.load()
            self._log(f"[b]ATLAS[/b]  Configurações: {len(settings.watch_paths)} caminho(s) observado(s), modo somente leitura.")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        question = event.value.strip()
        if not question:
            return
        log = self.query_one("#chat-log", RichLog)
        log.write(f"[b]VOCÊ[/b]  {question}")
        log.write(f"[b]ATLAS[/b]  {LocalAtlasProvider(self.database).answer(question)}")
        event.input.value = ""

    def action_next_button(self) -> None:
        """Move focus to next button in launch menu."""
        buttons = self.query("#launch-menu Button")
        if not buttons:
            return
        current = self.focused
        if current and current.id and current.id.startswith("launch-"):
            idx = int(current.id.split("-")[1])
            if idx < 6:
                self.query_one(f"#launch-{idx + 1}", Button).focus()
        else:
            self.query_one("#launch-1", Button).focus()

    def action_previous_button(self) -> None:
        """Move focus to previous button in launch menu."""
        buttons = self.query("#launch-menu Button")
        if not buttons:
            return
        current = self.focused
        if current and current.id and current.id.startswith("launch-"):
            idx = int(current.id.split("-")[1])
            if idx > 1:
                self.query_one(f"#launch-{idx - 1}", Button).focus()
        else:
            self.query_one("#launch-1", Button).focus()

    def action_select_button(self) -> None:
        """Activate the currently focused button."""
        current = self.focused
        if current and current.id and current.id.startswith("launch-"):
            current.press()


class DashboardScreen(Screen):
    BINDINGS = [("q", "app.quit", "Sair"), ("escape", "app.pop_screen", "Voltar"), ("r", "refresh", "Atualizar"), ("s", "scan", "Escanear")]

    def __init__(self, initial_view: str = "Overview") -> None:
        super().__init__()
        self.database = Database()
        self.current_view = initial_view
        self._scan_running = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="layout"):
            with Vertical(id="sidebar"):
                yield Static("/\\  ATLAS", id="brand")
                yield ListView(*(ListItem(Label(name), id=f"menu-{index}") for index, name in enumerate(MENU)), id="menu")
                yield Static("READ-ONLY", id="readonly")
            yield VerticalScroll(id="content")
        yield Footer()

    def on_mount(self) -> None:
        menu = self.query_one("#menu", ListView)
        menu.index = MENU.index(self.current_view)
        menu.focus()
        self.call_after_refresh(self.show_view, self.current_view)
        if self.database.latest_scan() is None:
            self._scan_running = True
            self.run_worker(self._initial_scan, thread=True, exclusive=True)
        self.set_interval(2.0, self._live_refresh)

    def _live_refresh(self) -> None:
        if self.current_view in {"Overview", "Live Monitor"}:
            self.call_after_refresh(self.show_view, self.current_view)

    def _initial_scan(self) -> None:
        self._scan_in_background()

    def _refresh_after_initial_scan(self) -> None:
        if self.current_view == "Overview":
            self.call_after_refresh(self.show_view, "Overview")

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.current_view = MENU[event.list_view.index or 0]
        await self.show_view(self.current_view)

    async def action_refresh(self) -> None:
        await self.show_view(self.current_view)

    async def action_scan(self) -> None:
        if self._scan_running:
            self.notify("Uma análise já está em andamento.")
            return
        self._scan_running = True
        body = self.query_one("#content", VerticalScroll)
        await body.remove_children()
        await body.mount(Static("Executando analise defensiva...", classes="panel"))
        self.run_worker(self._scan_in_background, thread=True, exclusive=True)

    def _scan_in_background(self) -> None:
        try:
            SecurityScanner(self.database).scan()
        except Exception as exc:
            self.app.call_from_thread(self.notify, f"Análise interrompida: {type(exc).__name__}. Pressione S para tentar novamente.", severity="error")
        finally:
            self._scan_running = False
            self.app.call_from_thread(self.call_after_refresh, self.show_view, self.current_view)

    async def show_view(self, name: str, scan=None) -> None:
        body = self.query_one("#content", VerticalScroll)
        await body.remove_children()
        await body.mount(Static(name.upper(), classes="view-title"))
        renderer = getattr(self, f"_render_{name.lower().replace(' ', '_')}")
        widgets = renderer(scan) if name == "Security" else renderer()
        for widget in widgets:
            await body.mount(widget)

    def _render_overview(self):
        from atlas.monitor import is_running

        info = host_overview()
        scan = self.database.latest_scan()
        active = self.database.active_session()
        score = str(scan.score) if scan else "--"
        score_style = "bold green" if scan and scan.score >= 80 else "bold yellow" if scan and scan.score >= 50 else "bold red"
        events = self.database.recent_monitor_events(6)
        recent = "\n".join(f"{event.created_at.astimezone():%H:%M}  {event.kind:<10} {event.component}" for event in events) or "Nenhuma alteracao registrada."
        return [
            Horizontal(
                Static(f"[b]HOST[/b]\n{info['hostname']}\n\n[b]SISTEMA[/b]\n{info['os']}", classes="panel metric-wide"),
                Static(f"[b]UPTIME[/b]\n{info['uptime']}\n\nCPU {info['cpu_percent']:.0f}%  MEM {info['memory_percent']:.0f}%", classes="panel metric"),
                Static(f"[b]SECURITY SCORE[/b]\n[{score_style}]{score}/100[/]", classes="panel score-card"),
                classes="cards",
            ),
            Static(f"[b]MONITOR[/b]  {'ATIVO · observação contínua' if is_running() else 'PARADO · use atlas monitor start'}\n[b]SESSAO ATIVA[/b]  {active.id[:8] + ' · ' + active.working_directory if active else 'Nenhuma sessao controlada'}", classes="panel"),
            Static(f"[b]ALTERACOES RECENTES[/b]\n{recent}", classes="panel"),
        ]

    def _render_live_monitor(self):
        from atlas.monitor import is_running, read_state

        state = read_state()
        table = DataTable(zebra_stripes=True, classes="panel")
        table.add_columns("Horario", "Risco", "Tipo", "Componente", "Evento", "Impacto")
        for event in self.database.recent_monitor_events(200):
            table.add_row(
                f"{event.created_at.astimezone():%H:%M:%S}",
                f"[{SEVERITY_COLORS.get(event.severity, '')}]{event.severity}[/]",
                event.kind,
                event.component,
                event.detail,
                event.risk,
            )
        header = (
            f"[b]STATUS[/b] {'ATIVO' if is_running() else 'PARADO'}  ·  "
            f"[b]PID[/b] {state.get('pid') or '--'}  ·  "
            f"[b]ESCOPO[/b] {', '.join(state.get('roots') or []) or 'nao configurado'}"
        )
        return [Static(header, classes="panel"), table]

    def _render_security(self, scan=None):
        scan = scan or self.database.latest_scan()
        if not scan:
            return [Static("Nenhuma analise registrada. Pressione [b]S[/b] para escanear a maquina.", classes="panel")]
        counts = {level: sum(item.severity == level for item in scan.findings)
                  for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        score_class = "bold green" if scan.score >= 80 else "bold yellow" if scan.score >= 50 else "bold red"
        cards = Horizontal(
            Static(f"[b]SECURITY SCORE[/b]\n[{score_class}]{scan.score}/100[/]", classes="panel score-card"),
            Static(f"[b]CRITICAL[/b]\n[bold white on red]{counts['CRITICAL']}[/]", classes="panel metric"),
            Static(f"[b]HIGH[/b]\n[bold #ff5f5f]{counts['HIGH']}[/]", classes="panel metric"),
            Static(f"[b]MEDIUM[/b]\n[bold #f5c451]{counts['MEDIUM']}[/]", classes="panel metric"),
            Static(f"[b]LOW / INFO[/b]\n{counts['LOW']} / {counts['INFO']}", classes="panel metric"),
            classes="cards security-cards",
        )
        table = DataTable(zebra_stripes=True, classes="panel")
        table.add_columns("Severidade", "Finding", "Componente", "Evidencia", "Recomendacao")
        ordered = sorted(scan.findings, key=lambda item: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(item.severity))
        for item in ordered:
            table.add_row(f"[{SEVERITY_COLORS[item.severity]}]{item.severity}[/]", item.title, item.component, item.evidence, item.recommendation)
        return [cards, Static(f"[b]SECURITY AUDIT[/b]  {len(scan.findings)} findings  ·  Pressione [b]S[/b] para analisar novamente", classes="panel"), table]

    def _render_changes(self):
        table = DataTable(zebra_stripes=True, classes="panel")
        table.add_columns("Horario", "Tipo", "Componente", "Detalhe", "Resultado")
        for event in self.database.recent_events(100):
            table.add_row(f"{event.created_at.astimezone():%d/%m %H:%M:%S}", event.kind, event.component, event.detail, event.result)
        return [table] if table.row_count else [Static("Nenhuma mudanca registrada. Use `atlas start`.", classes="panel")]

    def _render_sessions(self):
        table = DataTable(zebra_stripes=True, classes="panel")
        table.add_columns("ID", "Inicio", "Fim", "Status", "Diretorio", "Resumo")
        for item in self.database.sessions(50):
            ended = item.ended_at.astimezone().strftime("%d/%m %H:%M") if item.ended_at else "--"
            table.add_row(item.id[:8], f"{item.started_at.astimezone():%d/%m %H:%M}", ended, item.status, item.working_directory, item.summary or "")
        return [table] if table.row_count else [Static("Nenhuma sessao registrada.", classes="panel")]

    def _render_docker(self):
        inventory = docker_inventory()
        if not inventory["available"]:
            return [Static(f"Docker indisponivel: {inventory['reason']}", classes="panel")]
        table = DataTable(zebra_stripes=True, classes="panel")
        table.add_columns("Container", "Imagem", "Status", "Portas")
        for item in inventory["containers"]:
            table.add_row(item["name"] or item["id"], item["image"], item["status"], item["ports"])
        return [Static(f"Docker Engine {inventory.get('version', '?')}", classes="panel"), table]

    def _render_services(self):
        table = DataTable(zebra_stripes=True, classes="panel")
        table.add_columns("Servico", "Nome", "Status")
        for item in sorted(services(), key=lambda entry: (entry["status"] != "running", entry["name"]))[:300]:
            table.add_row(item["name"], item["display_name"], item["status"])
        return [table] if table.row_count else [Static("Servicos indisponiveis com as permissoes atuais.", classes="panel")]

    def _render_ask_atlas(self):
        return [RichLog(id="chat", wrap=True, markup=True, classes="panel chat"), Input(placeholder="Pergunte ao ATLAS...", id="question")]

    def _render_settings(self):
        settings = Settings.load()
        watched = ", ".join(settings.watch_paths) or "diretorio atual (ou ~/.ssh ao executar na home)"
        return [Static(f"[b]Modo[/b] Somente leitura (bloqueado)\n[b]Idioma[/b] Portugues; menus em ingles\n[b]Caminhos observados[/b] {watched}\n[b]Limite de arquivos[/b] {settings.secret_scan_max_files}\n[b]Limite por arquivo[/b] {settings.secret_scan_max_bytes} bytes\n\nEdite o arquivo de configuracao do perfil para personalizar estes limites.", classes="panel")]

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "question" or not event.value.strip():
            return
        log = self.query_one("#chat", RichLog)
        log.write(f"[bold #6bdcff]VOCE[/]  {event.value}")
        log.write(f"[bold white]ATLAS[/] {LocalAtlasProvider(self.database).answer(event.value)}")
        event.input.value = ""


class AtlasApp(App):
    TITLE = "ATLAS"
    CSS = """
    Screen { background: #000000; color: #f0f0f0; }
    #home-frame { height: 100%; border: solid #686868; padding: 1; }
    #home-grid { height: 1fr; }
    #identity-pane { width: 42%; padding: 0 2; }
    #agent-badge { height: 8; color: #f0f0f0; text-style: bold; padding: 0 1; }
    #identity { height: 5; color: #a8a8a8; }
    #portrait { height: 17; color: #f0f0f0; content-align: center middle; }
    #wordmark { height: 5; color: #f4f4f4; text-align: center; text-style: bold; }
    #command-pane { width: 58%; padding-left: 1; }
    #manifest { height: 5; border: solid #7a7a7a; padding: 1 2; color: #b8b8b8; }
    #launch-menu { height: 14; border: solid #7a7a7a; margin-top: 1; padding: 1; background: #000000; }
    #launch-menu Button { height: 2; padding: 0 1; color: #d4d4d4; background: transparent; border: none; width: 100%; content-align: left middle; }
    #launch-menu Button:hover { background: #f0f0f0; color: #080808; text-style: bold; }
    #launch-menu Button:focus { background: #f0f0f0; color: #080808; text-style: bold; }
    #system-panel { height: 8; border: solid #7a7a7a; margin-top: 1; padding: 1 2; color: #c8c8c8; }
    #action-status { height: 3; border: solid #7a7a7a; margin-top: 1; padding: 1 2; color: #6bdcff; text-style: bold; }
    #chat-log { height: 6; border: solid #7a7a7a; margin-top: 1; padding: 0 1; background: #080808; }
    #chat-input { height: 3; border: solid #7a7a7a; margin-top: 1; background: #000000; }
    #home-help { height: 3; border: solid #686868; padding: 0 1; content-align: left middle; color: #c8c8c8; }
    #layout { height: 1fr; }
    #sidebar { width: 24; background: #000000; border-right: solid #7a7a7a; }
    #brand { height: 5; padding: 1 2; color: #ffffff; text-style: bold; content-align: left middle; }
    #menu { height: 1fr; background: transparent; border: none; }
    ListItem { padding: 0 2; height: 3; }
    ListItem.--highlight { background: #f0f0f0; color: #080808; border-left: thick #ffffff; }
    #readonly { height: 3; content-align: center middle; color: #d0d0d0; text-style: bold; }
    #content { padding: 1 2; }
    .view-title { height: 3; color: #ffffff; text-style: bold; }
    .panel { background: #080808; border: solid #7a7a7a; padding: 1 2; margin-bottom: 1; }
    .cards { height: 10; }
    .cards .panel { margin-right: 1; }
    .metric-wide { width: 2fr; }
    .metric { width: 1fr; }
    .score-card { width: 1fr; content-align: center middle; }
    .score-good { color: #70d6a3; }
    .score-warn { color: #f5c451; }
    .score-bad { color: #ff5f5f; }
    DataTable { min-height: 10; }
    .chat { height: 1fr; min-height: 15; }
    #question { dock: bottom; }
    """

    def on_mount(self) -> None:
        self.push_screen(MainScreen())


class AtlasAgentApp(AtlasApp):
    """Portable local Ask ATLAS interface used when no optional backend exists."""

    def on_mount(self) -> None:
        self.push_screen(DashboardScreen("Ask Atlas"))


def run_tui() -> None:
    from atlas.panel import AtlasPanel

    AtlasPanel().run()


def run_agent_tui() -> None:
    run_tui()
