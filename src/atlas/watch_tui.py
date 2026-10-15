from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Label, ListItem, ListView, Static

from atlas.code_watch import CodeWatchdog, WatchState
from atlas.config import Settings
from atlas.database import Database
from atlas.models import CodeFinding
from atlas.multi_watch import MultiProjectWatchdog
from atlas.suppression_modal import SuppressionModal
from atlas.suppressions import add_suppression

MENU = [
    ("overview", "Visão geral"),
    ("watchdog", "Monitor"),
    ("new_findings", "Novos findings"),
    ("all_findings", "Todos os findings"),
    ("resolved", "Resolvidos"),
    ("scan", "Scan"),
    ("settings", "Ajustes"),
]
MENU_KEYS = [key for key, _ in MENU]
SEVERITY_STYLE = {
    "CRITICAL": "bold white on #b42318", "HIGH": "bold #ff5f5f", "MEDIUM": "bold #f5c451",
    "LOW": "#6bdcff", "INFO": "#8a9baa",
}


class WatchScreen(Screen):
    BINDINGS = [
        ("q", "app.quit", "Sair"),
        ("escape", "app.pop_screen", "Voltar"),
        ("w", "toggle_watch", "Iniciar/Parar"),
        ("s", "manual_scan", "Scan"),
        ("enter", "details", "Detalhes"),
        ("x", "suppress", "Suprimir"),
        ("a", "review_selected", "Revisão IA"),
        ("r", "refresh_view", "Atualizar"),
    ]

    def __init__(
        self, project: Path, database: Database | None = None,
        ai_enabled: bool = False, ai_model: str | None = None,
    ) -> None:
        super().__init__()
        self.project = project.resolve()
        self.database = database or Database()
        self.current_view = "overview"
        self.visible_findings: list[CodeFinding] = []
        self._last_render_key: tuple | None = None
        self.watchdog = CodeWatchdog(
            self.project, self.database, on_update=self._watchdog_update,
            ai_enabled=ai_enabled, ai_model=ai_model,
        )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="watch-layout"):
            with Vertical(id="watch-sidebar"):
                yield Static("/\\  ATLAS\nMONITOR DE CÓDIGO", id="watch-brand")
                yield ListView(*(ListItem(Label(label)) for _, label in MENU), id="watch-menu")
                yield Static("LOCAL · SEM ENVIO DE DADOS", id="local-mode")
            yield VerticalScroll(id="watch-content")
        yield Footer()

    def on_mount(self) -> None:
        menu = self.query_one("#watch-menu", ListView)
        menu.index = 0
        menu.focus()
        self.call_after_refresh(self.show_view)
        self.watchdog.start(initial_scan=True)
        self.set_interval(1.0, self._tick)

    def on_unmount(self) -> None:
        self.watchdog.stop()

    def _watchdog_update(self, _state: WatchState) -> None:
        try:
            self.app.call_from_thread(self._refresh_if_needed)
        except RuntimeError:
            pass

    def _refresh_if_needed(self) -> None:
        if self.current_view in MENU_KEYS:
            self.call_after_refresh(self.show_view)

    def _tick(self) -> None:
        if self.current_view in {"overview", "watchdog", "scan"}:
            key = self._state_key()
            if key != self._last_render_key:
                self.call_after_refresh(self.show_view)

    def _state_key(self) -> tuple:
        state = self.watchdog.state
        return (
            self.current_view, state.status, state.scan_scope, state.files_analyzed, state.files_skipped_large, state.changes,
            state.last_scan_at, tuple((item.name, item.available) for item in state.availability),
            tuple(item.id for item in state.new),
            tuple(item.id for item in state.resolved), tuple(item.name for item in state.availability),
        )

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.current_view = MENU_KEYS[event.list_view.index or 0]
        await self.show_view()

    async def action_refresh_view(self) -> None:
        await self.show_view()

    def action_manual_scan(self) -> None:
        self.run_worker(lambda: self.watchdog.scan_now(None), thread=True, exclusive=True)

    def action_toggle_watch(self) -> None:
        observer = self.watchdog._observer
        if observer and observer.is_alive():
            self.run_worker(self.watchdog.stop, thread=True, exclusive=True)
        else:
            self.run_worker(lambda: self.watchdog.start(initial_scan=False), thread=True, exclusive=True)

    def _selected_finding(self) -> CodeFinding | None:
        if not self.visible_findings:
            return None
        try:
            row = self.query(DataTable).first().cursor_row
        except Exception:
            return None
        if 0 <= row < len(self.visible_findings):
            return self.visible_findings[row]
        return None

    async def action_details(self) -> None:
        item = self._selected_finding()
        if item is None:
            self.notify("Selecione um finding primeiro", severity="information")
            return
        body = self.query_one("#watch-content", VerticalScroll)
        await body.remove_children()
        await body.mount(Static("DETALHES DO FINDING", classes="watch-title"))
        await body.mount(Static(
            f"[{SEVERITY_STYLE.get(item.severity, '')}]{item.severity}[/] · {item.state}\n\n"
            f"[b]Scanner[/b] {item.scanner}\n[b]Regra[/b] {item.rule_id}\n"
            f"[b]Categoria[/b] {item.category} · [b]Confiança heurística[/b] "
            f"{'ALTA' if item.confidence >= 80 else 'MÉDIA' if item.confidence >= 50 else 'BAIXA'} ({item.confidence}%)\n"
            + (f"[b]Supressão[/b] {item.suppression_reason}\n" if item.suppressed else "")
            + f"[b]Arquivo[/b] {self._relative(item.file_path)}:{item.line or '-'}\n\n"
            f"[b]Descrição[/b]\n{item.description}\n\n[b]Evidência[/b]\n{item.evidence}\n\n"
            f"[b]Recomendação[/b]\n{item.recommendation}", classes="watch-panel",
        ))

    def action_suppress(self) -> None:
        item = self._selected_finding()
        if item is None:
            self.notify("Selecione um finding primeiro", severity="information")
            return
        self.app.push_screen(SuppressionModal([item]), self._apply_suppression)

    def _apply_suppression(self, result) -> None:
        if not result:
            return
        item = result["finding"]
        settings = Settings.load()
        add_suppression(settings, item.fingerprint, result["reason"], result["days"])
        settings.save()
        self.database.apply_suppression(item.fingerprint, result["reason"])
        self.notify(f"Finding suprimido por {result['days']} dia(s).", severity="information")
        self.call_after_refresh(self.show_view)

    def action_review_selected(self) -> None:
        if not self.watchdog.ai_enabled:
            self.notify("Inicie com --ai para habilitar revisões locais explícitas", severity="warning")
            return
        item = self._selected_finding()
        if item is None:
            self.notify("Selecione um finding primeiro", severity="information")
            return

        def review() -> None:
            try:
                status = self.watchdog.review_finding_with_ai(item)
                message = status.detail
            except Exception as exc:
                message = f"Revisão indisponível: {type(exc).__name__}"
            self.app.call_from_thread(self.notify, message[:400], severity="information")

        self.run_worker(review, thread=True, exclusive=True)

    async def show_view(self) -> None:
        self._last_render_key = self._state_key()
        body = self.query_one("#watch-content", VerticalScroll)
        await body.remove_children()
        title = dict(MENU).get(self.current_view, self.current_view)
        await body.mount(Static(title.upper(), classes="watch-title"))
        renderer = getattr(self, f"_render_{self.current_view}")
        for widget in renderer():
            await body.mount(widget)

    def _relative(self, value: str) -> str:
        try:
            return str(Path(value).resolve().relative_to(self.project))
        except (OSError, ValueError):
            return Path(value).name

    def _status(self) -> str:
        status = self.watchdog.state.status
        partial = bool(
            self.watchdog.state.files_skipped_large
            or self.watchdog.state.health not in {"COMPLETE", "UNKNOWN"}
            or any(not item.available and item.status != "NOT_APPLICABLE"
                   for item in self.watchdog.state.availability)
        )
        labels = {
            "WATCHING": "● MONITORANDO", "SCANNING": "● ANALISANDO",
            "SAFE": (
                "⚠ SEM FINDINGS · COBERTURA PARCIAL" if partial else
                "● SEM FINDINGS NO ESCOPO ALTERADO" if self.watchdog.state.scan_scope == "INCREMENTAL" else
                "● SEM FINDINGS · SCAN COMPLETO"
            ),
            "FINDINGS": "⚠ FINDINGS", "STOPPED": "○ PARADO", "ERROR": "⚠ ERRO", "STARTING": "● INICIANDO",
        }
        return labels.get(status, status)

    def _age(self) -> str:
        last = self.watchdog.state.last_scan_at
        if not last:
            return "nunca"
        seconds = max(0, int((datetime.now(UTC) - last).total_seconds()))
        return f"{seconds} segundo(s) atrás"

    def _render_overview(self):
        state = self.watchdog.state
        active = [item for item in self.database.code_findings(str(self.project)) if item.state != "RESOLVED"]
        return [
            Static(
                f"[b cyan]ATLAS MONITOR DE CÓDIGO[/b cyan]             [b]{self._status()}[/b]\n\n"
                f"[b]Monitorando[/b]\n{self.project}\n\n"
                f"Escopo do scan: {state.scan_scope.lower()}\n"
                f"Saúde do scan: {state.health}\n"
                f"Arquivos analisados: {state.files_analyzed}    Alterações: {state.changes}    Findings ativos: {len(active)}\n"
                f"Findings não verificados: {len(self.database.code_findings(str(self.project), 'UNVERIFIED'))}\n"
                f"Lacunas de cobertura: {state.files_skipped_large} arquivo(s) grandes, {state.files_skipped_unreadable} inacessíveis, "
                f"{sum(item.status in {'NOT_INSTALLED', 'FAILED', 'PARTIAL', 'TIMEOUT', 'CANCELLED', 'SKIPPED'} for item in state.availability)} scanner(es)\n"
                "Teclas: W monitorar · S scan · Enter detalhes · X suprimir · A revisar com IA (com --ai)\n"
                f"Último scan: {self._age()}", classes="watch-panel",
            ),
            *self._finding_widgets(self.database.code_findings(str(self.project), "NEW", 8), "NOVOS FINDINGS"),
            *self._finding_widgets(self.database.code_findings(str(self.project), "RESOLVED", 5), "RESOLVIDOS RECENTES"),
        ]

    def _render_watchdog(self):
        state = self.watchdog.state
        tools = "\n".join(
            f"{item.name}: {item.status} · {item.duration_seconds:.2f}s · {item.scope or 'n/d'}"
            + (f"\nInstalação: {item.install}" if item.status == "NOT_INSTALLED" else "")
            + (f"\nMotivo: {item.reason or item.detail}" if item.status in {"FAILED", "PARTIAL", "TIMEOUT", "SKIPPED"} else "")
            for item in state.availability
        )
        return [Static(
            f"[b]Status[/b] {self._status()}\n[b]Saúde do scan[/b] {state.health}\n[b]Caminho[/b] {self.project}\n"
            f"[b]Debounce[/b] {self.watchdog.debounce_seconds:.1f}s\n[b]Último scan[/b] {self._age()}\n"
            f"[b]Omitidos (>2 MB)[/b] {state.files_skipped_large}\n\n"
            f"[b]Inacessíveis[/b] {state.files_skipped_unreadable}\n\n"
            f"[b]Execuções dos scanners[/b]\n{tools or 'Nenhuma execução de scanner registrada.'}", classes="watch-panel",
        )]

    def _finding_widgets(self, findings: list[CodeFinding], title: str):
        self.visible_findings = findings
        if not findings:
            return [Static(f"[b]{title}[/b]\nNenhum", classes="watch-panel")]
        table = DataTable(zebra_stripes=True, classes="watch-panel")
        table.cursor_type = "row"
        table.add_columns("Estado", "Severidade", "Confiança est.", "Categoria", "Arquivo", "Linha", "Descrição", "Scanner")
        for item in findings:
            table.add_row(
                item.state, f"[{SEVERITY_STYLE.get(item.severity, '')}]{item.severity}[/]", f"{item.confidence}%", item.category,
                self._relative(item.file_path), str(item.line or "-"), item.description, item.scanner,
            )
        return [Static(f"[b]{title}[/b]", classes="watch-section"), table]

    def _render_new_findings(self):
        return self._finding_widgets(self.database.code_findings(str(self.project), "NEW"), "NOVOS FINDINGS")

    def _render_all_findings(self):
        items = [item for item in self.database.code_findings(str(self.project)) if item.state != "RESOLVED"]
        return self._finding_widgets(items, "TODOS OS FINDINGS ATIVOS")

    def _render_resolved(self):
        return self._finding_widgets(self.database.code_findings(str(self.project), "RESOLVED"), "RESOLVIDOS")

    def _render_scan(self):
        scan = self.database.latest_code_scan(str(self.project))
        detail = "Nenhum scan registrado ainda. Pressione S para executar."
        if scan:
            detail = (
                f"Status: {scan.status}\nArquivos analisados: {scan.files_analyzed}\nAlterações: {scan.changes}\n"
                f"Saúde do scan: {scan.health}\n"
                f"Escopo: {'incremental' if scan.trigger_file else 'completo'}\n"
                f"Arquivos omitidos (>2 MB): {scan.files_skipped_large}\n"
                f"Arquivos/diretórios inacessíveis: {scan.files_skipped_unreadable}\n"
                f"Concluído: {scan.completed_at.astimezone():%d/%m/%Y %H:%M:%S}" if scan.completed_at else "Analisando agora..."
            )
        return [Static(detail + "\n\nPressione [b]S[/b] para um scan manual completo.", classes="watch-panel")]

    def _render_settings(self):
        return [Static(
            "[b]Modo[/b] Somente scanners locais\n[b]IA[/b] Desativada\n[b]Read-only[/b] Sim\n"
            "[b]Ignorados[/b] .git, node_modules, venv, .venv, __pycache__, _pycache_, dist, build\n"
            "[b]Banco[/b] Banco SQLite ATLAS por usuário\n"
            "[b]Supressão[/b] Tecla X no finding selecionado", classes="watch-panel",
        )]


class WatchdogApp(App):
    TITLE = "ATLAS · MONITOR DE CÓDIGO"
    CSS = """
    Screen { background: #000000; color: #e8e8e8; }
    #watch-layout { height: 1fr; }
    #watch-sidebar { width: 25; background: #000000; border-right: solid #7a7a7a; }
    #watch-brand { height: 5; padding: 1 2; color: #f0f0f0; text-style: bold; }
    #watch-menu { height: 1fr; background: transparent; border: none; }
    ListItem { padding: 0 2; height: 3; }
    ListItem.--highlight { background: #f0f0f0; color: #080808; border-left: thick #ffffff; }
    #local-mode { height: 3; content-align: center middle; color: #d0d0d0; text-style: bold; }
    #watch-content { padding: 1 2; }
    .watch-title { height: 3; color: #f0f0f0; text-style: bold; }
    .watch-section { height: 2; color: #d8d8d8; }
    .watch-panel { background: #080808; border: solid #7a7a7a; padding: 1 2; margin-bottom: 1; }
    DataTable { min-height: 8; }
    """

    def __init__(
        self, project: Path, database: Database | None = None,
        ai_enabled: bool = False, ai_model: str | None = None,
    ) -> None:
        super().__init__()
        self.project = project
        self.database = database
        self.ai_enabled = ai_enabled
        self.ai_model = ai_model

    def on_mount(self) -> None:
        self.push_screen(WatchScreen(self.project, self.database, self.ai_enabled, self.ai_model))


def run_watch_tui(project: Path, ai_enabled: bool = False, ai_model: str | None = None) -> None:
    WatchdogApp(project, ai_enabled=ai_enabled, ai_model=ai_model).run()


class MultiWatchScreen(Screen):
    """Agregated read-only view for all configured project Watchdogs."""

    BINDINGS = [("q", "app.quit", "Sair"), ("w", "toggle_watch", "Iniciar/Parar"), ("s", "manual_scan", "Scan"), ("r", "refresh_view", "Atualizar")]

    def __init__(
        self, projects: list[Path], database: Database | None = None,
        ai_enabled: bool = False, ai_model: str | None = None,
    ) -> None:
        super().__init__()
        self.database = database or Database()
        self.manager = MultiProjectWatchdog(
            projects, self.database, ai_enabled=ai_enabled, ai_model=ai_model,
        )
        self._last_render_key: tuple | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield VerticalScroll(id="multi-watch-content")
        yield Footer()

    def on_mount(self) -> None:
        self.manager.start(initial_scan=True)
        self.set_interval(1.0, self.refresh_view)
        self.call_after_refresh(self.refresh_view)

    def on_unmount(self) -> None:
        self.manager.stop()

    async def action_toggle_watch(self) -> None:
        active = any(watcher._observer and watcher._observer.is_alive() for watcher in self.manager.watchdogs.values())
        if active:
            self.manager.stop()
        else:
            self.manager.start(initial_scan=False)
        await self.refresh_view()

    def action_manual_scan(self) -> None:
        self.run_worker(self.manager.scan_now, thread=True, exclusive=True)

    async def refresh_view(self) -> None:
        rows = [(project, watcher.state) for project, watcher in self.manager.watchdogs.items()]
        key = tuple(
            (str(project), state.status, state.files_analyzed, state.files_skipped_large, state.changes, state.last_scan_at,
             tuple(item.id for item in state.new), tuple(item.id for item in state.resolved))
            for project, state in rows
        )
        if key == self._last_render_key:
            return
        self._last_render_key = key
        body = self.query_one("#multi-watch-content", VerticalScroll)
        await body.remove_children()
        total_new = 0
        for _, state in rows:
            total_new += len(state.new)
        gaps = sum(bool(state.files_skipped_large or any(not item.available for item in state.availability))
                   for _, state in rows)
        status = "⚠ FINDINGS" if total_new else ("⚠ COBERTURA PARCIAL" if gaps else "● MONITORANDO")
        await body.mount(Static(
            f"[b cyan]ATLAS MONITOR MULTI-PROJETO[/b cyan]   [b]{status}[/b]\n\n"
            f"Projetos: {len(rows)}    Findings novos: {total_new}    Projetos com cobertura parcial: {gaps}\n"
            "Todas as análises são locais e read-only.", classes="watch-panel",
        ))
        table = DataTable(zebra_stripes=True, classes="watch-panel")
        table.add_columns("Projeto", "Status", "Arquivos", "Omitidos >2MB", "Alterações", "Novos", "Último scan")
        for project, state in rows:
            last = state.last_scan_at.astimezone().strftime("%d/%m/%Y %H:%M:%S") if state.last_scan_at else "-"
            table.add_row(project.name, state.status, str(state.files_analyzed), str(state.files_skipped_large),
                          str(state.changes), str(len(state.new)), last)
        await body.mount(table)
        findings = [item for _, state in rows for item in state.new]
        if findings:
            await body.mount(Static("[b]NOVOS FINDINGS[/b]", classes="watch-section"))
            finding_table = DataTable(zebra_stripes=True, classes="watch-panel")
            finding_table.add_columns("Severidade", "Arquivo", "Descrição", "Scanner")
            for item in findings[:100]:
                finding_table.add_row(item.severity, Path(item.file_path).name + f":{item.line or '-'}", item.description, item.scanner)
            await body.mount(finding_table)


class MultiWatchApp(App):
    TITLE = "ATLAS · MONITOR MULTI-PROJETO"
    CSS = WatchdogApp.CSS

    def __init__(self, projects: list[Path], ai_enabled: bool = False, ai_model: str | None = None) -> None:
        super().__init__()
        self.projects = projects
        self.ai_enabled = ai_enabled
        self.ai_model = ai_model

    def on_mount(self) -> None:
        self.push_screen(MultiWatchScreen(self.projects, ai_enabled=self.ai_enabled, ai_model=self.ai_model))


def run_multi_watch_tui(projects: list[Path], ai_enabled: bool = False, ai_model: str | None = None) -> None:
    MultiWatchApp(projects, ai_enabled=ai_enabled, ai_model=ai_model).run()
