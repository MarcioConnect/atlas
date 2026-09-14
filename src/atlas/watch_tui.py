from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Label, ListItem, ListView, Static

from atlas.code_watch import CodeWatchdog, WatchState
from atlas.database import Database
from atlas.models import CodeFinding
from atlas.multi_watch import MultiProjectWatchdog

MENU = ["Overview", "Watchdog", "New Findings", "All Findings", "Resolved", "Scan", "Settings"]
SEVERITY_STYLE = {
    "CRITICAL": "bold white on #b42318", "HIGH": "bold #ff5f5f", "MEDIUM": "bold #f5c451",
    "LOW": "#6bdcff", "INFO": "#8a9baa",
}


class WatchScreen(Screen):
    BINDINGS = [
        ("q", "app.quit", "Quit"),
        ("escape", "app.pop_screen", "Back"),
        ("w", "toggle_watch", "Start/Stop"),
        ("s", "manual_scan", "Scan"),
        ("enter", "details", "Details"),
        ("r", "refresh_view", "Refresh"),
    ]

    def __init__(
        self, project: Path, database: Database | None = None,
        ai_enabled: bool = False, ai_model: str | None = None,
    ) -> None:
        super().__init__()
        self.project = project.resolve()
        self.database = database or Database()
        self.current_view = "Overview"
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
                yield Static("/\\  ATLAS\nSECURITY WATCHDOG", id="watch-brand")
                yield ListView(*(ListItem(Label(name)) for name in MENU), id="watch-menu")
                yield Static("LOCAL · NO AI TOKENS", id="local-mode")
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
        if self.current_view in MENU:
            self.call_after_refresh(self.show_view)

    def _tick(self) -> None:
        if self.current_view in {"Overview", "Watchdog", "Scan"}:
            key = self._state_key()
            if key != self._last_render_key:
                self.call_after_refresh(self.show_view)

    def _state_key(self) -> tuple:
        state = self.watchdog.state
        return (
            self.current_view, state.status, state.files_analyzed, state.changes,
            state.last_scan_at, tuple(item.id for item in state.new),
            tuple(item.id for item in state.resolved), tuple(item.name for item in state.availability),
        )

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.current_view = MENU[event.list_view.index or 0]
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

    async def action_details(self) -> None:
        if not self.visible_findings:
            self.notify("No finding selected", severity="information")
            return
        try:
            row = self.query(DataTable).first().cursor_row
            item = self.visible_findings[row]
        except Exception:
            self.notify("Select a finding first", severity="information")
            return
        body = self.query_one("#watch-content", VerticalScroll)
        await body.remove_children()
        await body.mount(Static("FINDING DETAILS", classes="watch-title"))
        await body.mount(Static(
            f"[{SEVERITY_STYLE.get(item.severity, '')}]{item.severity}[/] · {item.state}\n\n"
            f"[b]Scanner[/b] {item.scanner}\n[b]Rule[/b] {item.rule_id}\n"
            f"[b]File[/b] {self._relative(item.file_path)}:{item.line or '-'}\n\n"
            f"[b]Description[/b]\n{item.description}\n\n[b]Evidence[/b]\n{item.evidence}\n\n"
            f"[b]Recommendation[/b]\n{item.recommendation}", classes="watch-panel",
        ))

    async def show_view(self) -> None:
        self._last_render_key = self._state_key()
        body = self.query_one("#watch-content", VerticalScroll)
        await body.remove_children()
        await body.mount(Static(self.current_view.upper(), classes="watch-title"))
        renderer = getattr(self, f"_render_{self.current_view.lower().replace(' ', '_')}")
        for widget in renderer():
            await body.mount(widget)

    def _relative(self, value: str) -> str:
        try:
            return str(Path(value).resolve().relative_to(self.project))
        except (OSError, ValueError):
            return Path(value).name

    def _status(self) -> str:
        status = self.watchdog.state.status
        labels = {
            "WATCHING": "● WATCHING", "SCANNING": "● SCANNING", "SAFE": "● SAFE",
            "FINDINGS": "⚠ FINDINGS", "STOPPED": "○ STOPPED", "ERROR": "⚠ ERROR", "STARTING": "● STARTING",
        }
        return labels.get(status, status)

    def _age(self) -> str:
        last = self.watchdog.state.last_scan_at
        if not last:
            return "never"
        seconds = max(0, int((datetime.now(UTC) - last).total_seconds()))
        return f"{seconds} seconds ago" if seconds != 1 else "1 second ago"

    def _render_overview(self):
        state = self.watchdog.state
        active = [item for item in self.database.code_findings(str(self.project)) if item.state != "RESOLVED"]
        return [
            Static(
                f"[b cyan]ATLAS WATCHDOG[/b cyan]                     [b]{self._status()}[/b]\n\n"
                f"[b]Watching[/b]\n{self.project}\n\n"
                f"Files analyzed: {state.files_analyzed}    Changes: {state.changes}    Active findings: {len(active)}\n"
                f"Last scan: {self._age()}", classes="watch-panel",
            ),
            *self._finding_widgets(self.database.code_findings(str(self.project), "NEW", 8), "NEW FINDINGS"),
            *self._finding_widgets(self.database.code_findings(str(self.project), "RESOLVED", 5), "RECENTLY RESOLVED"),
        ]

    def _render_watchdog(self):
        state = self.watchdog.state
        unavailable = [item for item in state.availability if not item.available]
        tools = "\n".join(
            f"Scanner unavailable: {item.name}\nInstall: {item.install}"
            + (f"\nReason: {item.detail}" if item.detail else "")
            for item in unavailable
        )
        return [Static(
            f"[b]Status[/b] {self._status()}\n[b]Path[/b] {self.project}\n"
            f"[b]Debounce[/b] {self.watchdog.debounce_seconds:.1f}s\n[b]Last scan[/b] {self._age()}\n\n"
            f"{tools or 'All configured scanners are available.'}", classes="watch-panel",
        )]

    def _finding_widgets(self, findings: list[CodeFinding], title: str):
        self.visible_findings = findings
        if not findings:
            return [Static(f"[b]{title}[/b]\nNone", classes="watch-panel")]
        table = DataTable(zebra_stripes=True, classes="watch-panel")
        table.cursor_type = "row"
        table.add_columns("State", "Severity", "File", "Line", "Description", "Scanner")
        for item in findings:
            table.add_row(
                item.state, f"[{SEVERITY_STYLE.get(item.severity, '')}]{item.severity}[/]",
                self._relative(item.file_path), str(item.line or "-"), item.description, item.scanner,
            )
        return [Static(f"[b]{title}[/b]", classes="watch-section"), table]

    def _render_new_findings(self):
        return self._finding_widgets(self.database.code_findings(str(self.project), "NEW"), "NEW FINDINGS")

    def _render_all_findings(self):
        items = [item for item in self.database.code_findings(str(self.project)) if item.state != "RESOLVED"]
        return self._finding_widgets(items, "ALL ACTIVE FINDINGS")

    def _render_resolved(self):
        return self._finding_widgets(self.database.code_findings(str(self.project), "RESOLVED"), "RESOLVED")

    def _render_scan(self):
        scan = self.database.latest_code_scan(str(self.project))
        detail = "No scan recorded yet. Press S to run one."
        if scan:
            detail = (
                f"Status: {scan.status}\nFiles analyzed: {scan.files_analyzed}\nChanges: {scan.changes}\n"
                f"Completed: {scan.completed_at.astimezone():%d/%m/%Y %H:%M:%S}" if scan.completed_at else "Scanning now..."
            )
        return [Static(detail + "\n\nPress [b]S[/b] for a full manual scan.", classes="watch-panel")]

    def _render_settings(self):
        return [Static(
            "[b]Mode[/b] Local scanners only\n[b]AI[/b] Disabled\n[b]Read-only[/b] Yes\n"
            "[b]Ignored[/b] .git, node_modules, venv, .venv, __pycache__, _pycache_, dist, build\n"
            "[b]Database[/b] Per-user ATLAS SQLite database", classes="watch-panel",
        )]


class WatchdogApp(App):
    TITLE = "ATLAS · SECURITY WATCHDOG"
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
    """Aggregated read-only view for all configured project Watchdogs."""

    BINDINGS = [("q", "app.quit", "Quit"), ("w", "toggle_watch", "Start/Stop"), ("s", "manual_scan", "Scan"), ("r", "refresh_view", "Refresh")]

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
            (str(project), state.status, state.files_analyzed, state.changes, state.last_scan_at,
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
        status = "⚠ FINDINGS" if total_new else "● WATCHING"
        await body.mount(Static(
            f"[b cyan]ATLAS MULTI-PROJECT WATCHDOG[/b cyan]   [b]{status}[/b]\n\n"
            f"Projetos: {len(rows)}    Findings novos: {total_new}\n"
            "Todas as análises são locais e read-only.", classes="watch-panel",
        ))
        table = DataTable(zebra_stripes=True, classes="watch-panel")
        table.add_columns("Projeto", "Status", "Arquivos", "Alterações", "Novos", "Último scan")
        for project, state in rows:
            last = state.last_scan_at.astimezone().strftime("%d/%m/%Y %H:%M:%S") if state.last_scan_at else "-"
            table.add_row(project.name, state.status, str(state.files_analyzed), str(state.changes), str(len(state.new)), last)
        await body.mount(table)
        findings = [item for _, state in rows for item in state.new]
        if findings:
            await body.mount(Static("[b]NEW FINDINGS[/b]", classes="watch-section"))
            finding_table = DataTable(zebra_stripes=True, classes="watch-panel")
            finding_table.add_columns("Severity", "Arquivo", "Descrição", "Scanner")
            for item in findings[:100]:
                finding_table.add_row(item.severity, Path(item.file_path).name + f":{item.line or '-'}", item.description, item.scanner)
            await body.mount(finding_table)


class MultiWatchApp(App):
    TITLE = "ATLAS · MULTI-PROJECT WATCHDOG"
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
