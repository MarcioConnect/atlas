from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from rich.text import Text
from sqlalchemy import desc, select
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Footer, Input, RichLog, Static

from atlas import __version__
from atlas.assistant import AssistantReply, ProjectAssistant
from atlas.code_watch import CodeWatchdog
from atlas.config import Settings
from atlas.database import Database
from atlas.models import CodeScan
from atlas.privacy import sanitize_text
from atlas.report import generate_markdown_report
from atlas.security import redact
from atlas.terminal_art import AtlasPortrait, AtlasWordmark


class AtlasPanel(App):
    TITLE = "ATLAS | Security Agent"
    BINDINGS = [("ctrl+q", "quit", "Sair"), ("ctrl+s", "scan", "Scan"),
                ("ctrl+r", "report", "Relatório"), ("ctrl+w", "watch", "Watch")]
    CSS = """
    Screen { background: #000000; color: #d4d4d4; }
    Static, RichLog, DataTable { background: #000000; }
    DataTable > .datatable--header { background: #000000; color: #808080; text-style: none; }
    DataTable > .datatable--cursor { background: #e4e4e4; color: #000000; }
    DataTable > .datatable--hover { background: #181818; color: #ffffff; }
    #top { height: 2; border-bottom: solid #444444; color: #bdbdbd; padding: 0 1; }
    #layout { height: 1fr; }
    #nav { width: 22; padding: 1; border-right: solid #444444; }
    #nav-brand { height: 4; color: #ffffff; text-style: bold; content-align: left middle; }
    #nav-note { height: 1fr; content-align: left bottom; color: #707070; }
    Button { background: #000000; color: #c5c5c5; border: none; height: 3; width: 100%; margin-bottom: 1; content-align: left middle; padding: 0 1; text-style: none; }
    Button:hover { background: #181818; color: #ffffff; }
    Button:focus, Button.selected { background: #e4e4e4; color: #000000; text-style: bold; }
    #workspace { padding: 0 1; }
    .row { height: 1fr; min-height: 10; }
    #work-row { min-height: 15; }
    #banner-row { height: 1.8fr; min-height: 16; max-height: 22; }
    .box { background: #000000; border: solid #444444; border-title-color: #bdbdbd; border-title-style: none; padding: 1; margin: 0 1 1 0; }
    #hero { width: 2fr; height: 100%; }
    #wordmark { width: 1fr; content-align: center middle; color: #ffffff; }
    #portrait { width: 50%; height: 100%; color: #d4d4d4; }
    #hero { padding: 0 1; }
    #overview { width: 1fr; height: 100%; }
    #scans { width: 2fr; height: 100%; }
    #severity { width: 1fr; height: 100%; }
    #activity { width: 2fr; height: 100%; }
    #actions { width: 1fr; height: 100%; }
    #actions Button { height: 2; margin: 0; }
    #details { height: auto; max-height: 9; color: #909090; }
    #chat { height: 3; border: solid #444444; border-title-color: #bdbdbd; }
    #chat.expanded { height: 9; }
    Input { background: #000000; color: #ffffff; border: solid #444444; }
    Input:focus { background: #080808; border: solid #c5c5c5; }
    Input > .input--placeholder { color: #707070; }
    #command { dock: bottom; }
    #directory { height: 3; display: none; }
    #directory.visible { display: block; }
    #ai-status { height: 1; color: #909090; padding: 0 1; }
    Footer { background: #000000; color: #808080; }
    FooterKey { background: #000000; color: #a0a0a0; }
    FooterKey > .footer-key--key { background: #000000; color: #ffffff; }
    FooterKey:hover { background: #181818; }
    * { scrollbar-background: #000000; scrollbar-color: #444444; scrollbar-color-hover: #808080; scrollbar-color-active: #bdbdbd; }
    Screen.compact #portrait { width: 44%; }
    Screen.compact #nav { width: 18; }
    Screen.compact #actions { padding: 0 1; }
    Screen.compact #actions Button { height: 1; min-height: 1; }
    Screen.compact .row { min-height: 8; }
    Screen.compact #work-row { min-height: 9; }
    Screen.compact #banner-row { height: 11; min-height: 11; max-height: 11; }
    Screen.compact #nav-brand { height: 2; }
    Screen.compact #nav Button { height: 2; }
    .hidden { display: none; }
    """

    def __init__(self, database: Database | None = None, project: Path | None = None, model: str | None = None):
        super().__init__()
        self.database = database or Database()
        self.project = (project or Path.cwd()).resolve()
        self.model = model
        self.watchdog = CodeWatchdog(self.project, self.database, ai_enabled=Settings.load().ai_review_enabled, ai_model=model)
        self.assistant = ProjectAssistant(self.project, self.database, model=model)
        self.last_context: dict = {}
        self.watch_transition = False
        self.busy = False
        self.chat_busy = False
        self._scans_key = None
        self._activity_key = None

    def compose(self) -> ComposeResult:
        yield Static(f" ATLAS v{__version__}  |  Security Agent", id="top")
        with Horizontal(id="layout"):
            with Vertical(id="nav"):
                yield Static("/\\  A T L A S", id="nav-brand")
                for key, label in [("home", "⌂  Início"), ("scan", "⌕  Scan"), ("report", "▤  Relatórios"),
                                   ("history", "◷  Histórico"), ("settings", "⚙  Ajustes"),
                                   ("tools", "◇  Ferramentas"), ("help", "?  Ajuda"), ("exit", "↪  Sair")]:
                    yield Button(label, id=f"nav-{key}")
                yield Static("LOCAL FIRST\n\nSeus arquivos.\nSeu controle.\n\nSecurity Agent", id="nav-note")
            with VerticalScroll(id="workspace"):
                yield Input(str(self.project), placeholder="Diretório do projeto — Enter para selecionar", id="directory")
                with Horizontal(classes="row", id="banner-row"):
                    with Horizontal(id="hero", classes="box"):
                        yield AtlasWordmark(id="wordmark")
                        yield AtlasPortrait(id="portrait")
                    yield Static(id="overview", classes="box", markup=False)
                with Horizontal(classes="row"):
                    yield DataTable(id="scans", classes="box", cursor_type="row")
                    yield Static(id="severity", classes="box", markup=False)
                with Horizontal(classes="row", id="work-row"):
                    yield RichLog(id="activity", classes="box", markup=False, wrap=True)
                    with Vertical(id="actions", classes="box"):
                        for key, label in [("scan", "▷ Iniciar scan"), ("watch", "◉ Iniciar / parar Watch"),
                                           ("directory", "□ Selecionar diretório"), ("report", "▤ Gerar relatório"),
                                           ("refresh", "↻ Atualizar")]:
                            yield Button(label, id=f"quick-{key}")
                yield Static("Painel pronto. Selecione um projeto para analisar.", id="details", markup=False)
                yield RichLog(id="chat", markup=False, wrap=True)
        yield Input(placeholder="Pergunte ao ATLAS ou use /scan /watch /report /help", id="command")
        yield Static("Ollama: verificando serviço local…", id="ai-status", markup=False)
        yield Footer()

    def on_mount(self):
        for widget, title in {"hero": " ATLAS / SECURITY AGENT ", "overview": " VISÃO GERAL ",
                              "scans": " ÚLTIMOS SCANS ", "severity": " SEVERIDADE ",
                              "activity": " ATIVIDADE EM TEMPO REAL ", "actions": " AÇÕES RÁPIDAS ",
                              "chat": " ATLAS / ASSISTENTE LOCAL "}.items():
            self.query_one("#" + widget).border_title = title
        self.query_one("#nav-home").add_class("selected")
        self.query_one("#scans", DataTable).add_columns("#", "DATA/HORA", "DIRETÓRIO", "STATUS")
        self.query_one("#chat", RichLog).write("ATLAS integrado ao painel. Respostas locais disponíveis.")
        self.refresh_data()
        self.set_interval(2, self.refresh_data)
        self.run_worker(self._check_ai, thread=True)
        self.set_interval(30, lambda: self.run_worker(self._check_ai, thread=True, group="ai-status", exclusive=True))

    def on_resize(self, event):
        self.screen.set_class(event.size.width < 130, "compact")

    def _check_ai(self):
        from atlas.ollama_ai import OllamaReviewer, ensure_local_service

        ensure_local_service()
        status = OllamaReviewer(self.project, self.model or Settings.load().ollama_model, timeout=3).availability()
        self.call_from_thread(self.query_one("#ai-status", Static).update, status.detail)

    def on_unmount(self):
        self.watchdog.stop()

    def refresh_data(self):
        with self.database.session() as db:
            scans = list(db.scalars(select(CodeScan).order_by(desc(CodeScan.id)).limit(8)))
        table = self.query_one("#scans", DataTable)
        scans_key = tuple((scan.id, scan.status, scan.files_analyzed) for scan in scans)
        if scans_key != self._scans_key:
            table.clear()
            for scan in scans:
                table.add_row(str(scan.id), scan.started_at.astimezone().strftime("%d/%m %H:%M"),
                              redact(scan.project_path), scan.status, key=str(scan.id))
            self._scans_key = scans_key
        findings = [f for f in self.database.code_findings(str(self.project)) if f.state != "RESOLVED"]
        current_scan = self.database.latest_code_scan(str(self.project))
        counts = Counter(f.severity for f in findings)
        severity = Text()
        maximum = max(counts.values(), default=1) or 1
        bar_width = max(3, min(16, self.query_one("#severity").content_size.width - 19))
        for level, label, color in [("CRITICAL", "Crítico", "#ff5555"), ("HIGH", "Alto", "#ff9852"),
                                     ("MEDIUM", "Médio", "#f4cc55"), ("LOW", "Baixo", "#62baff"),
                                     ("INFO", "Informação", "#96a9ba")]:
            filled = round(bar_width * counts[level] / maximum)
            severity.append(f"● {label:<10} {counts[level]:>4}  ", style=color)
            severity.append("━" * filled, style=color)
            severity.append("─" * (bar_width - filled) + "\n", style="#263b4a")
        self.query_one("#severity", Static).update(severity)
        self.query_one("#overview", Static).update(
            f"Projeto: {self.project.name}\n\n"
            f"Arquivos no último scan: {current_scan.files_analyzed if current_scan else 0}\n"
            f"Findings ativos: {len(findings)}\n\nWatch: {self.watchdog.state.status}\n"
            f"Revisão IA: {'ATIVA' if self.watchdog.ai_enabled else 'DESLIGADA'}\n"
            + (f"Último scan: {current_scan.started_at.astimezone():%d/%m %H:%M}" if current_scan else
               "Sem scan registrado neste projeto."))
        log = self.query_one("#activity", RichLog)
        events = self.database.recent_monitor_events(10)
        activity_key = tuple(event.id for event in events)
        if activity_key != self._activity_key:
            log.clear()
            for event in reversed(events):
                log.write(redact(f"{event.created_at.astimezone():%H:%M:%S} [{event.severity}] {event.kind}: {event.detail}"))
            self._activity_key = activity_key
        self.query_one("#top", Static).update(f" ATLAS v{__version__} | Security Agent    {datetime.now(UTC).astimezone():%d/%m/%Y %H:%M:%S} | LOCAL")

    def status(self, text: str):
        self.query_one("#details", Static).update(redact(text))

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id != "scans":
            return
        with self.database.session() as db:
            scan = db.get(CodeScan, int(str(event.row_key.value)))
        if scan is None:
            return
        findings = self.database.code_findings(scan.project_path)
        active = [item for item in findings if item.state != "RESOLVED"]
        self.status("Findings atuais do projeto (não snapshot histórico):\n" + ("\n\n".join(
            f"{item.severity} · {item.scanner} · {Path(item.file_path).name}:{item.line or '-'}\n"
            f"{item.description}\n{item.recommendation}" for item in active[:30]) or "Nenhum finding ativo."))
        self.query_one("#details").scroll_visible()

    def on_button_pressed(self, event: Button.Pressed):
        if (event.button.id or "").startswith("nav-"):
            for button in self.query("#nav Button"):
                button.set_class(button is event.button, "selected")
        key = (event.button.id or "").split("-", 1)[-1]
        if key == "exit":
            self.exit()
        elif key in {"scan", "report", "watch"}:
            getattr(self, f"action_{key}")()
        elif key in {"directory", "settings"}:
            self.query_one("#directory", Input).add_class("visible")
            self.query_one("#directory", Input).focus()
            self.status("Edite o diretório acima e pressione Enter. As configurações ficam salvas para o Watch.")
        elif key == "history":
            self.query_one("#scans").focus()
            self.query_one("#scans").scroll_visible()
        elif key == "tools":
            self.status("Scanners: " + (", ".join(f"{s.name}: {'disponível' if s.available else 'indisponível'}" for s in self.watchdog.state.availability) or "execute um scan para medir disponibilidade."))
        elif key == "help":
            self.status("Ctrl+S scan · Ctrl+W Watch · Ctrl+R relatório · Ctrl+Q sair. Chat: /scan /watch /report ou perguntas sobre segurança.")
        else:
            if key == "home":
                self.query_one("#directory", Input).remove_class("visible")
                self.status("Projeto: " + str(self.project))
            self.refresh_data()
            self.query_one("#workspace").scroll_home()

    def action_scan(self):
        if self.busy:
            self.status("Scan em andamento.")
            return
        self.busy = True
        self.status("Analisando o projeto…")
        self.run_worker(self._scan, thread=True)

    def _scan(self):
        try:
            self.watchdog.scan_now()
            self.call_from_thread(self.status, f"Scan: {self.watchdog.state.status}. Novos findings: {len(self.watchdog.state.new)}")
        except Exception as exc:
            self.call_from_thread(self.status, "Falha no scan: " + type(exc).__name__ + ". Consulte o histórico e tente novamente.")
        finally:
            self.busy = False

    def action_watch(self):
        if self.watch_transition or self.busy:
            self.status('Aguarde a operação atual do Watch.')
            return
        self.watch_transition = True
        stopping = bool(self.watchdog._observer and self.watchdog._observer.is_alive())
        self.status('Parando Watch…' if stopping else 'Iniciando Watch…')
        self.run_worker(lambda: self._toggle_watch(stopping), thread=True)

    def _toggle_watch(self, stopping):
        try:
            self.watchdog.stop() if stopping else self.watchdog.start()
            message = 'Watch parado.' if stopping else 'Watch ativo para ' + str(self.project)
        except Exception as exc:
            message = 'Falha ao alterar Watch: ' + type(exc).__name__
        self.call_from_thread(self._watch_finished, message)

    def _watch_finished(self, message):
        self.watch_transition = False
        self.status(message)

    def action_report(self):
        self.run_worker(self._report, thread=True, group="report", exclusive=True)

    def _report(self):
        try:
            path = generate_markdown_report(self.database)
            self.call_from_thread(self.status, "Relatório salvo: " + str(path))
        except Exception as exc:
            self.call_from_thread(self.status, "Falha ao gerar relatório: " + type(exc).__name__)

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "directory":
            target = Path(event.value).expanduser().resolve()
            if not target.is_dir():
                self.status("Diretório inexistente.")
                return
            if self.busy or self.chat_busy or self.watch_transition or self.watchdog.state.status == 'SCANNING' or (self.watchdog._observer and self.watchdog._observer.is_alive()):
                self.status("Pare o Watch e aguarde as análises antes de trocar de projeto.")
                return
            self.project = target
            self.watchdog = CodeWatchdog(target, self.database, ai_enabled=Settings.load().ai_review_enabled, ai_model=self.model)
            self.assistant = ProjectAssistant(target, self.database, model=self.model)
            self.last_context = {}
            self.query_one('#chat', RichLog).clear()
            settings = Settings.load()
            settings.watch_paths = sorted(set(settings.watch_paths + [str(target)]))
            settings.save()
            self.status("Projeto selecionado: " + str(target))
            self.query_one("#directory", Input).remove_class("visible")
            return
        question = event.value.strip()
        if not question:
            return
        if self.chat_busy and not question.startswith('/'):
            self.status('Aguarde a resposta atual; sua pergunta foi mantida no campo.')
            return
        event.input.value = ""
        if question in {"/scan", "/watch", "/report"}:
            getattr(self, "action_" + question[1:])()
        elif question == "/help":
            self.query_one("#chat", RichLog).write("/scan · /watch · /report · /context (fontes) · /clear · /ai on · /ai off. Pergunte sobre um arquivo ou função.")
        elif question == '/context':
            self.query_one('#chat', RichLog).add_class('expanded')
            files = self.last_context.get('files', [])
            self.query_one('#chat', RichLog).write('Fontes da última resposta (contexto parcial):\n' +
                ('\n'.join(f"{f['file']}:{f['line_start']}-{f['line_end']}" for f in files) or 'Nenhuma fonte lida ainda.'))
        elif question == '/clear':
            if self.chat_busy:
                self.status('Aguarde a resposta antes de limpar a conversa.')
                return
            self.assistant.clear()
            self.last_context = {}
            self.query_one('#chat', RichLog).clear()
            self.status('Conversa e cache de código apagados da memória.')
        elif question in {'/ai on', '/ai off'}:
            if self.busy or self.watch_transition or self.watchdog.state.status == 'SCANNING' or (self.watchdog._observer and self.watchdog._observer.is_alive()):
                self.status('Pare o Watch e aguarde o scan antes de alterar a revisão IA.')
                return
            enabled = question == '/ai on'
            settings = Settings.load()
            settings.ai_review_enabled = enabled
            settings.save()
            self.watchdog.ai_enabled = enabled
            self.status('Revisão Ollama nos próximos scans: ' + ('ATIVA' if enabled else 'DESLIGADA'))
            self.refresh_data()
        elif question.startswith('/'):
            self.status('Comando desconhecido. Use /help.')
        else:
            self.query_one("#chat", RichLog).add_class("expanded")
            self.query_one("#chat", RichLog).write("Você: " + sanitize_text(question, 2000))
            self.chat_busy = True
            self.status("ATLAS está carregando o modelo e preparando a resposta…")
            self.run_worker(lambda: self._answer(question), thread=True)

    def _answer(self, question: str):
        try:
            reply = self.assistant.ask(question)
        except Exception as exc:
            reply = AssistantReply('Não foi possível ler o projeto. Tente novamente.', {}, False, type(exc).__name__)
        self.call_from_thread(self._finish_answer, reply)

    def _finish_answer(self, reply: AssistantReply):
        self.chat_busy = False
        self.last_context = reply.context
        chat = self.query_one('#chat', RichLog)
        chat.write('ATLAS: ' + sanitize_text(reply.text))
        files = reply.context.get('files', [])
        if files:
            chat.write('Fontes: ' + ', '.join(f"{f['file']}:{f['line_start']}-{f['line_end']}" for f in files))
        count = reply.context.get('files_read', 0)
        mode = 'Resposta IA' if reply.used_ai else 'Sem análise IA'
        self.status(f'{mode}. Contexto parcial: {count} arquivo(s). {reply.detail}')
