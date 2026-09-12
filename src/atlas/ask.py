from __future__ import annotations

import re
from datetime import datetime

from atlas.database import Database
from atlas.models import Severity

SEVERITY_ORDER = {Severity.CRITICAL.value: 0, Severity.HIGH.value: 1, Severity.MEDIUM.value: 2, Severity.LOW.value: 3, Severity.INFO.value: 4}


class LocalAtlasProvider:
    """Rule-based provider; replaceable by an LLM provider later."""

    def __init__(self, database: Database | None = None) -> None:
        self.database = database or Database()

    def answer(self, question: str) -> str:
        normalized = re.sub(r"\s+", " ", question.lower().strip())
        if any(term in normalized for term in ("falha", "vulner", "risco", "seguranca", "segurança")):
            if "mudanca" in normalized or "mudança" in normalized or "alter" in normalized:
                return self._change_risk()
            return self._findings()
        if any(term in normalized for term in ("alterei", "mudei", "mudanca", "mudança", "hoje")):
            return self._today_changes()
        if "nginx" in normalized and any(term in normalized for term in ("reinici", "restart", "quando")):
            return self._nginx_restart()
        if any(term in normalized for term in ("primeiro", "prior", "corrigir", "recomend")):
            return self._priorities()
        return (
            "Posso responder sobre falhas da ultima analise, alteracoes de hoje, risco de mudancas, "
            "reinicios do nginx e prioridades de correcao. Execute `atlas security` para atualizar os dados."
        )

    def _findings(self) -> str:
        scan = self.database.latest_scan()
        if not scan:
            return "Ainda nao existe uma analise. Execute `atlas security`."
        actionable = [item for item in scan.findings if item.severity != Severity.INFO.value]
        if not actionable:
            return f"A ultima analise tem score {scan.score}/100 e nao encontrou falhas acionaveis."
        ordered = sorted(actionable, key=lambda item: SEVERITY_ORDER.get(item.severity, 9))[:5]
        details = "; ".join(f"[{item.severity}] {item.title} ({item.component})" for item in ordered)
        return f"Security Score {scan.score}/100. Principais achados: {details}."

    def _today_changes(self) -> str:
        today = datetime.now().astimezone().date()
        events = [event for event in self.database.recent_events(200) if event.created_at.astimezone().date() == today and event.kind != "command"]
        monitored = [event for event in self.database.recent_monitor_events(200) if event.created_at.astimezone().date() == today]
        combined = [f"{event.kind} {event.component}: {event.detail}" for event in monitored[:10]]
        combined.extend(f"{event.kind} {event.component}: {event.detail}" for event in events[:10])
        if not combined:
            return "Nao ha alteracoes registradas hoje. Ative com `atlas monitor start`."
        return "Alteracoes de hoje: " + "; ".join(combined[:12])

    def _change_risk(self) -> str:
        events = self.database.recent_events(100)
        monitored = self.database.recent_monitor_events(100)
        findings = list(self.database.latest_findings())
        risky = [event for event in monitored if event.severity in {Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value}]
        if risky:
            details = "; ".join(f"[{event.severity}] {event.kind} {event.component}: {event.risk}" for event in risky[:5])
            return "O monitor detectou: " + details
        matches = []
        for event in events:
            for item in findings:
                if event.component.lower() in item.component.lower() or item.component.lower() in event.component.lower():
                    matches.append(item)
        if not matches:
            return "Nao encontrei correlacao direta entre alteracoes registradas e os findings atuais. Isso nao garante ausencia de risco."
        unique = {item.fingerprint: item for item in matches}.values()
        return "Riscos correlacionados: " + "; ".join(f"[{item.severity}] {item.title}" for item in list(unique)[:5])

    def _nginx_restart(self) -> str:
        events = [event for event in self.database.recent_events(500) if event.kind == "service" and "nginx" in event.component.lower()]
        if not events:
            return "Nenhum reinicio do nginx foi registrado nas sessoes do ATLAS."
        event = events[0]
        return f"O evento mais recente do nginx foi registrado em {event.created_at.astimezone():%d/%m/%Y %H:%M:%S}: {event.detail}."

    def _priorities(self) -> str:
        scan = self.database.latest_scan()
        if not scan:
            return "Execute `atlas security` antes de calcular prioridades."
        items = sorted(scan.findings, key=lambda item: SEVERITY_ORDER.get(item.severity, 9))
        actionable = [item for item in items if item.severity != Severity.INFO.value][:3]
        if not actionable:
            return "Nao ha correcao prioritaria na ultima analise; revise os itens informativos e mantenha o monitoramento."
        return "Corrija nesta ordem: " + " ".join(f"{index}. [{item.severity}] {item.title} — {item.recommendation}" for index, item in enumerate(actionable, 1))
