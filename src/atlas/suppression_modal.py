"""Reusable Textual dialog that suppresses a finding with a mandatory reason."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Static

SEVERITY_STYLE = {
    "CRITICAL": "bold white on #b42318", "HIGH": "bold #ff5f5f", "MEDIUM": "bold #f5c451",
    "LOW": "#6bdcff", "INFO": "#8a9baa",
}
DEFAULT_DAYS = 30


def _short_path(value: str) -> str:
    try:
        return str(Path(value))
    except (OSError, ValueError):
        return str(value)


class SuppressionModal(ModalScreen[dict[str, Any] | None]):
    """Ask for a reason and validity, then return the chosen finding.

    When more than one finding is provided the user picks a row first; with a
    single finding the table is hidden and the confirmation applies directly.
    """

    BINDINGS = [("escape", "cancel", "Cancelar")]

    CSS = """
    SuppressionModal { align: center middle; background: #000000 75%; }
    #suppression-dialog { width: 90%; max-width: 110; height: auto; max-height: 85%;
        border: round #6c94b8; background: #050505; padding: 1 2; }
    #suppression-title { height: 2; color: #8fcfff; text-style: bold; }
    #suppression-info { height: auto; color: #cfcfcf; margin-bottom: 1; }
    #suppression-findings { height: auto; max-height: 12; margin-bottom: 1; }
    #suppression-dialog Label { color: #9fc5df; margin-top: 1; }
    #suppression-error { color: #ff5f5f; height: 1; }
    #suppression-actions { height: 3; margin-top: 1; }
    #suppression-actions Button { width: 1fr; margin-right: 1; }
    """

    def __init__(self, findings: list[Any], default_days: int = DEFAULT_DAYS) -> None:
        super().__init__()
        self.findings = list(findings)
        self.default_days = default_days
        self.selected_index = 0

    def compose(self) -> ComposeResult:
        with Vertical(id="suppression-dialog"):
            yield Static("SUPRIMIR FINDING", id="suppression-title")
            yield Static("", id="suppression-info")
            if len(self.findings) > 1:
                yield DataTable(id="suppression-findings", cursor_type="row")
            yield Label("Motivo (obrigatório)")
            yield Input(placeholder="Ex.: falso positivo revisado", id="suppression-reason")
            yield Label("Validade em dias")
            yield Input(value=str(self.default_days), id="suppression-days")
            yield Static("", id="suppression-error")
            with Horizontal(id="suppression-actions"):
                yield Button("Suprimir", id="suppression-confirm", variant="primary")
                yield Button("Cancelar", id="suppression-cancel")

    def on_mount(self) -> None:
        if len(self.findings) > 1:
            table = self.query_one("#suppression-findings", DataTable)
            table.add_columns("Severidade", "Regra", "Arquivo", "Linha")
            for item in self.findings:
                table.add_row(
                    str(getattr(item, "severity", "")), str(getattr(item, "rule_id", "")),
                    _short_path(str(getattr(item, "file_path", ""))),
                    str(getattr(item, "line", "-") or "-"),
                )
            table.focus()
            self._update_info()
        else:
            self._update_info()
            self.query_one("#suppression-reason", Input).focus()

    def _update_info(self) -> None:
        item = self.findings[self.selected_index] if self.findings else None
        if item is None:
            self.query_one("#suppression-info", Static).update("Nenhum finding para suprimir.")
            return
        severity = str(getattr(item, "severity", "INFO"))
        style = SEVERITY_STYLE.get(severity, "")
        text = (
            f"[{style}]{severity}[/] · {getattr(item, 'rule_id', 'unknown')}\n"
            f"{_short_path(str(getattr(item, 'file_path', '')))}:{getattr(item, 'line', '-') or '-'}\n"
            f"{getattr(item, 'description', '')}"
        )
        self.query_one("#suppression-info", Static).update(text)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.selected_index = event.cursor_row
        self._update_info()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "suppression-cancel":
            self.dismiss(None)
        elif event.button.id == "suppression-confirm":
            self._submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _submit(self) -> None:
        reason = self.query_one("#suppression-reason", Input).value.strip()
        raw_days = self.query_one("#suppression-days", Input).value.strip()
        error = self.query_one("#suppression-error", Static)
        if not self.findings:
            self.dismiss(None)
            return
        if not reason:
            error.update("Informe um motivo para a supressão.")
            self.query_one("#suppression-reason", Input).focus()
            return
        try:
            days = int(raw_days) if raw_days else self.default_days
        except ValueError:
            error.update("Validade deve ser um número de dias.")
            return
        days = max(1, min(days, 3650))
        finding = self.findings[self.selected_index]
        self.dismiss({"finding": finding, "reason": reason, "days": days})
