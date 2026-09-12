from pathlib import Path

from atlas.ask import LocalAtlasProvider
from atlas.database import Database
from atlas.models import Scan, Severity
from atlas.security import finding


def test_ask_prioritizes_findings(tmp_path: Path):
    database = Database(tmp_path / "atlas.db")
    database.save_scan(
        Scan(
            hostname="host",
            score=60,
            findings=[finding("fw", "Firewall desligado", Severity.HIGH, "disabled", "risk", "firewall", "Ative o firewall")],
        )
    )
    provider = LocalAtlasProvider(database)
    answer = provider.answer("O que devo corrigir primeiro?")
    assert "Firewall desligado" in answer


def test_ask_requests_scan_when_empty(tmp_path: Path):
    provider = LocalAtlasProvider(Database(tmp_path / "atlas.db"))
    assert "atlas security" in provider.answer("Quais falhas existem nessa máquina?")
