from pathlib import Path

from atlas.database import Database
from atlas.models import Scan, Severity
from atlas.security import finding


def test_scan_round_trip(tmp_path: Path):
    database = Database(tmp_path / "atlas.db")
    scan = Scan(
        hostname="test-host",
        score=85,
        findings=[finding("test", "Teste", Severity.HIGH, "evidencia", "risco", "componente", "corrigir")],
    )
    database.save_scan(scan)
    loaded = database.latest_scan()
    assert loaded is not None
    assert loaded.score == 85
    assert loaded.findings[0].severity == "HIGH"
