from pathlib import Path

from atlas.database import Database
from atlas.models import Severity
from atlas.security import SecurityScanner, finding, redact, score_findings


def test_redact_removes_common_secrets():
    sample = "to" + "ken" + "=" + "abc123456 " + "pass" + "word:" + "supersecret " + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
    sanitized = redact(sample)
    assert "abc123456" not in sanitized
    assert "supersecret" not in sanitized
    assert "ghp_" not in sanitized
    assert sanitized.count("[REDACTED]") >= 3


def test_score_is_bounded_and_ignores_duplicate_fingerprint():
    first = finding("x", "Issue", Severity.HIGH, "same", "risk", "component", "fix")
    duplicate = finding("x", "Issue", Severity.HIGH, "same", "risk", "component", "fix")
    assert score_findings([first, duplicate]) == 85
    critical = [finding("x", "Issue", Severity.CRITICAL, str(index), "risk", str(index), "fix") for index in range(10)]
    assert score_findings(critical) == 0


def test_secret_scanner_never_returns_secret_value(tmp_path: Path):
    credential_value = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "123456"
    (tmp_path / ".env").write_text(f"API_TOKEN={credential_value}", encoding="utf-8")
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    findings = scanner._secrets([tmp_path])
    assert findings
    assert all(credential_value not in item.evidence for item in findings)
    assert all("valor omitido" in item.evidence for item in findings)
