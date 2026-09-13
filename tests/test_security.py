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
    assert score_findings(critical) == 50


def test_secret_scanner_never_returns_secret_value(tmp_path: Path):
    credential_value = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "123456"
    (tmp_path / ".env").write_text(f"API_TOKEN={credential_value}", encoding="utf-8")
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    findings = scanner._secrets([tmp_path])
    assert findings
    assert all(credential_value not in item.evidence for item in findings)
    assert all("valor omitido" in item.evidence for item in findings)


def test_secret_scanner_ignores_review_artifacts(tmp_path: Path):
    """Temporary review/test worktrees must not lower the host score."""
    artifact = tmp_path / ".review-open-errors"
    artifact.mkdir()
    (artifact / ".env").write_text("API_TOKEN=ghp_fake_review_artifact_value", encoding="utf-8")
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    assert scanner._secrets([tmp_path]) == []


def test_secret_scanner_detects_real_project_secret(tmp_path: Path):
    config = tmp_path / "config.py"
    config.write_text("API_KEY = 'ghp_fake_but_project_secret_value'\n", encoding="utf-8")
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    findings = scanner._secrets([tmp_path])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "ghp_fake_but_project_secret_value" not in findings[0].evidence


def test_default_secret_scope_does_not_sweep_watch_paths(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    scanner.settings.watch_paths = [str(tmp_path / "other-project")]
    assert scanner._default_secret_roots() == [tmp_path.resolve()]
