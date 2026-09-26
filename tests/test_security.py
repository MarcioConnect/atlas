from pathlib import Path

from atlas.database import Database
from atlas.models import Severity
from atlas.security import SecurityScanner, finding, redact, score_breakdown, score_findings
from atlas.threats import DefenderSnapshot


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
    fake_value = "review-artifact-" + "not-a-real-token"
    (artifact / ".env").write_text(f"API_TOKEN={fake_value}", encoding="utf-8")
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    assert scanner._secrets([tmp_path]) == []


def test_secret_scanner_detects_real_project_secret(tmp_path: Path):
    config = tmp_path / "config.py"
    fake_value = "r8V7n2Qp4Xx9u6Lw3A"
    config.write_text(f"API_KEY = '{fake_value}'\n", encoding="utf-8")
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    findings = scanner._secrets([tmp_path])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert fake_value not in findings[0].evidence


def test_secret_scanner_does_not_flag_explicitly_fake_value_in_project(tmp_path: Path):
    config = tmp_path / "config.py"
    config.write_text("API_KEY = 'test-only-credential-value'\n", encoding="utf-8")
    assert SecurityScanner(Database(tmp_path / "atlas.db"))._secrets([tmp_path]) == []


def test_default_secret_scope_does_not_sweep_watch_paths(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    scanner.settings.watch_paths = [str(tmp_path / "other-project")]
    assert scanner._default_secret_roots() == [tmp_path.resolve()]


def test_secret_scanner_ignores_placeholders_and_test_fixtures(tmp_path: Path):
    (tmp_path / "config.py").write_text("API_KEY = 'your_api_key'\nTOKEN = 'placeholder'\n", encoding="utf-8")
    fixture = tmp_path / "tests"
    fixture.mkdir()
    (fixture / ".env").write_text("API_TOKEN=definitely-not-a-real-test-token-value\n", encoding="utf-8")
    scanner = SecurityScanner(Database(tmp_path / "atlas.db"))
    assert scanner._secrets([tmp_path]) == []


def test_passive_defender_is_not_called_unprotected(tmp_path: Path, monkeypatch):
    snapshot = DefenderSnapshot(True, {
        "AMRunningMode": "Passive Mode", "AntivirusEnabled": False,
        "RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 30,
    }, [])
    monkeypatch.setattr("atlas.threats.defender_snapshot", lambda: snapshot)
    findings = SecurityScanner(Database(tmp_path / "atlas.db"))._antimalware()
    assert any(item.check_id == "defender-disabled" and item.severity == "INFO" for item in findings)
    assert not any(item.check_id == "defender-signatures" for item in findings)
    assert not any(item.severity == "CRITICAL" for item in findings)


def test_listener_is_observation_not_proven_external_exposure(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("atlas.security.listening_ports", lambda: [
        {"host": "0.0.0.0", "port": 135, "pid": 4, "process": "System"},
        {"host": "0.0.0.0", "port": 2375, "pid": 10, "process": "dockerd"},
    ])
    findings = SecurityScanner(Database(tmp_path / "atlas.db"))._ports()
    by_port = {item.component.rsplit(":", 1)[-1]: item for item in findings}
    assert by_port["135"].severity == Severity.INFO
    assert by_port["2375"].severity == Severity.HIGH
    assert all(item.confidence == 40 for item in findings)
    assert all("nao foram confirmados" in item.risk for item in findings)


def test_score_breakdown_separates_domains_and_caps_repetition():
    repeated = [
        finding("open-port", "Listener", Severity.MEDIUM, str(index), "risk", f"port:{index}", "fix")
        for index in range(20)
    ]
    credential = finding("exposed-secret", "Secret", Severity.HIGH, "hidden", "risk", "config.py", "fix")
    breakdown = score_breakdown([*repeated, credential])
    assert breakdown["network"] == 80
    assert breakdown["credentials"] == 85
    assert breakdown["overall"] == 75
    assert breakdown["host"] == 100
