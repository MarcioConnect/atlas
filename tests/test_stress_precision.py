"""Deterministic, synthetic stress cases for high-risk classification boundaries.

The generated cases are regression coverage, not real-world precision estimates.
"""

import hashlib
from pathlib import Path

import pytest

from atlas.code_scanners import LocalCodeScanners, NormalizedFinding
from atlas.database import Database
from atlas.security import is_secret_candidate, redact


def _sample(index: int) -> str:
    return hashlib.sha256(f"atlas-synthetic-{index}".encode()).hexdigest()[:24]


SECRET_CASES = [
    (index, kind)
    for index in range(512)
    for kind in ("plausible", "explicit_fake", "environment_reference")
]


@pytest.mark.parametrize("index,kind", SECRET_CASES)
def test_generated_secret_candidate_boundaries(index: int, kind: str):
    value = _sample(index)
    candidate = {
        "plausible": value,
        "explicit_fake": f"fake-{value}",
        "environment_reference": f"${{ATLAS_DEMO_{index:04d}}}",
    }[kind]
    assert is_secret_candidate(candidate) is (kind == "plausible")


@pytest.mark.parametrize("index", range(512))
def test_generated_secret_values_never_survive_redaction(index: int):
    value = _sample(index)
    variants = (
        f"api_key={value}",
        f"password:{value}",
        f"ghp_{value}",
        f"postgres://user:{value}@localhost/sample",
    )
    evidence = variants[index % len(variants)]
    sanitized = redact(evidence)
    assert value not in sanitized
    assert "[REDACTED]" in sanitized


@pytest.mark.parametrize("index", range(256))
def test_generated_python_call_is_distinct_from_string_example(index: int, tmp_path: Path, monkeypatch):
    monkeypatch.setattr("atlas.code_scanners.shutil.which", lambda _name: None)
    target = tmp_path / "app.py"
    symbol = f"user_input_{index}"
    is_call = index % 2 == 0
    source = f"eval({symbol})\n" if is_call else f"example = 'eval({symbol})'\n"
    target.write_text(source, encoding="utf-8")
    findings = LocalCodeScanners(tmp_path).scan([target]).findings
    detected = any(item.scanner == "ATLAS Native" and item.rule_id == "python-eval" for item in findings)
    assert detected is is_call


@pytest.mark.parametrize("index", range(256))
def test_generated_fingerprint_survives_unrelated_header(index: int, tmp_path: Path):
    target = tmp_path / "app.py"
    source = f"result = eval(user_input_{index})\n"
    target.write_text(source, encoding="utf-8")
    first = NormalizedFinding("HIGH", "ATLAS Native", "python-eval", str(target), 1,
                              "Issue", "sanitized evidence", "Fix").finalize(tmp_path)
    header_count = index % 7 + 1
    target.write_text("# unrelated header\n" * header_count + source, encoding="utf-8")
    moved = NormalizedFinding("HIGH", "ATLAS Native", "python-eval", str(target), header_count + 1,
                              "Issue", "sanitized evidence", "Fix").finalize(tmp_path)
    assert first.fingerprint == moved.fingerprint


@pytest.mark.parametrize("status", [
    "NOT_INSTALLED", "NOT_APPLICABLE", "READY", "RUNNING", "SUCCESS", "PARTIAL",
    "FAILED", "TIMEOUT", "CANCELLED", "SKIPPED",
])
@pytest.mark.parametrize("covered", [False, True])
def test_scanner_status_and_scope_matrix_never_invents_resolution(
    status: str, covered: bool, tmp_path: Path,
):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "app.py"
    target.write_text("pass\n", encoding="utf-8")
    database = Database(tmp_path / "matrix.sqlite")
    finding = NormalizedFinding("HIGH", "Matrix Scanner", "R1", str(target), 1,
                                "Issue", "sanitized evidence", "Fix").finalize(project)
    initial = database.begin_code_scan(str(project))
    database.reconcile_code_findings(str(project), initial.id, [finding.record()],
                                     {"Matrix Scanner": {str(target.resolve()).casefold()}},
                                     {"Matrix Scanner": "SUCCESS"})
    next_scan = database.begin_code_scan(str(project))
    scope = {str(target.resolve()).casefold()} if covered else set()
    result = database.reconcile_code_findings(str(project), next_scan.id, [],
                                              {"Matrix Scanner": scope}, {"Matrix Scanner": status})
    should_resolve = status == "SUCCESS" and covered
    assert bool(result["RESOLVED"]) is should_resolve
    assert bool(database.code_findings(str(project), "RESOLVED")) is should_resolve
    if status != "SUCCESS":
        assert len(result["UNVERIFIED"]) == 1
