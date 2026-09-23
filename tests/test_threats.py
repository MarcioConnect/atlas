import json
from types import SimpleNamespace

from atlas.threats import DefenderSnapshot, defender_snapshot, inspect_executable, persistence_snapshot, scan_with_yara


def test_defender_snapshot_redacts_resource_paths(monkeypatch):
    responses = iter([
        {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True},
        [{"ThreatID": 42, "ActionSuccess": True, "InitialDetectionTime": "now", "Resources": ["C:/private/file.exe"]}],
    ])
    monkeypatch.setattr("atlas.threats._powershell_json", lambda script: next(responses))
    snapshot = defender_snapshot()
    assert snapshot.available
    assert snapshot.detections[0]["Resources"] == ["file.exe"]


def test_defender_snapshot_degrades_safely(monkeypatch):
    monkeypatch.setattr("atlas.threats._powershell_json", lambda script: (_ for _ in ()).throw(OSError("blocked")))
    snapshot = defender_snapshot()
    assert snapshot == DefenderSnapshot(False, {}, [], "OSError")


def test_executable_inspection_hashes_without_running_target(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"fixture executable bytes")
    monkeypatch.setattr("atlas.threats.subprocess.run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=json.dumps({"Status": "Valid", "Signer": "Fixture Signer", "StatusMessage": "OK"}),
    ))
    result = inspect_executable(target)
    assert result["sha256"] == "f67bea1e29bf7fa00d04549495d9d5d3bf5fc92aa36a59fc471f792d6c8b153c"
    assert result["authenticode"]["status"] == "Valid"


def test_yara_unavailable_is_nonfatal(monkeypatch, tmp_path):
    monkeypatch.setattr("atlas.threats.importlib.import_module", lambda _name: (_ for _ in ()).throw(ImportError()))
    result = scan_with_yara(tmp_path, tmp_path)
    assert result["available"] is False
    assert result["matches"] == []


def test_yara_scans_only_selected_local_rules_with_bounded_output(monkeypatch, tmp_path):
    rule_dir = tmp_path / "trusted rules"
    rule_dir.mkdir()
    (rule_dir / "example.yar").write_text("rule fixture { condition: true }")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")

    class Rules:
        def match(self, file_path, timeout):
            assert timeout <= 5
            return [SimpleNamespace(rule="FixtureRule")]

    monkeypatch.setattr("atlas.threats.importlib.import_module", lambda _name: SimpleNamespace(compile=lambda **_kwargs: Rules()))
    result = scan_with_yara(target, rule_dir)
    assert result["available"] is True and result["complete"] is True
    assert result["matches"] == [{"rule": "FixtureRule", "file": "sample.bin"}]


def test_persistence_snapshot_hashes_values_without_returning_commands(monkeypatch):
    monkeypatch.setattr("atlas.threats.os.name", "nt")
    monkeypatch.setattr("atlas.threats._powershell_json", lambda *_args, **_kwargs: [
        {"kind": "registry-run", "name": "HKCU:Run:Agent", "value": r"C:\private\agent.exe --token=secret"},
    ])
    result = persistence_snapshot()
    assert result[0]["kind"] == "registry-run"
    assert "secret" not in str(result)
    assert len(result[0]["fingerprint"]) == 64
