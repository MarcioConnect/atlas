from atlas.threats import DefenderSnapshot, defender_snapshot


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
