
from atlas.multi_watch import MultiProjectWatchdog, configured_projects


def test_multi_watch_deduplicates_existing_projects(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    manager = MultiProjectWatchdog([first, first, second, tmp_path / "missing"])
    assert manager.projects == [first.resolve(), second.resolve()]
    assert set(manager.states) == {first.resolve(), second.resolve()}



def test_configured_projects_prunes_overlapping_broad_roots(tmp_path, monkeypatch):
    broad = tmp_path / "workspace"
    project = broad / "real-project"
    project.mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    monkeypatch.setattr(
        "atlas.multi_watch.Settings.load",
        lambda: type("S", (), {"watch_paths": [str(broad), str(project)]})(),
    )
    assert configured_projects() == [project.resolve()]
