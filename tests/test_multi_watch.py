
from atlas.multi_watch import MultiProjectWatchdog, configured_projects


def test_multi_watch_deduplicates_existing_projects(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    manager = MultiProjectWatchdog([first, first, second, tmp_path / "missing"])
    assert manager.projects == [first.resolve(), second.resolve()]
    assert set(manager.states) == {first.resolve(), second.resolve()}


def test_multi_watch_rolls_back_started_projects_when_later_start_fails(tmp_path, monkeypatch):
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    manager = MultiProjectWatchdog([one, two])
    started = []
    stopped = []
    watchers = list(manager.watchdogs.values())

    def start(self, initial_scan=True):
        started.append(self)
        if len(started) == 2:
            raise OSError("observer unavailable")

    monkeypatch.setattr("atlas.multi_watch.CodeWatchdog.start", start)
    monkeypatch.setattr("atlas.multi_watch.CodeWatchdog.stop", lambda self: stopped.append(self))
    try:
        manager.start()
    except OSError:
        pass
    else:
        raise AssertionError("expected startup failure")
    assert started == watchers
    assert stopped == [watchers[0]]



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
