
from atlas.multi_watch import MultiProjectWatchdog


def test_multi_watch_deduplicates_existing_projects(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    manager = MultiProjectWatchdog([first, first, second, tmp_path / "missing"])
    assert manager.projects == [first.resolve(), second.resolve()]
    assert set(manager.states) == {first.resolve(), second.resolve()}

