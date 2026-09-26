import asyncio

from atlas.code_scanners import ScannerAvailability
from atlas.database import Database
from atlas.tui import run_tui
from atlas.watch_tui import WatchdogApp, WatchScreen


def test_tui_entry_point_opens_integrated_panel(monkeypatch):
    opened = []
    monkeypatch.setattr("atlas.panel.AtlasPanel.run", lambda self: opened.append(self))

    run_tui()

    assert len(opened) == 1


def test_watchdog_tui_opens_for_path_with_spaces(monkeypatch, tmp_path):
    project = tmp_path / "Project With Spaces"
    project.mkdir()
    monkeypatch.setattr("atlas.watch_tui.CodeWatchdog.start", lambda self, initial_scan=True: None)
    monkeypatch.setattr("atlas.watch_tui.CodeWatchdog.stop", lambda self: None)

    async def run():
        database = Database(tmp_path / "tui.sqlite")
        async with WatchdogApp(project, database).run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            assert isinstance(pilot.app.screen, WatchScreen)
            assert "Project With Spaces" in str(pilot.app.screen.project)
            assert pilot.app.screen.query_one("#watch-content") is not None
            assert pilot.app.screen.query_one("#watch-menu").has_focus

    asyncio.run(run())


def test_watchdog_status_does_not_call_partial_scan_safe(tmp_path):
    screen = WatchScreen(tmp_path, Database(tmp_path / "partial-tui.sqlite"))
    screen.watchdog.state.status = "SAFE"
    screen.watchdog.state.availability = [ScannerAvailability("Semgrep", False, "install semgrep")]
    assert "PARTIAL COVERAGE" in screen._status()


def test_watchdog_status_limits_incremental_clean_claim(tmp_path):
    screen = WatchScreen(tmp_path, Database(tmp_path / "incremental-tui.sqlite"))
    screen.watchdog.state.status = "SAFE"
    screen.watchdog.state.scan_scope = "INCREMENTAL"
    assert "CHANGED SCOPE" in screen._status()
