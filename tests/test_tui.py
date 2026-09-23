import asyncio

from atlas.code_scanners import ScannerAvailability
from atlas.database import Database
from atlas.tui import AtlasApp, DashboardScreen, MainScreen
from atlas.watch_tui import WatchdogApp, WatchScreen


def test_tui_opens_overview(monkeypatch):
    async def run():
        async with AtlasApp().run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(pilot.app.screen, MainScreen)
            assert pilot.app.screen.query_one("#launch-menu") is not None
            assert len(pilot.app.screen.query("#launch-menu Button")) == 6
            assert pilot.app.screen.query_one("#chat-input") is not None
            assert pilot.app.screen.query_one("#chat-log") is not None
            assert "LOCAL AGENT READY" in str(pilot.app.screen.query_one("#wordmark").render())

    asyncio.run(run())


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


def test_dashboard_menu_accepts_keyboard_selection(monkeypatch):
    async def run():
        async with AtlasApp().run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            await pilot.press("escape")
            # The regular atlas home is intentionally separate; exercise the
            # dashboard screen directly to validate its menu focus/selection.
            await pilot.app.push_screen(DashboardScreen())
            await pilot.pause(0.1)
            screen = pilot.app.screen
            assert isinstance(screen, DashboardScreen)
            assert screen.query_one("#menu").has_focus
            await pilot.press("down", "enter")
            await pilot.pause(0.1)
            assert screen.current_view == "Live Monitor"

    asyncio.run(run())


def test_home_watch_mode_item_dispatches(monkeypatch):
    async def run():
        async with AtlasApp().run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            screen = pilot.app.screen
            assert isinstance(screen, MainScreen)
            await pilot.press("down", "enter")
            await pilot.pause(0.2)
            assert isinstance(pilot.app.screen, WatchScreen)

    asyncio.run(run())


def test_home_menu_buttons_accept_mouse_click(monkeypatch):
    async def run():
        async with AtlasApp().run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            screen = pilot.app.screen
            assert isinstance(screen, MainScreen)
            await pilot.click("#launch-2")
            await pilot.pause(0.2)
            assert isinstance(pilot.app.screen, WatchScreen)

    asyncio.run(run())


def test_home_report_button_generates_markdown(monkeypatch, tmp_path):
    report = tmp_path / "atlas-report-2026-09-12.md"
    monkeypatch.setattr("atlas.tui.generate_markdown_report", lambda *args, **kwargs: report)

    async def run():
        async with AtlasApp().run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            await pilot.click("#launch-4")
            await pilot.pause(0.1)
            status = str(pilot.app.screen.query_one("#action-status").render())
            assert "REPORT SAVED" in status

    asyncio.run(run())
