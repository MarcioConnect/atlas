from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from atlas.database import Database
from atlas.watch_tui import WatchdogApp, WatchScreen

PROJECT = Path(r"C:\atlas-demo")
OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "screenshots" / ".atlas-watchdog.svg"
DATABASE = Path(__file__).resolve().parent / ".atlas-screenshot.sqlite"


async def capture() -> None:
    database = Database(DATABASE)
    try:
        with (
            patch("atlas.watch_tui.CodeWatchdog.start", lambda self, initial_scan=True: None),
            patch("atlas.watch_tui.CodeWatchdog.stop", lambda self: None),
        ):
            app = WatchdogApp(PROJECT, database)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                screen = app.screen
                if not isinstance(screen, WatchScreen):
                    raise TypeError("Unexpected watchdog screen type")
                screen.watchdog.state.status = "SAFE"
                screen.watchdog.state.files_analyzed = 24
                screen.watchdog.state.changes = 0
                screen.watchdog.state.last_scan_at = datetime.now(UTC)
                await screen.show_view()
                await pilot.pause()
                app.save_screenshot(filename=OUTPUT.name, path=str(OUTPUT.parent))
    finally:
        database.engine.dispose()


if __name__ == "__main__":
    try:
        asyncio.run(capture())
    finally:
        DATABASE.unlink(missing_ok=True)
