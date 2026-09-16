import asyncio
import base64

from atlas.database import Database
from atlas.panel import AtlasPanel
from atlas.security_guard import assess_untrusted


def test_panel_navigation_scan_report_and_directory(tmp_path, monkeypatch):
    database = Database(tmp_path / "history.db")
    project = tmp_path / "Project With Spaces"
    project.mkdir()
    calls = []
    monkeypatch.setattr("atlas.panel.CodeWatchdog.scan_now", lambda self: calls.append("scan"))
    monkeypatch.setattr("atlas.panel.generate_markdown_report", lambda db: tmp_path / "report.md")
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    monkeypatch.setattr("atlas.ollama_ai.ensure_local_service", lambda: False)

    async def run():
        async with AtlasPanel(database, project).run_test(size=(160, 55)) as pilot:
            await pilot.click("#nav-scan")
            await pilot.pause(.2)
            assert calls == ["scan"]
            await pilot.click("#nav-report")
            await pilot.pause(.2)
            assert "report.md" in str(pilot.app.query_one("#details").render())
            for button in ("settings", "tools", "help", "history", "home"):
                await pilot.click("#nav-" + button)
                await pilot.pause()
            assert pilot.app.query_one("#command")
            pilot.app.save_screenshot(str(tmp_path / "panel.svg"))
    asyncio.run(run())


def test_benign_encoding_and_invisible_text_do_not_raise_incident():
    assert assess_untrusted(base64.b64encode(b"ordinary application documentation and example content").decode()) == []
    assert assess_untrusted("ordinary\u200b text") == []


def test_portrait_preserves_original_menu_art():
    from textual.app import App

    from atlas.terminal_art import AtlasPortrait
    from atlas.tui import ATLAS_PORTRAIT

    class ArtApp(App):
        def compose(self):
            art = AtlasPortrait()
            art.styles.height = 19
            yield art

    async def run():
        async with ArtApp().run_test(size=(40, 19)) as pilot:
            await pilot.pause()
            assert pilot.app.query_one(AtlasPortrait).render().plain == ATLAS_PORTRAIT

    asyncio.run(run())


def test_panel_fits_terminal_and_reports_ai_status(tmp_path, monkeypatch):
    from atlas.ollama_ai import AIReviewStatus

    monkeypatch.setattr("atlas.ollama_ai.OllamaReviewer.availability", lambda self: AIReviewStatus(True, "Local model: test"))
    monkeypatch.setattr("atlas.ollama_ai.ensure_local_service", lambda: True)

    async def run():
        for size in [(160, 55), (120, 40), (160, 90), (120, 70)]:
            async with AtlasPanel(Database(tmp_path / 'layout.db'), tmp_path).run_test(size=size) as pilot:
                await pilot.pause(.2)
                assert 'Local model: test' in str(pilot.app.query_one('#ai-status').render())
                command = pilot.app.query_one('#command')
                assert command.region.bottom <= size[1]
                assert pilot.app.query_one('#banner-row').size.height <= (11 if size[0] < 130 else 22)
                assert pilot.app.screen.styles.background.hex == '#000000'
                assert pilot.app.query_one('#hero').styles.background.hex == '#000000'
                assert pilot.app.query_one('#nav-home').styles.background.hex == '#E4E4E4'
                assert pilot.app.query_one('#portrait').content_size.height >= 8
                portrait = str(pilot.app.query_one('#portrait').render())
                assert any(0x2801 <= ord(char) <= 0x28FF for char in portrait)
                assert '▀' not in portrait
                assert pilot.app.query_one('#hero').border_title == ' ATLAS / SECURITY AGENT '
                actions = pilot.app.query_one('#actions')
                assert pilot.app.query_one('#quick-refresh').region.bottom <= actions.content_region.bottom
                await pilot.click('#quick-directory')
                await pilot.pause(.1)
                assert pilot.app.query_one('#directory').has_class('visible')
                assert pilot.app.query_one('#directory').has_focus
    asyncio.run(run())


def test_scan_failure_does_not_crash_panel(tmp_path, monkeypatch):
    monkeypatch.setattr("atlas.ollama_ai.ensure_local_service", lambda: False)

    def fail(self):
        raise OSError("scan failed")

    monkeypatch.setattr("atlas.panel.CodeWatchdog.scan_now", fail)

    async def run():
        async with AtlasPanel(Database(tmp_path / "failure.db"), tmp_path).run_test(size=(120, 40)) as pilot:
            await pilot.click('#nav-scan')
            await pilot.pause(.2)
            assert not pilot.app.busy
            assert 'Falha no scan' in str(pilot.app.query_one('#details').render())

    asyncio.run(run())
