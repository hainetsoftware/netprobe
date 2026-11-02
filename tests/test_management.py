"""Exercise real key bindings, modal actions and persistence across app launches."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from textual.widgets import Label
from core.storage import StorageManager
from tui.app import NetProbeTUIApp
from ui.menu import ManagementMenu


class ManagementTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_db_lowercase_uppercase_and_button(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = StorageManager(Path(directory) / 'netprobe.db')
            app = NetProbeTUIApp(storage=storage)
            with patch.object(storage, 'open_storage_dir', return_value=True) as opener:
                async with app.run_test(size=(100, 60)) as pilot:
                    await pilot.press('m', 'o', 'O')
                    await pilot.click('#manage-open-db')
                    self.assertEqual(opener.call_count, 3)
                    self.assertIn('Cartella aperta nel file manager.',
                                  str(app.screen.query_one('#management-message', Label).render()))
                    opener.return_value = False
                    await pilot.press('o')
                    self.assertIn('Impossibile aprire',
                                  str(app.screen.query_one('#management-message', Label).render()))

    async def test_open_menu_refreshes_live_clean_and_congested_counts(self):
        from core.ingestion import ingest_report
        from tests.test_storage import latest_report
        with tempfile.TemporaryDirectory() as directory:
            storage = StorageManager(Path(directory) / 'netprobe.db')
            app = NetProbeTUIApp(storage=storage)
            async with app.run_test(size=(100, 60)) as pilot:
                await pilot.press('m')
                clean = latest_report()
                clean['performance']['speed']['valid'] = False
                ingest_report(clean, storage=storage)
                congested = latest_report()
                congested['performance']['bufferbloat']['download_delta_ms'] = 60
                ingest_report(congested, storage=storage)
                await pilot.pause(1.1)
                text = str(app.screen.query_one('#management-status', Label).render())
                self.assertIn('Cached Runs: 2 total (1 clean, 1 congested)', text)
                storage.reset_telemetry()
                await pilot.pause(1.1)
                self.assertIn('Cached Runs: 0 total (0 clean, 0 congested)',
                              str(app.screen.query_one('#management-status', Label).render()))

    async def test_m_theme_restart_and_factory_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = StorageManager(Path(directory) / 'netprobe.db')
            app = NetProbeTUIApp(storage=storage)
            async with app.run_test(size=(100, 60)) as pilot:
                await pilot.press('ctrl+p')
                self.assertNotIsInstance(app.screen, ManagementMenu)
                await pilot.press('m')
                await pilot.pause()
                self.assertIsInstance(app.screen, ManagementMenu)
                self.assertIn('Cached Runs: 0', str(app.screen.query_one('#management-status', Label).render()))
                await pilot.press('1')
                await pilot.click('#select-oled-black')
                self.assertEqual(storage.get_theme(), 'oled-black')
                await pilot.press('q')
                self.assertEqual(app.theme, 'oled-black')
            app = NetProbeTUIApp(storage=StorageManager(storage.db_path))
            async with app.run_test(size=(100, 60)) as pilot:
                self.assertEqual(app.theme, 'oled-black')
                await pilot.press('M')
                await pilot.pause()
                self.assertIsInstance(app.screen, ManagementMenu)
                await pilot.press('5')
                self.assertEqual(storage.get_theme(), 'oled-black')
                await pilot.press('5')
                self.assertEqual(storage.get_theme(), 'midnight-slate')
                self.assertEqual(app.theme, 'midnight-slate')
                await pilot.press('q')
