"""Exercise real key bindings, modal actions and persistence across app launches."""
from pathlib import Path
import tempfile
import unittest
from textual.widgets import Label
from core.storage import StorageManager
from tui.app import NetProbeTUIApp
from ui.menu import ManagementMenu


class ManagementTests(unittest.IsolatedAsyncioTestCase):
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
