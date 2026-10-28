"""Management modal shared by the idle and results dashboard."""
import time
import sqlite3
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label
from core.storage import THEMES


class ManagementMenu(ModalScreen):
    BINDINGS = [Binding('q', 'close', 'Return'), Binding('escape', 'close', 'Return'),
                *[Binding(str(n), f'choose({n})', show=False) for n in range(1, 6)]]
    DEFAULT_CSS = '''
    ManagementMenu { align: center middle; }
    ManagementMenu > VerticalScroll {
        width: 80; max-width: 95%; height: auto; max-height: 95%;
        border: solid $primary; background: $surface; padding: 1 2;
    }
    ManagementMenu Button { width: 100%; margin-top: 1; }
    ManagementMenu #management-status { margin: 1 0; }
    ManagementMenu #theme-choices { height: auto; display: none; }
    ManagementMenu #theme-choices.visible { display: block; }
    '''

    def __init__(self, storage):
        super().__init__()
        self.storage = storage
        self.confirm_action = None

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label('NETPROBE MANAGEMENT & CACHE CONTROL', markup=False)
            yield Label('', id='management-status', markup=False)
            for n, text in enumerate(('Select UI Theme', 'Clean Invalids (timed-out or corrupt runs)',
                                      'Export Anonymized Dataset (JSONL)', 'Reset Telemetry Cache (keep config)',
                                      'Factory Reset (all data and settings)'), 1):
                yield Button(f'[{n}] {text}', id=f'manage-{n}')
            with Vertical(id='theme-choices'):
                for theme in THEMES:
                    yield Button(theme, id=f'select-{theme}')
            yield Label('', id='management-message', markup=False)
            yield Button('[q] Return to Diagnostics', id='manage-close')

    def on_mount(self):
        self.refresh_status()

    def refresh_status(self):
        s = self.storage.status()
        self.query_one('#management-status', Label).update(
            f"Database Path: {s['path']}\nDatabase Size: {s['size_kb']} KB\n"
            f"Cached Runs: {s['total']} ({s['clean']} clean, {s['congested']} congested)\n"
            f"Active Theme: {s['theme']}")

    def action_close(self):
        self.dismiss()

    def action_choose(self, choice):
        try:
            self._choose(choice)
        except (OSError, sqlite3.Error) as error:
            self.query_one('#management-message', Label).update(f'[FAIL] {error}')

    def _choose(self, choice):
        message = self.query_one('#management-message', Label)
        if choice in (4, 5) and self.confirm_action != choice:
            self.confirm_action = choice
            message.update('[WARN] Press the same action again to confirm deletion. Any other action cancels.')
            return
        self.confirm_action = None
        if choice == 1:
            self.query_one('#theme-choices').toggle_class('visible')
        elif choice == 2:
            message.update(f'[OK] Removed {self.storage.clean_invalids()} invalid runs.')
        elif choice == 3:
            path = self.storage.db_path.parent / f'netprobe_dataset_{time.time_ns()}.jsonl'
            count = self.storage.export_anonymized(path)
            message.update(f'[OK] Exported {count} runs: {path}')
        elif choice == 4:
            self.storage.reset_telemetry()
            message.update('[OK] Telemetry cache cleared.')
        elif choice == 5:
            self.storage.factory_reset()
            self.app.theme = self.storage.get_theme()
            message.update('[OK] All cached data and settings cleared.')
        self.refresh_status()

    def on_button_pressed(self, event: Button.Pressed):
        event.stop()
        identifier = event.button.id or ''
        if identifier == 'manage-close':
            self.dismiss()
        elif identifier.startswith('select-'):
            self.confirm_action = None
            theme = identifier[len('select-'):]
            try:
                self.storage.set_theme(theme)
                self.app.theme = theme
                self.refresh_status()
            except (OSError, sqlite3.Error) as error:
                self.query_one('#management-message', Label).update(f'[FAIL] {error}')
        elif identifier.startswith('manage-'):
            self.action_choose(int(identifier.split('-')[1]))
