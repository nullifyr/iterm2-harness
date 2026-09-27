"""Public API-shaped doubles, not simulations of macOS or iTerm2 internals."""
import asyncio
from types import SimpleNamespace


class Transaction:
    def __init__(self, connection): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass


class Session:
    def __init__(self, sid, app):
        self.session_id, self.app = sid, app
        self.name = 'session-' + sid
        self.grid_size = SimpleNamespace(width=80, height=24)
        self.variables = {'path':'/workspace', 'jobName':'zsh', 'commandLine':'zsh',
                          'hostname':'host', 'username':'tester', 'tmuxRole':''}
        self.writes = []
        self.reads = []
        self.after_write = None
        self.geometry = SimpleNamespace(scrollback_buffer_height=10000, mutable_area_height=24, overflow=300)
        self.close_force = None

    async def async_get_variable(self, name): return self.variables.get(name, '')
    async def async_set_variable(self, name, value): self.variables[name] = value
    async def async_get_line_info(self): return self.geometry
    async def async_get_contents(self, first_line, number_of_lines):
        self.reads.append((first_line, number_of_lines))
        return [SimpleNamespace(string='line-%d' % (first_line+i)) for i in range(number_of_lines)]
    async def async_send_text(self, text, suppress_broadcast=False):
        self.writes.append((text, suppress_broadcast))
        await asyncio.sleep(0)
        if self.after_write: self.after_write()
    async def async_set_name(self, name): self.name = name
    async def async_activate(self):
        self.app.current_window = self.app.windows[0]
        self.app.current_window.current_tab.current_session = self
    async def async_close(self, force=False): self.close_force = force
    async def async_split_pane(self, vertical=False, before=False, profile=None):
        return self.app.add_session('new-split')


class Window:
    def __init__(self, app):
        self.app, self.window_id = app, 'w'
        self.tabs = [SimpleNamespace(tab_id='t', sessions=[], all_sessions=[], current_session=None)]
        self.current_tab = self.tabs[0]
        self.created_tabs = 0
    async def async_create_tab(self, profile=None, command=None, select=True):
        self.created_tabs += 1
        return SimpleNamespace(tab_id='new-tab')
    @staticmethod
    async def async_create(connection, profile=None, command=None):
        return SimpleNamespace(window_id='new-window')


class App:
    def __init__(self):
        self.windows = [Window(self)]
        self.current_window = None
        self.buried_sessions = []
        self.fail_probe = False
        self.add_session('a')
        self.add_session('b')
    def add_session(self, sid):
        session = Session(sid, self)
        tab = self.windows[0].tabs[0]
        tab.sessions.append(session)
        tab.all_sessions.append(session)
        if tab.current_session is None: tab.current_session = session
        return session
    async def async_get_variable(self, name):
        if self.fail_probe: raise ConnectionError('gone')
        return 1234
    def get_window_by_id(self, wid):
        return self.windows[0] if wid == 'w' else None


def sdk_for(app):
    async def get_app(connection): return app
    return SimpleNamespace(Session=Session, Window=Window, Transaction=Transaction, async_get_app=get_app)
