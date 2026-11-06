"""Stand-ins for velib's VeDbusService and SettingsDevice, close to the real API
(Venus OS 3.75: dbus-systemcalc-py/ext/velib_python), so mappers run without D-Bus."""


class FakeBus(object):
    """The system bus as seen by one connection, plus what all connections share (service
    names, localsettings values). connection() opens another (private) connection."""

    def __init__(self, system=None):
        self.system = system or self
        if system is None:
            self.names = {}             # service name -> FakeVeDbusService (registered)
            self.settings = {}          # setting path -> value
            self.fail_settings = False
            self.connections = []
        self.has_root = False           # velib exports '/' once per connection
        self.closed = False

    def list_names(self):
        return ['com.victronenergy.settings'] + sorted(self.system.names)

    def connection(self):
        c = FakeBus(system=self.system)
        self.system.connections.append(c)
        return c

    def close(self):
        self.closed = True

    def __getattr__(self, name):        # names / settings / fail_settings of the shared system
        if name in ('names', 'settings', 'fail_settings', 'connections'):
            return getattr(self.system, name)
        raise AttributeError(name)


class FakeVeDbusService(object):
    def __init__(self, servicename, bus=None, register=None):
        assert register is False, 'mappers must use register=False then register()'
        if bus.has_root:   # real velib: VeDbusRootExport(conn, '/') in __init__ (seen on the van)
            raise KeyError("Can't register the object-path handler for '/': there is already a handler")
        bus.has_root = True
        self.name = servicename
        self.bus = bus
        self.paths = {}
        self.text = {}
        self.writeable = {}         # path -> onchangecallback
        self.registered = False
        self.removed = False
        self.flushes = []           # one entry per "with service as s" block (ItemsChanged)

    def add_path(self, path, value, description='', writeable=False, onchangecallback=None,
                 gettextcallback=None, valuetype=None, itemtype=None):
        assert not self.registered or path in self.paths, 'paths are added before register()'
        self.paths[path] = value
        self.text[path] = gettextcallback
        if writeable:
            self.writeable[path] = onchangecallback

    def set_from_gui(self, path, value):
        """What a SetValue from the GUI does in velib: refused when not writeable or when the
        onchangecallback returns False; otherwise the value is stored. Returns True when accepted."""
        if path not in self.writeable:
            return False
        cb = self.writeable[path]
        if cb is not None and not cb(path, value):
            return False
        self.paths[path] = value
        return True

    def register(self):
        assert '/DeviceInstance' in self.paths, '/DeviceInstance before register() (dbus-api)'
        assert self.name not in self.bus.names, 'name already taken'
        self.registered = True
        self.bus.names[self.name] = self

    def gettext(self, path):
        cb = self.text.get(path)
        return cb(path, self.paths[path]) if cb else str(self.paths[path])

    def __getitem__(self, path):
        return self.paths[path]

    def __setitem__(self, path, value):
        assert path in self.paths, 'unknown path %s' % path
        self.paths[path] = value

    def __enter__(self):
        self._changes = {}
        return self

    def __exit__(self, *exc):
        self.flushes.append(dict(self.paths))

    def __del__(self):
        if getattr(self, 'registered', False) and not self.removed:
            self.removed = True
            self.bus.names.pop(self.name, None)
            self.bus.has_root = False


class FakeSettingsDevice(object):
    """localsettings semantics for ClassAndVrmInstance: first free instance of the class at or
    above the requested one, kept once allocated (AddSetting never changes an existing value)."""

    def __init__(self, bus, supportedSettings, eventCallback, name='com.victronenergy.settings', timeout=0):
        if bus.fail_settings:
            raise Exception('The settings service com.victronenergy.settings does not exist!')
        self.bus = bus
        self.callback = eventCallback
        self.map = {}
        for key, (path, default, _min, _max) in supportedSettings.items():
            self.map[key] = path
            if path not in bus.settings:
                cls, inst = default.split(':')
                inst = int(inst)
                taken = set(v for p, v in bus.settings.items() if p.endswith('/ClassAndVrmInstance'))
                while '%s:%d' % (cls, inst) in taken:
                    inst += 1
                bus.settings[path] = '%s:%d' % (cls, inst)

    def __getitem__(self, key):
        return self.bus.settings[self.map[key]]

    def change(self, key, value):   # what the GUI does when the user edits the instance
        old = self[key]
        self.bus.settings[self.map[key]] = value
        self.callback(key, old, value)
