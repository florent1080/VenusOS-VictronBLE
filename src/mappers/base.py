"""Common part of the D-Bus mappers: one read-only Venus OS service per whitelisted device.

Paths follow the Venus OS D-Bus documentation (checked 2026-11-06):
  https://github.com/victronenergy/venus/wiki/dbus      (per product type)
  https://github.com/victronenergy/venus/wiki/dbus-api  (common paths, VRM device instances)
Rules applied from there:
  - /DeviceInstance comes from localsettings: AddSetting of
    /Settings/Devices/<unique id>/ClassAndVrmInstance with "<class>:1" reserves the first free
    instance of that class and keeps it (same mechanism as dbus-serialbattery);
  - the service is registered on D-Bus only once /DeviceInstance is added (register=False, then register());
  - /ProductId GetText is the hexadecimal id.
Read only: no path is writeable and no control path (/Mode, /Relay/...) is published.
"""

import logging
import sys

log = logging.getLogger('victronble.mappers')

VELIB = '/opt/victronenergy/dbus-systemcalc-py/ext/velib_python'
CONNECTION = 'Bluetooth (Instant Readout)'
PROCESS_NAME = 'victron-ble'


def velib():
    """VeDbusService and SettingsDevice from the copy of velib_python shipped with Venus OS."""
    if VELIB not in sys.path:
        sys.path.insert(1, VELIB)
    from settingsdevice import SettingsDevice
    from vedbus import VeDbusService
    return VeDbusService, SettingsDevice


def mac_id(mac):
    return mac.replace(':', '').lower()


def _text(unit, fmt):
    def gettext(path, value):
        if value is None or value == []:
            return '---'
        try:
            text = fmt % value if fmt else str(value)
        except (TypeError, ValueError):
            text = str(value)
        return '%s%s' % (text, unit) if unit else text
    return gettext


class Mapper(object):
    """Subclasses set SERVICE_CLASS and PATHS = ((path, reading key, unit, printf format), ...),
    or override paths() / static_paths() when they depend on the model or on the first reading
    (`first_values`, known at publishing time since a service is created on its first reading)."""
    SERVICE_CLASS = None
    PATHS = ()

    def __init__(self, device, model_id, product_name, bus, version, vedbus_cls=None, settings_cls=None,
                 first_values=None, bus_factory=None):
        self.device = device
        # Each VeDbusService needs its own connection: velib exports '/' on it, so a second
        # service on a shared connection fails (seen on the van: "already a handler" for '/').
        # `bus` (shared) is only used as a client, for localsettings.
        self.bus_factory = bus_factory
        self.svc_bus = None
        self.first_values = dict(first_values or {})
        self.model_id = model_id
        self.product_name = product_name
        self.bus = bus
        self.version = version
        self._classes = (vedbus_cls, settings_cls) if vedbus_cls else None
        self.service_name = 'com.victronenergy.%s.ble_%s' % (self.SERVICE_CLASS, mac_id(device.mac))
        self.settings_path = '/Settings/Devices/victronble_%s/ClassAndVrmInstance' % mac_id(device.mac)
        self.svc = None
        self.settings = None
        self.instance = None
        self.connected = False
        # rename_cb(mac, name) -> bool: persists a name typed in the GUI (set by the service)
        self.rename_cb = None

    # --------------------------------------------------------------- lifecycle ----

    def publish(self):
        """Create and register the D-Bus service. Raises on failure (the caller retries later)."""
        VeDbusService, SettingsDevice = self._classes or velib()
        # timeout=0: raise at once if localsettings is not up yet, never block the event loop
        self.settings = SettingsDevice(self.bus, {
            'instance': [self.settings_path, '%s:1' % self.SERVICE_CLASS, 0, 0],
        }, self._setting_changed, timeout=0)
        self.instance = int(str(self.settings['instance']).split(':')[1])
        conn = self._new_connection()
        try:
            svc = self._build(VeDbusService, conn)
        except Exception:
            self._close(conn)            # also drops whatever a half-built service exported
            raise
        self.svc, self.svc_bus = svc, conn
        log.info('%s published as %s, device instance %d', self.device.mac, self.service_name, self.instance)

    def _new_connection(self):
        if self.bus_factory is not None:
            return self.bus_factory()
        import dbus
        return dbus.SystemBus(private=True)

    @staticmethod
    def _close(conn):
        try:
            conn.close()
        except Exception as e:
            log.debug('closing a D-Bus connection: %s', e)

    def _build(self, VeDbusService, conn):
        svc = VeDbusService(self.service_name, bus=conn, register=False)
        svc.add_path('/Mgmt/ProcessName', PROCESS_NAME)
        svc.add_path('/Mgmt/ProcessVersion', self.version)
        svc.add_path('/Mgmt/Connection', CONNECTION)
        svc.add_path('/DeviceInstance', self.instance)
        svc.add_path('/ProductId', self.model_id, gettextcallback=lambda p, v: '0x%X' % v)
        svc.add_path('/ProductName', self.product_name)
        # editable from the GUI / VRM like on a native device; the name is a label, not a command
        svc.add_path('/CustomName', self.device.name or '', writeable=True, onchangecallback=self._renamed)
        svc.add_path('/FirmwareVersion', None)      # not carried by Instant Readout
        svc.add_path('/HardwareVersion', None)
        svc.add_path('/Connected', 0)
        for path, value in sorted(self.static_paths().items()):
            svc.add_path(path, value)
        for path, _key, unit, fmt in self.paths():
            svc.add_path(path, None, gettextcallback=_text(unit, fmt))
        svc.register()
        return svc

    def destroy(self):
        """Remove the service from D-Bus (device removed from the whitelist or changed).
        The ClassAndVrmInstance setting is kept, so the instance stays the same if it comes back."""
        if self.svc is not None:
            try:
                self.svc.__del__()      # velib: forces the immediate release of the name and paths
            except Exception as e:
                log.debug('releasing %s: %s', self.service_name, e)
            log.info('%s removed from D-Bus', self.service_name)
        if self.svc_bus is not None:
            self._close(self.svc_bus)
        self.svc = None
        self.svc_bus = None
        self.connected = False

    # ------------------------------------------------------------------- data ----

    def paths(self):
        """(path, reading key, unit, printf format) published with the readings."""
        return self.PATHS

    def static_paths(self):
        """path -> fixed value published once (e.g. /NrOfOutputs)."""
        return {}

    def values(self, reading_values):
        """D-Bus path -> value for one reading (subclasses may convert)."""
        return dict((path, reading_values.get(key)) for path, key, _u, _f in self.paths())

    def update(self, reading):
        if self.svc is None:
            return
        with self.svc as s:
            for path, value in self.values(reading.values).items():
                s[path] = value
            if not self.connected:
                s['/Connected'] = 1
        self.connected = True

    def disconnect(self):
        """No frame for timeout_s: /Connected = 0 and the measurements become invalid
        (so neither the GUI nor VRM shows stale values). The service itself stays."""
        if self.svc is None or not self.connected:
            return
        with self.svc as s:
            for path, _key, _u, _f in self.paths():
                s[path] = None
            s['/Connected'] = 0
        self.connected = False

    def set_name(self, device):
        """Same device, new name (renamed in the configuration): update in place, no republishing."""
        self.device = device
        name = device.name or ''
        if self.svc is not None and self.svc['/CustomName'] != name:
            self.svc['/CustomName'] = name

    def _renamed(self, path, value):
        """GUI wrote /CustomName. True accepts the value, False makes D-Bus refuse it."""
        if not isinstance(value, str) or self.rename_cb is None:
            return False
        try:   # the service validates (registry rules) and writes the configuration
            return bool(self.rename_cb(self.device.mac, value))
        except Exception:
            log.exception('%s: rename failed', self.service_name)
            return False

    def _setting_changed(self, setting, old, new):
        if setting != 'instance' or self.svc is None:
            return
        try:
            instance = int(str(new).split(':')[1])
        except (ValueError, IndexError):
            log.warning('%s: unexpected ClassAndVrmInstance %r', self.service_name, new)
            return
        # localsettings also signals a setting it has just created (same value): not a change
        if instance != self.instance:
            self.instance = instance
            self.svc['/DeviceInstance'] = instance
            log.info('%s: device instance changed to %d', self.service_name, instance)
