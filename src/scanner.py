"""Who makes the radio scan. The listener (listener.py) never scans: it only hears.

Modes (configuration key "scanner"):
  auto   (default) rely on the Venus OS Bluetooth sensors service, whose passive scan
         is the lightest (17 % duty cycle, 2026-11-06 measurements). If the user turns
         those sensors off, start our own BlueZ LE discovery; stop it when they come
         back. The Venus setting is read, never written: the user's choice wins.
  venus  never scan ourselves (devices go disconnected while the sensors are off).
  bluez  always use our BlueZ discovery (the Venus sensors should then be off).
  none   no scanning at all (replay, tests).

Only BlueZ's D-Bus discovery API is used. No raw HCI command and no
AdvertisementMonitor: registering one disables vesmart-server's PIN brute-force
protection on Venus OS 3.75 (unknown mgmt event 0x2B, see the diagnostic of 2026-11-06).
"""

import logging
import time

log = logging.getLogger('victronble.scanner')

MODES = ('auto', 'venus', 'bluez', 'none')
SETTINGS_SERVICE = 'com.victronenergy.settings'
BLE_SENSORS_PATH = '/Settings/Services/BleSensors'


class VenusSensorsSetting(object):
    """Reads /Settings/Services/BleSensors. Returns 1, 0 or None when unreadable."""

    def __init__(self, bus):
        self.bus = bus

    def get(self):
        try:
            obj = self.bus.get_object(SETTINGS_SERVICE, BLE_SENSORS_PATH, introspect=False)
            return int(obj.GetValue(dbus_interface='com.victronenergy.BusItem', timeout=5))
        except Exception as e:
            log.debug('cannot read %s: %s', BLE_SENSORS_PATH, e)
            return None


class BluezDiscovery(object):
    """Our own LE discovery session in BlueZ. BlueZ ends it by itself when our process
    leaves the bus, so a crash cannot leave a scan running."""

    def __init__(self, bus, adapter_path='/org/bluez/hci0'):
        self.bus = bus
        self.adapter_path = adapter_path
        self.running = False

    def _iface(self, name):
        import dbus
        return dbus.Interface(self.bus.get_object('org.bluez', self.adapter_path), name)

    def start(self):
        import dbus
        adapter = self._iface('org.bluez.Adapter1')
        try:
            # DuplicateData makes the kernel turn the controller's duplicate filter off,
            # otherwise a device would be reported once per scan only.
            adapter.SetDiscoveryFilter(dbus.Dictionary({'Transport': 'le', 'DuplicateData': True},
                                                       signature='sv'), timeout=10)
        except dbus.exceptions.DBusException as e:
            log.warning('SetDiscoveryFilter refused (%s), discovering without filter', e.get_dbus_name())
        try:
            adapter.StartDiscovery(timeout=10)
        except dbus.exceptions.DBusException as e:
            if e.get_dbus_name() != 'org.bluez.Error.InProgress':
                log.error('BlueZ StartDiscovery failed: %s %s', e.get_dbus_name(), e.get_dbus_message())
                self.running = False
                return False
        self.running = True
        return True

    def stop(self):
        if not self.running:
            return
        self.running = False
        try:
            self._iface('org.bluez.Adapter1').StopDiscovery(timeout=10)
        except Exception as e:
            log.debug('StopDiscovery: %s', e)

    def adapter_discovering(self):
        try:
            props = self._iface('org.freedesktop.DBus.Properties')
            return bool(props.Get('org.bluez.Adapter1', 'Discovering', timeout=5))
        except Exception:
            return None


class ScanDriver(object):
    CHECK_INTERVAL_S = 10
    # auto: setting unreadable this many checks in a row -> scan ourselves. 60 s leaves time to
    # localsettings at boot, so we do not start a discovery only to stop it a few seconds later.
    UNKNOWN_SETTING_LIMIT = 6
    SILENCE_WARN_S = 120

    def __init__(self, loop, mode, sensors=None, discovery=None, clock=time.time):
        if mode not in MODES:
            raise ValueError('scanner mode %r (expected %s)' % (mode, ', '.join(MODES)))
        self.loop = loop
        self.mode = mode
        self.sensors = sensors
        self.discovery = discovery
        self.clock = clock
        self.state = 'idle'            # 'idle' | 'venus' | 'bluez'
        self.ble_sensors = None
        self.since = clock()
        self._unknown = 0
        self._timer = None
        self._last_advert = None
        self._silence_reported = False
        self._both_reported = False
        self._start_failed = False

    def start(self):
        self.check()
        if self.mode != 'none':
            self._timer = self.loop.timeout_add_seconds(self.CHECK_INTERVAL_S, self.check)

    def stop(self):
        if self._timer is not None:
            self.loop.source_remove(self._timer)
            self._timer = None
        if self.state == 'bluez' and self.discovery:
            self.discovery.stop()
        self._set('idle', 'service stopping')

    def set_mode(self, mode):
        if mode not in MODES or mode == self.mode:
            return
        log.info('scanner mode %s -> %s', self.mode, mode)
        self.mode = mode
        self.check()

    def note_advert(self, t=None):
        self._last_advert = t or self.clock()
        if self._silence_reported:
            log.info('Victron advertisements received again')
            self._silence_reported = False

    def status(self):
        return {'mode': self.mode, 'state': self.state, 'ble_sensors': self.ble_sensors,
                'since': round(self.since, 1), 'last_advert': self._last_advert}

    def _desired(self):
        if self.mode == 'none':
            return 'idle'
        if self.mode in ('venus', 'bluez'):
            return self.mode
        if self.ble_sensors == 1:
            return 'venus'
        if self.ble_sensors == 0 or self._unknown >= self.UNKNOWN_SETTING_LIMIT:
            return 'bluez'
        return self.state if self.state != 'idle' else 'idle'   # setting not readable yet: wait

    def _set(self, state, why):
        if state != self.state:
            log.info('scanning: %s -> %s (%s)', self.state, state, why)
            self.state = state
            self.since = self.clock()

    def check(self):
        if self.sensors is not None and self.mode != 'none':
            value = self.sensors.get()
            if value is None:
                self._unknown += 1
            else:
                self._unknown = 0
                if value != self.ble_sensors and self.ble_sensors is not None:
                    log.info('Venus OS Bluetooth sensors turned %s by the user', 'on' if value else 'off')
                self.ble_sensors = value
        desired = self._desired()
        if desired != self.state:
            if self.state == 'bluez' and self.discovery:
                self.discovery.stop()
            if desired == 'bluez':
                if not self.discovery or not self.discovery.start():
                    if not self._start_failed:
                        log.warning('our BlueZ discovery could not start, retrying every %d s',
                                    self.CHECK_INTERVAL_S)
                        self._start_failed = True
                    self._set('idle', 'BlueZ discovery not started')
                    return True
                if self._start_failed:
                    log.info('BlueZ discovery started after an earlier failure')
                    self._start_failed = False
                why = ('Venus OS Bluetooth sensors are off: using our own BlueZ discovery, '
                       'their setting is left unchanged' if self.mode == 'auto' else 'mode bluez')
            elif desired == 'venus':
                why = 'Venus OS Bluetooth sensors are on: relying on their scan'
            else:
                why = 'mode %s' % self.mode
            self._set(desired, why)
        elif self.state == 'bluez' and self.discovery and self.discovery.adapter_discovering() is False:
            log.warning('BlueZ discovery is no longer running (bluetoothd restarted?): starting it again')
            self.discovery.running = False
            self.discovery.start()
        if self.mode == 'bluez' and self.ble_sensors == 1 and not self._both_reported:
            log.warning('scanner mode bluez while Venus OS Bluetooth sensors are on: two scans run')
            self._both_reported = True
        self._watch_silence()
        return True

    def _watch_silence(self):
        if self.state == 'idle' or self._silence_reported:
            return
        ref = self._last_advert if self._last_advert is not None else self.since
        if self.clock() - ref > self.SILENCE_WARN_S:
            log.warning('no Victron advertisement for %d s while scanning (%s): Bluetooth adapter down, '
                        'or no device in range?', self.SILENCE_WARN_S, self.state)
            self._silence_reported = True
