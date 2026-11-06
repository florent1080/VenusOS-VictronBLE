import unittest

import _path  # noqa: F401
import parsers
import registry
from fake_velib import FakeBus, FakeSettingsDevice, FakeVeDbusService
from mappers import CONNECTION, MAPPERS, ChargerMapper, DcdcMapper

ORION = 'FC:00:00:00:00:01'
FRAME = bytes.fromhex('1000c0a304121d64ca8d442b90bbdf6a8cba')      # victron_ble public vector
KEY = '64ba49f1a8562e45197a8e1fe50d7658'


def orion_device(mac=ORION, name='Orion-Tr Smart'):
    return registry.DeviceEntry(mac, KEY, 'dcdc', name)


def make(bus, mac=ORION, name='Orion-Tr Smart'):
    return DcdcMapper(orion_device(mac, name), 0xA3C0, parsers.model_name(0xA3C0), bus, '0.4.0',
                      vedbus_cls=FakeVeDbusService, settings_cls=FakeSettingsDevice,
                      bus_factory=bus.connection)


class DcdcMapperTests(unittest.TestCase):
    def setUp(self):
        self.bus = FakeBus()
        self.m = make(self.bus)
        self.m.publish()
        self.svc = self.bus.names['com.victronenergy.dcdc.ble_fc0000000001']

    def test_registered_with_the_documented_paths(self):
        p = self.svc.paths
        self.assertTrue(self.svc.registered)
        self.assertEqual((p['/Mgmt/ProcessName'], p['/Mgmt/ProcessVersion'], p['/Mgmt/Connection']),
                         ('victron-ble', '0.4.0', CONNECTION))
        self.assertEqual(CONNECTION, 'Bluetooth (Instant Readout)')
        self.assertEqual((p['/DeviceInstance'], p['/ProductId'], p['/Connected']), (1, 0xA3C0, 0))
        self.assertEqual(self.svc.gettext('/ProductId'), '0xA3C0')
        self.assertEqual((p['/ProductName'], p['/CustomName']),
                         ('Orion Smart 12V/12V-18A DC-DC Converter', 'Orion-Tr Smart'))
        for path in ('/Dc/0/Voltage', '/Dc/In/V', '/State', '/ErrorCode', '/DeviceOffReason',
                     '/FirmwareVersion', '/HardwareVersion'):
            self.assertIsNone(p[path], path)
        for absent in ('/Mode', '/Dc/0/Current', '/Dc/In/I', '/Dc/0/Power', '/Relay/0/State'):
            self.assertNotIn(absent, p)         # no control path, no current: the Orion-Tr has none
        self.assertEqual(self.bus.settings['/Settings/Devices/victronble_fc0000000001/ClassAndVrmInstance'],
                         'dcdc:1')

    def test_update_disconnect_and_back(self):
        r = parsers.decode(FRAME, KEY, 'dcdc')
        self.m.update(r)
        p = self.svc.paths
        self.assertEqual((p['/Dc/In/V'], p['/Dc/0/Voltage'], p['/State'], p['/ErrorCode'], p['/DeviceOffReason'],
                          p['/Connected']), (13.15, None, 0, 0, 0x80, 1))
        self.assertEqual(self.svc.gettext('/Dc/In/V'), '13.15V')
        self.assertEqual(self.svc.gettext('/Dc/0/Voltage'), '---')
        self.assertEqual(self.svc.gettext('/DeviceOffReason'), '0x80')
        self.assertEqual(len(self.svc.flushes), 1)            # one ItemsChanged per reading
        self.m.disconnect()
        self.assertEqual((p['/Connected'], p['/Dc/In/V'], p['/State']), (0, None, None))
        self.assertTrue(self.svc.registered)                  # the service stays
        self.m.update(r)
        self.assertEqual((p['/Connected'], p['/Dc/In/V']), (1, 13.15))

    def test_instance_is_free_and_stable(self):
        other = make(self.bus, mac='AA:00:00:00:00:09', name='Second Orion')
        other.publish()
        self.assertEqual(other.instance, 2)                   # dcdc:1 is taken
        self.m.destroy()
        self.assertNotIn('com.victronenergy.dcdc.ble_fc0000000001', self.bus.names)
        again = make(self.bus)
        again.publish()
        self.assertEqual(again.instance, 1)                   # same device, same instance

    def test_instance_changed_by_the_user(self):
        with self.assertLogs('victronble.mappers', level='INFO') as logs:
            self.m.settings.change('instance', 'dcdc:7')
        self.assertEqual(self.svc.paths['/DeviceInstance'], 7)
        self.assertIn('device instance changed to 7', logs.output[0])

    def test_same_instance_signalled_is_not_a_change(self):
        # van, 2026-11-06: localsettings signals a setting it has just created, same value
        with self.assertNoLogs('victronble.mappers', level='INFO'):
            self.m.settings.change('instance', 'dcdc:1')
        self.assertEqual(self.svc.paths['/DeviceInstance'], 1)

    def test_destroy_releases_the_name(self):
        self.m.destroy()
        self.assertTrue(self.svc.removed)
        self.assertNotIn(self.svc.name, self.bus.names)
        self.m.update(parsers.decode(FRAME, KEY, 'dcdc'))     # no-op after destroy

    def test_publish_fails_when_localsettings_is_missing(self):
        bus = FakeBus()
        bus.fail_settings = True
        with self.assertRaises(Exception):
            make(bus).publish()
        self.assertEqual(bus.names, {})

    def test_only_the_name_is_writeable(self):
        self.assertEqual(sorted(self.svc.writeable), ['/CustomName'])
        for path in ('/Dc/In/V', '/State', '/DeviceInstance', '/ProductId', '/Connected'):
            self.assertFalse(self.svc.set_from_gui(path, 1), path)

    def test_rename_goes_through_the_callback(self):
        asked = []
        self.m.rename_cb = lambda mac, name: asked.append((mac, name)) or name != 'refused'
        self.assertTrue(self.svc.set_from_gui('/CustomName', 'Orion moteur'))
        self.assertEqual(self.svc.paths['/CustomName'], 'Orion moteur')
        self.assertFalse(self.svc.set_from_gui('/CustomName', 'refused'))
        self.assertEqual(self.svc.paths['/CustomName'], 'Orion moteur')
        self.assertFalse(self.svc.set_from_gui('/CustomName', 42))      # not a string: refused
        self.assertEqual(asked, [(ORION, 'Orion moteur'), (ORION, 'refused')])
        self.m.rename_cb = None                                          # no service behind: refused
        self.assertFalse(self.svc.set_from_gui('/CustomName', 'x'))

    def test_set_name_updates_in_place(self):
        self.m.set_name(orion_device(name='Renamed in the file'))
        self.assertEqual(self.svc.paths['/CustomName'], 'Renamed in the file')
        self.assertIn(self.svc.name, self.bus.names)

    def test_two_devices_need_their_own_connection(self):
        # seen on the van, 2026-11-06: a second VeDbusService on the same connection fails because
        # velib exports '/' on it; each published device must open its own private connection
        charger = make_charger(self.bus, parsers.decode(CHARGER_FRAME, CHARGER_KEY, 'charger').values)
        charger.publish()
        self.assertIn('com.victronenergy.charger.ble_cc0000000002', self.bus.names)
        self.assertIsNot(charger.svc.bus, self.m.svc.bus)
        self.assertIsNot(self.m.svc.bus, self.bus)                 # not the shared connection either
        conn = charger.svc.bus
        charger.destroy()
        self.assertTrue(conn.closed)                               # private connection released

    def test_registry(self):
        self.assertIs(MAPPERS['dcdc'], DcdcMapper)
        self.assertTrue(set(MAPPERS) <= set(parsers.DEVICE_TYPES))


CHARGER = 'CC:00:00:00:00:02'
CHARGER_FRAME = bytes.fromhex('100030a308f926c1b5170a0d2280335bf12d5ed083')   # victron_ble vector, IP22 12/30 (1)
CHARGER_KEY = 'c129cf8f75c3fe5a1655b481e205fb7d'


def make_charger(bus, values, model_id=0xA330):
    dev = registry.DeviceEntry(CHARGER, CHARGER_KEY, 'charger', 'Blue Smart')
    return ChargerMapper(dev, model_id, parsers.model_name(model_id), bus, '0.5.0', vedbus_cls=FakeVeDbusService,
                         settings_cls=FakeSettingsDevice, first_values=values, bus_factory=bus.connection)


class ChargerMapperTests(unittest.TestCase):
    def test_single_output_model(self):
        bus = FakeBus()
        r = parsers.decode(CHARGER_FRAME, CHARGER_KEY, 'charger')
        m = make_charger(bus, r.values)
        m.publish()
        m.update(r)
        svc = bus.names['com.victronenergy.charger.ble_cc0000000002']
        p = svc.paths
        self.assertEqual((p['/NrOfOutputs'], p['/Dc/0/Voltage'], p['/Dc/0/Current'], p['/State'], p['/ErrorCode']),
                         (1, 13.49, 0.4, 6, 0))
        self.assertEqual((svc.gettext('/Dc/0/Voltage'), svc.gettext('/Dc/0/Current')), ('13.49V', '0.4A'))
        for absent in ('/Dc/1/Voltage', '/Dc/2/Voltage', '/Ac/In/L1/I', '/Dc/0/Temperature', '/Mode',
                       '/Relay/0/State'):
            self.assertNotIn(absent, p)
        self.assertEqual(sorted(svc.writeable), ['/CustomName'])
        m.disconnect()
        self.assertEqual((p['/Connected'], p['/Dc/0/Current'], p['/NrOfOutputs']), (0, None, 1))

    def test_three_output_model(self):
        bus = FakeBus()
        values = {'state': 3, 'error': 0, 'output_voltage1': 13.2, 'output_current1': 10.0,
                  'output_voltage2': None, 'output_current2': None, 'output_voltage3': None,
                  'output_current3': None, 'temperature': None, 'ac_current': 2.5}
        m = make_charger(bus, values, model_id=0xA321)          # "Blue Smart IP22 Charger 12|15 (3)"
        self.assertIn('(3)', m.product_name)
        m.publish()
        p = bus.names['com.victronenergy.charger.ble_cc0000000002'].paths
        self.assertEqual(p['/NrOfOutputs'], 3)
        for i in range(3):
            self.assertIn('/Dc/%d/Voltage' % i, p)
            self.assertIn('/Dc/%d/Current' % i, p)
        self.assertIn('/Ac/In/L1/I', p)                         # this one reports its AC current

    def test_outputs_seen_in_the_first_reading(self):
        from mappers.charger import nr_outputs
        self.assertEqual(nr_outputs('Phoenix Smart', {'output_voltage2': 13.0}), 2)
        self.assertEqual(nr_outputs('Blue Smart IP65 Charger 12|25', {}), 1)


if __name__ == '__main__':
    unittest.main()
