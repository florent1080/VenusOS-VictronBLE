"""Whole chain without Bluetooth nor D-Bus: replay -> service -> seen.json (virtual time)."""

import json
import os
import shutil
import tempfile
import unittest

import _path
import main
import registry
from listener import ReplayListener
from loop import SimpleLoop
from scanner import ScanDriver

# victron_ble public vectors, under made-up MAC addresses
ORION_MAC, ORION_FRAME, ORION_KEY = ('AA:00:00:00:00:01', '1000c0a304121d64ca8d442b90bbdf6a8cba',
                                     '64ba49f1a8562e45197a8e1fe50d7658')
CHARGER_MAC, CHARGER_FRAME, CHARGER_KEY = ('AA:00:00:00:00:02', '100030a308f926c1b5170a0d2280335bf12d5ed083',
                                           'c129cf8f75c3fe5a1655b481e205fb7d')
BMV_MAC = 'FE:00:00:00:00:03'
BMV_IR = '100283a3027d799366aa6b293cf97ab63d76e27d5a4690'
BMV_OTHER = '02e7b5147898fe1894487858454c721fe0ccbe5e264e'


def device(mac, key, dtype, name=''):
    return {'mac': mac, 'key': key, 'type': dtype, 'name': name}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='vble-svc-')
        self.config = os.path.join(self.dir, 'victron-ble.json')
        self.seen = os.path.join(self.dir, 'seen.json')
        self.frames = os.path.join(self.dir, 'frames.jsonl')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write_config(self, devices, **extra):
        data = {'version': 1, 'devices': devices}
        data.update(extra)
        registry.save(data, self.config)

    def write_frames(self, frames, extra_lines=()):
        with open(self.frames, 'w', encoding='utf-8') as f:
            for t, mac, mfg in frames:
                f.write(json.dumps({'t': t, 'mac': mac, 'mfg': mfg, 'rssi': -60}) + '\n')
            for line in extra_lines:
                f.write(line + '\n')

    def run_service(self, during=None, bus=None, products=None):
        loop = SimpleLoop(virtual=True, start=1000000.0)
        import mappers
        from fake_velib import FakeSettingsDevice, FakeVeDbusService

        def factory(dev, reading):
            return mappers.MAPPERS[dev.type](dev, reading.model_id, reading.model_name, bus, main.VERSION,
                                             vedbus_cls=FakeVeDbusService, settings_cls=FakeSettingsDevice,
                                             bus_factory=bus.connection, first_values=reading.values)
        svc = main.Service(loop, self.config, self.seen, clock=loop.now, scanner_override='none',
                           log_level_override='INFO', mapper_factory=factory if bus is not None else None)
        svc.products = products or {}
        self.service = svc
        src = ReplayListener(loop, svc.on_advert, self.frames, speed=1.0, on_end=loop.quit)
        for t, fn in (during or []):
            loop.timeout_add_seconds(t, lambda fn=fn: fn() or False, repeat_on_error=False)
        svc.start(src, ScanDriver(loop, 'none'))
        loop.run()
        svc.stop()
        with open(self.seen, encoding='utf-8') as f:
            text = f.read()
        return svc, json.loads(text), text

    @staticmethod
    def by_mac(doc):
        return dict((d['mac'], d) for d in doc['devices'])

    def every_second(self, mac, frame, start, stop):
        return [(t, mac, frame) for t in range(start, stop)]

    def test_whitelisted_devices_are_decoded(self):
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc', 'Orion'),
                           device(CHARGER_MAC, CHARGER_KEY, 'charger', 'Blue Smart')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 20)
                          + self.every_second(CHARGER_MAC, CHARGER_FRAME, 0, 20)
                          + [(1, BMV_MAC, BMV_IR), (2, BMV_MAC, BMV_OTHER)],
                          extra_lines=['{"mac": "AA:00:00:00:00:09", "mfg": "zz"}', 'not json'])
        with self.assertLogs('victronble', level='INFO') as logs:
            svc, doc, text = self.run_service()
        devs = self.by_mac(doc)
        self.assertEqual((devs[ORION_MAC]['status'], devs[ORION_MAC]['values']['input_voltage']), ('ok', 13.15))
        self.assertEqual((devs[CHARGER_MAC]['status'], devs[CHARGER_MAC]['values']['output_current1']), ('ok', 0.4))
        self.assertEqual((devs[BMV_MAC]['status'], devs[BMV_MAC]['whitelisted']), ('not_whitelisted', False))
        self.assertEqual((devs[BMV_MAC]['frames'], devs[BMV_MAC]['ir_frames']), (2, 1))
        self.assertNotIn(ORION_KEY, text)
        self.assertNotIn(CHARGER_KEY, text)
        self.assertEqual(svc.counters['decoded'], 2)            # repeated payloads are not decrypted again
        self.assertEqual(doc['service']['config_status'], 'ok')
        self.assertTrue(any('Orion (AA:00:00:00:00:01)' in m and 'heard' in m for m in logs.output))

    def test_wrong_key_reported_once(self):
        self.write_config([device(ORION_MAC, '00' * 16, 'dcdc', 'Orion')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 30))
        with self.assertLogs('victronble', level='WARNING') as logs:
            svc, doc, _ = self.run_service()
        self.assertEqual(self.by_mac(doc)[ORION_MAC]['status'], 'key_mismatch')
        warnings = [m for m in logs.output if 'key rejected' in m]
        self.assertEqual(len(warnings), 1)
        self.assertIn('Bluetooth PIN', warnings[0])

    def test_type_mismatch(self):
        self.write_config([device(ORION_MAC, ORION_KEY, 'charger')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 5))
        with self.assertLogs('victronble', level='WARNING'):
            svc, doc, _ = self.run_service()
        d = self.by_mac(doc)[ORION_MAC]
        self.assertEqual(d['status'], 'type_mismatch')
        self.assertIn('advertises DC/DC converter', d['error'])

    def test_hot_reload_adds_a_device(self):
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 40)
                          + self.every_second(CHARGER_MAC, CHARGER_FRAME, 0, 40))

        def add_charger():
            self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc'),
                               device(CHARGER_MAC, CHARGER_KEY, 'charger', 'added live')])
        with self.assertLogs('victronble', level='INFO') as logs:
            svc, doc, _ = self.run_service(during=[(12, add_charger)])
        self.assertEqual(self.by_mac(doc)[CHARGER_MAC]['status'], 'ok')
        self.assertEqual(self.by_mac(doc)[CHARGER_MAC]['name'], 'added live')
        self.assertTrue(any('added %s' % CHARGER_MAC in m for m in logs.output))

    def test_invalid_reload_keeps_the_working_whitelist(self):
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 30))

        def break_file():
            with open(self.config, 'w') as f:
                f.write('{"version": 1, "devices": [')
        with self.assertLogs('victronble', level='ERROR'):
            svc, doc, _ = self.run_service(during=[(7, break_file)])
        self.assertEqual(self.by_mac(doc)[ORION_MAC]['status'], 'ok')
        self.assertEqual(doc['service']['config_status'], 'invalid (previous configuration kept)')

    def test_mistake_undone_clears_the_invalid_status(self):
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 30))
        with open(self.config, encoding='utf-8') as f:
            good = f.read()

        def break_file():
            with open(self.config, 'w') as f:
                f.write('{"version": 1, "devices": [')

        def repair():
            with open(self.config, 'w', newline='\n') as f:
                f.write(good)
        with self.assertLogs('victronble', level='INFO') as logs:
            svc, doc, _ = self.run_service(during=[(7, break_file), (17, repair)])
        self.assertEqual(doc['service']['config_status'], 'ok')
        self.assertTrue(any('configuration valid again' in m for m in logs.output))

    def test_timeout_and_never_heard(self):
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc', 'Orion'),
                           device(CHARGER_MAC, CHARGER_KEY, 'charger', 'Charger')], timeout_s=10)
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 5)
                          + [(60, BMV_MAC, BMV_OTHER)])            # keeps the replay going to t=60
        with self.assertLogs('victronble', level='WARNING') as logs:
            self.run_service()
        text = '\n'.join(logs.output)
        self.assertIn('Orion (AA:00:00:00:00:01): nothing heard for 10 s, marked disconnected', text)
        self.assertIn('Charger (AA:00:00:00:00:02): no Instant Readout heard since it was whitelisted', text)

    def test_device_added_late_is_not_reported_missing(self):
        # soak test on the van, 2026-11-06: a device re-added 4 min after start was reported
        # "never heard" before its first frame, because the delay counted from the service start
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')], timeout_s=10)
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 60)
                          + [(t, CHARGER_MAC, CHARGER_FRAME) for t in range(33, 60)])

        def add_charger():
            self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc'),
                               device(CHARGER_MAC, CHARGER_KEY, 'charger', 'Charger')], timeout_s=10)
        with self.assertLogs('victronble', level='INFO') as logs:
            svc, doc, _ = self.run_service(during=[(30, add_charger)])
        self.assertFalse([m for m in logs.output if 'no Instant Readout heard' in m], logs.output)
        self.assertEqual(self.by_mac(doc)[CHARGER_MAC]['status'], 'ok')

    def test_missing_configuration_still_lists_devices(self):
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 3))
        with self.assertLogs('victronble.registry', level='WARNING'):
            svc, doc, _ = self.run_service()
        self.assertEqual(doc['service']['config_status'], 'missing')
        self.assertEqual(self.by_mac(doc)[ORION_MAC]['supported_type'], 'dcdc')

    # ------------------------------------------------------ D-Bus publishing ----

    def orion_service(self, bus):
        return bus.names.get('com.victronenergy.dcdc.ble_aa0000000001')

    def test_orion_published_disconnected_and_back(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc', 'Orion')], timeout_s=10)
        # heard 0-9 s, silent 10-39 s, heard again 40-49 s with the SAME payload
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 10)
                          + self.every_second(ORION_MAC, ORION_FRAME, 40, 50))
        snapshots = []

        def look():
            s = self.orion_service(bus)
            snapshots.append(s and (s.paths['/Connected'], s.paths['/Dc/In/V']))
        with self.assertLogs('victronble', level='INFO'):
            svc, doc, _ = self.run_service(bus=bus, during=[(5, look), (30, look)])
        self.assertEqual(snapshots, [(1, 13.15), (0, None)])     # disconnected after 10 s, service kept
        s = self.orion_service(bus)
        self.assertIsNone(s)                                      # released when the service stopped
        self.assertEqual(self.by_mac(doc)[ORION_MAC]['dbus'], None)
        self.assertEqual(self.service.counters['decoded'], 2)    # decoded again when it came back

    def test_orion_back_after_timeout_reconnects(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')], timeout_s=10)
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 5)
                          + self.every_second(ORION_MAC, ORION_FRAME, 30, 40))
        seen = []
        with self.assertLogs('victronble', level='INFO'):
            self.run_service(bus=bus, during=[(38, lambda: seen.append(self.orion_service(bus).paths['/Connected']))])
        self.assertEqual(seen, [1])

    def test_duplicate_of_a_vedirect_device_is_not_published(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 5))
        with self.assertLogs('victronble', level='WARNING') as logs:
            svc, doc, _ = self.run_service(bus=bus, products={0xA3C0: ['com.victronenergy.dcdc.ttyUSB9']})
        self.assertEqual(bus.names, {})
        self.assertIn('NOT published', '\n'.join(logs.output))
        self.assertIn('duplicate of com.victronenergy.dcdc.ttyUSB9', self.by_mac(doc)[ORION_MAC]['dbus_note'])

    def test_allow_duplicate_publishes_anyway(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        dev = device(ORION_MAC, ORION_KEY, 'dcdc')
        dev['allow_duplicate'] = True
        self.write_config([dev])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 5))
        published = []
        with self.assertLogs('victronble', level='INFO'):
            self.run_service(bus=bus, products={0xA3C0: ['com.victronenergy.dcdc.ttyUSB9']},
                             during=[(3, lambda: published.append(sorted(bus.names)))])
        self.assertEqual(published, [['com.victronenergy.dcdc.ble_aa0000000001']])

    def test_removed_from_whitelist_leaves_dbus(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 30))
        names = []
        with self.assertLogs('victronble', level='INFO'):
            self.run_service(bus=bus, during=[(4, lambda: names.append(sorted(bus.names))),
                                              (10, lambda: self.write_config([])),
                                              (20, lambda: names.append(sorted(bus.names)))])
        self.assertEqual(names, [['com.victronenergy.dcdc.ble_aa0000000001'], []])

    def test_rename_from_the_gui_is_saved_without_republishing(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc', 'Orion'),
                           device(CHARGER_MAC, CHARGER_KEY, 'charger', 'Charger')], timeout_s=30)
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 40))
        got = {}

        def gui_rename():
            s = self.orion_service(bus)
            got['service'] = s
            got['accepted'] = s.set_from_gui('/CustomName', 'Orion moteur')
            got['too_long'] = s.set_from_gui('/CustomName', 'x' * 65)

        def look():
            got['after'] = self.orion_service(bus)
        with self.assertLogs('victronble', level='INFO') as logs:
            self.run_service(bus=bus, during=[(5, gui_rename), (15, look)])
        self.assertTrue(got['accepted'])
        self.assertFalse(got['too_long'])
        self.assertIs(got['after'], got['service'])                        # same service: no flap
        self.assertEqual(got['after'].paths['/CustomName'], 'Orion moteur')
        cfg = registry.load(self.config).config.by_mac()
        self.assertEqual(cfg[ORION_MAC].name, 'Orion moteur')              # persisted
        self.assertEqual(cfg[CHARGER_MAC].name, 'Charger')                 # the rest of the file kept
        self.assertTrue(any('renamed %s' % ORION_MAC in m for m in logs.output))

    def test_rename_refused_while_the_file_is_broken(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc', 'Orion')])
        self.write_frames(self.every_second(ORION_MAC, ORION_FRAME, 0, 20))
        broken = '{"version": 1, "devices": ['
        got = {}

        def edit_by_hand():
            with open(self.config, 'w') as f:
                f.write(broken)

        def gui_rename():
            got['accepted'] = self.orion_service(bus).set_from_gui('/CustomName', 'Orion moteur')
        with self.assertLogs('victronble', level='WARNING') as logs:
            self.run_service(bus=bus, during=[(5, edit_by_hand), (6, gui_rename)])
        self.assertFalse(got['accepted'])
        with open(self.config) as f:
            self.assertEqual(f.read(), broken)                            # the user's edit untouched
        self.assertTrue(any('rename of %s refused' % ORION_MAC in m for m in logs.output))

    def test_type_without_mapper_decoded_but_not_published(self):
        import mappers
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(CHARGER_MAC, CHARGER_KEY, 'charger')])
        # a new payload every second, as on the van (the warning was once repeated for each one)
        self.write_frames([(t, CHARGER_MAC, CHARGER_FRAME[:-2] + '%02x' % t) for t in range(20)])
        saved = mappers.MAPPERS.pop('charger')
        try:
            with self.assertLogs('victronble', level='WARNING') as logs:
                svc, doc, _ = self.run_service(bus=bus)
        finally:
            mappers.MAPPERS['charger'] = saved
        self.assertEqual(bus.names, {})
        self.assertEqual(sum('no D-Bus mapper for type charger' in m for m in logs.output), 1)
        self.assertEqual(self.by_mac(doc)[CHARGER_MAC]['status'], 'ok')

    def test_charger_published(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        self.write_config([device(CHARGER_MAC, CHARGER_KEY, 'charger', 'Blue Smart'),
                           device(ORION_MAC, ORION_KEY, 'dcdc', 'Orion')])
        self.write_frames(self.every_second(CHARGER_MAC, CHARGER_FRAME, 0, 10)
                          + self.every_second(ORION_MAC, ORION_FRAME, 0, 10))
        got = {}
        with self.assertLogs('victronble', level='INFO'):
            self.run_service(bus=bus, during=[(5, lambda: got.update(
                charger=dict(bus.names['com.victronenergy.charger.ble_aa0000000002'].paths),
                names=sorted(bus.names)))])
        p = got['charger']
        self.assertEqual((p['/NrOfOutputs'], p['/Dc/0/Voltage'], p['/Dc/0/Current'], p['/State'], p['/ErrorCode'],
                          p['/Connected'], p['/CustomName'], p['/DeviceInstance']),
                         (1, 13.49, 0.4, 6, 0, 1, 'Blue Smart', 1))
        self.assertEqual(got['names'], ['com.victronenergy.charger.ble_aa0000000002',
                                        'com.victronenergy.dcdc.ble_aa0000000001'])
        # both got instance 1: VRM instances are unique per device class
        self.assertEqual(bus.settings['/Settings/Devices/victronble_aa0000000001/ClassAndVrmInstance'], 'dcdc:1')
        self.assertEqual(bus.settings['/Settings/Devices/victronble_aa0000000002/ClassAndVrmInstance'], 'charger:1')

    def test_publishing_retried_until_localsettings_answers(self):
        from fake_velib import FakeBus
        bus = FakeBus()
        bus.fail_settings = True
        self.write_config([device(ORION_MAC, ORION_KEY, 'dcdc')])
        frames = [(t, ORION_MAC, ORION_FRAME[:-2] + '%02x' % t) for t in range(0, 70)]   # new payload each second
        self.write_frames(frames)
        names = []

        def settings_up():
            bus.fail_settings = False
        with self.assertLogs('victronble', level='ERROR') as logs:
            self.run_service(bus=bus, during=[(10, settings_up), (65, lambda: names.append(sorted(bus.names)))])
        self.assertEqual(sum('publishing on D-Bus failed' in m for m in logs.output), 1)
        self.assertEqual(names, [['com.victronenergy.dcdc.ble_aa0000000001']])

    def test_recorded_frames_with_the_real_keys(self):
        keys_file = os.path.join(_path.FIXTURES, 'keys.local.json')
        if not os.path.exists(keys_file):
            self.skipTest('no tests/fixtures/keys.local.json')
        with open(keys_file, encoding='utf-8') as f:
            keys = dict((k.upper(), v) for k, v in json.load(f).items())
        orion, charger = 'FC:00:00:00:00:01', 'CC:00:00:00:00:02'
        if orion not in keys or charger not in keys:
            self.skipTest('keys of the Orion and of the Blue Smart needed')
        self.write_config([device(orion, keys[orion], 'dcdc', 'Orion-Tr Smart'),
                           device(charger, keys[charger], 'charger', 'Blue Smart IP65')])
        frames = []
        with open(os.path.join(_path.FIXTURES, 'recorded_frames.jsonl'), encoding='utf-8') as f:
            for line in f:
                r = json.loads(line)
                if r['source'] == 'venus-ble-diag4' or r['mac'] != charger:
                    frames.append((len(frames) * 0.2, r['mac'], r['mfg']))
        self.write_frames(frames)
        with self.assertLogs('victronble', level='INFO'):
            svc, doc, _ = self.run_service()
        devs = self.by_mac(doc)
        self.assertEqual((devs[orion]['status'], devs[charger]['status']), ('ok', 'ok'))
        self.assertEqual(devs[charger]['values']['state'], 3)         # BULK
        self.assertEqual(devs[orion]['model_name'], 'Orion Smart 12V/12V-18A DC-DC Converter')


if __name__ == '__main__':
    unittest.main()
