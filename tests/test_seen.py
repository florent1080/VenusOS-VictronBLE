import json
import os
import shutil
import tempfile
import unittest

import _path  # noqa: F401
import parsers
import registry
from listener import Advert
from seen import SeenTable

ORION = 'FC:00:00:00:00:01'
FRAME = bytes.fromhex('1000c0a304121d64ca8d442b90bbdf6a8cba')
KEY = '64ba49f1a8562e45197a8e1fe50d7658'


class Clock(object):
    t = 1000.0

    def __call__(self):
        return self.t


class SeenTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='vble-seen-')
        self.path = os.path.join(self.dir, 'run', 'seen.json')
        self.clock = Clock()
        self.table = SeenTable(self.path, write_interval_s=5, clock=self.clock)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def advert(self, mac=ORION, mfg=FRAME, rssi=-55):
        return Advert(mac, rssi, mfg, self.clock(), 'test')

    def test_not_whitelisted_device(self):
        self.table.update(self.advert(), parsers.parse_header(FRAME), 'not_whitelisted')
        d = self.table.to_dict()['devices'][0]
        self.assertEqual((d['mac'], d['model_id'], d['record_type'], d['supported_type'], d['key_check']),
                         (ORION, '0xA3C0', '0x04', 'dcdc', '64'))
        self.assertEqual((d['whitelisted'], d['status'], d['rssi']), (False, 'not_whitelisted', -55))

    def test_whitelisted_reading_and_no_key_in_file(self):
        cfg = registry.validate({'version': 1, 'devices': [
            {'mac': ORION, 'key': KEY, 'type': 'dcdc', 'name': 'Orion'}]}).config
        self.table.set_whitelist(cfg)
        r = parsers.decode(FRAME, KEY)
        self.table.update(self.advert(), parsers.parse_header(FRAME), 'ok', r)
        self.assertTrue(self.table.flush())
        with open(self.path, encoding='utf-8') as f:
            text = f.read()
        self.assertNotIn(KEY, text)
        d = json.loads(text)['devices'][0]
        self.assertEqual((d['name'], d['status'], d['values']['input_voltage']), ('Orion', 'ok', 13.15))
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ['seen.json'])
        # removed from the whitelist: decoded values disappear
        self.table.set_whitelist(registry.Config())
        d = self.table.to_dict()['devices'][0]
        self.assertEqual((d['whitelisted'], d['status'], d['values']), (False, 'not_whitelisted', None))

    def test_other_victron_frames_counted(self):
        self.table.update(self.advert(mfg=bytes.fromhex('02e7b5147898')))
        d = self.table.to_dict()['devices'][0]
        self.assertEqual((d['frames'], d['ir_frames'], d['record_type']), (1, 0, None))

    def test_flush_rate_limit(self):
        self.table.update(self.advert())
        self.assertTrue(self.table.flush())
        self.table.update(self.advert())
        self.assertFalse(self.table.flush())          # less than 5 s later
        self.clock.t += 6
        self.assertTrue(self.table.flush())
        self.assertFalse(self.table.flush())          # nothing changed
        self.assertTrue(self.table.flush(force=True))

    def test_vedirect_duplicate(self):
        self.table.update(self.advert(), parsers.parse_header(FRAME), 'not_whitelisted')
        self.table.set_vedirect({0xA3C0: ['com.victronenergy.dcdc.ttyUSB9']})
        self.assertEqual(self.table.to_dict()['devices'][0]['vedirect_duplicate'], ['com.victronenergy.dcdc.ttyUSB9'])

    def test_forget_and_bounded_size(self):
        self.table.MAX_DEVICES = 3
        for i in range(5):
            self.clock.t += 1
            self.table.update(self.advert(mac='AA:00:00:00:00:%02X' % i))
        self.assertEqual(len(self.table.devices), 3)
        self.assertNotIn('AA:00:00:00:00:00', self.table.devices)
        self.clock.t += 4000
        self.table.flush(force=True)
        self.assertEqual(self.table.devices, {})

    def test_write_error_is_logged_not_raised(self):
        table = SeenTable(os.path.join(self.dir, 'file-not-dir', 'seen.json'), clock=self.clock)
        with open(os.path.join(self.dir, 'file-not-dir'), 'w') as f:
            f.write('x')
        table.update(self.advert())
        with self.assertLogs('victronble.seen', level='ERROR'):
            self.assertFalse(table.flush())


if __name__ == '__main__':
    unittest.main()
