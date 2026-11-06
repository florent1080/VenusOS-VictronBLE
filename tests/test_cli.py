import io
import json
import os
import shutil
import tempfile
import unittest

import _path
import cli
import registry

ORION_FRAME = '1000c0a304121d64ca8d442b90bbdf6a8cba'      # victron_ble public test vector
ORION_KEY = '64ba49f1a8562e45197a8e1fe50d7658'


def run(*argv):
    out = io.StringIO()
    code = cli.main(list(argv), out)
    return code, out.getvalue()


class ValidateCommandTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='vble-cli-')
        self.path = os.path.join(self.dir, 'victron-ble.json')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, data):
        with open(self.path, 'w', encoding='utf-8') as f:
            f.write(data if isinstance(data, str) else json.dumps(data))

    def test_valid(self):
        self.write({'version': 1, 'devices': [
            {'mac': 'fc:00:00:00:00:01', 'key': ORION_KEY, 'type': 'dcdc', 'name': 'Orion'}]})
        code, out = run('validate', '-c', self.path)
        self.assertEqual(code, 0, out)
        self.assertIn('OK, 1 device(s), timeout 60 s', out)
        self.assertIn('FC:00:00:00:00:01', out)
        self.assertIn('key 64****', out)
        self.assertNotIn(ORION_KEY, out)

    def test_invalid(self):
        self.write({'version': 1, 'devices': [{'mac': 'nope', 'key': 'short', 'type': 'dcdc'}]})
        code, out = run('validate', '-c', self.path)
        self.assertEqual(code, 1)
        self.assertIn('INVALID', out)
        self.assertIn('devices[0].mac', out)
        self.assertIn('devices[0].key', out)

    def test_missing_file(self):
        code, out = run('validate', '-c', self.path)
        self.assertEqual(code, 1)
        self.assertIn('file not found', out)

    def test_warnings_shown(self):
        self.write({'version': 1, 'extra': True})
        code, out = run('validate', '-c', self.path)
        self.assertEqual(code, 0)
        self.assertIn("warning: unknown field 'extra'", out)


class DecodeCommandTests(unittest.TestCase):
    def test_hex_frame(self):
        code, out = run('decode', '--key', ORION_KEY, ORION_FRAME)
        self.assertEqual(code, 0, out)
        self.assertIn('Orion Smart 12V/12V-18A DC-DC Converter', out)
        self.assertIn('input_voltage=13.15 V', out)
        self.assertIn('summary: decoded 1', out)

    def test_frame_pasted_with_company_id(self):
        code, out = run('decode', '--key', ORION_KEY, 'e102' + ORION_FRAME)
        self.assertEqual(code, 0, out)

    def test_wrong_key(self):
        code, out = run('decode', '--key', '00' * 16, ORION_FRAME)
        self.assertEqual(code, 1)
        self.assertIn('KeyMismatch 1', out)

    def test_recorded_jsonl_without_the_real_key(self):
        path = os.path.join(_path.FIXTURES, 'recorded_frames.jsonl')
        code, out = run('decode', '--key', '9c' + '00' * 15, '--mac', 'fc:00:00:00:00:01', '--jsonl', path)
        self.assertEqual(code, 0, out)                 # right check byte: decodes (garbage values)
        self.assertIn('summary: decoded 150', out)

    def test_key_from_config(self):
        d = tempfile.mkdtemp(prefix='vble-cli-')
        try:
            p = os.path.join(d, 'c.json')
            registry.save({'version': 1, 'devices': [
                {'mac': 'FC:00:00:00:00:01', 'key': ORION_KEY, 'type': 'dcdc'}]}, p)
            code, out = run('decode', '-c', p, '--mac', 'FC:00:00:00:00:01', ORION_FRAME)
            self.assertEqual(code, 0, out)
            code, out = run('decode', '-c', p, '--mac', '00:00:00:00:00:01', ORION_FRAME)
            self.assertEqual(code, 2)
            self.assertIn('not whitelisted', out)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_usage_errors(self):
        self.assertEqual(run('decode', '--key', ORION_KEY)[0], 2)
        self.assertEqual(run('decode', ORION_FRAME)[0], 2)
        self.assertEqual(run('decode', '--key', ORION_KEY, 'zz')[0], 1)
        self.assertEqual(run()[0], 2)


class DiscoverAddRemoveTests(unittest.TestCase):
    ORION = 'FC:00:00:00:00:01'

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='vble-cli-')
        self.config = os.path.join(self.dir, 'victron-ble.json')
        self.seen = os.path.join(self.dir, 'seen.json')
        devices = [
            {'mac': self.ORION, 'model_id': '0xA3C0', 'model_name': 'Orion Smart 12V/12V-18A DC-DC Converter',
             'record_type': '0x04', 'record_name': 'DC/DC converter', 'supported_type': 'dcdc', 'key_check': '9c',
             'rssi': -53, 'age_s': 0.4, 'whitelisted': False, 'status': 'not_whitelisted', 'vedirect_duplicate': None},
            {'mac': 'FE:00:00:00:00:03', 'model_id': '0xA383', 'model_name': 'BMV-712 Smart',
             'record_type': '0x02', 'record_name': 'Battery monitor', 'supported_type': None, 'key_check': '93',
             'rssi': -37, 'age_s': 0.2, 'whitelisted': False, 'status': 'not_whitelisted',
             'vedirect_duplicate': ['com.victronenergy.battery.ttyUSB0']},
            {'mac': 'AA:BB:CC:00:00:01', 'record_type': None, 'whitelisted': False, 'age_s': 3},
        ]
        import time
        with open(self.seen, 'w', encoding='utf-8') as f:
            json.dump({'version': 1, 'updated': time.time(), 'pid': 1, 'devices': devices,
                       'scanner': {'state': 'venus', 'mode': 'auto', 'ble_sensors': 1},
                       'service': {'config_status': 'missing'}}, f)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_discover(self):
        code, out = run('discover', '--seen', self.seen)
        self.assertEqual(code, 0, out)
        self.assertIn('scanning: venus (mode auto, Venus OS Bluetooth sensors on)', out)
        self.assertIn('not whitelisted (victron-ble add FC:00:00:00:00:01 --type dcdc)', out)
        self.assertIn('Battery monitor: not supported yet', out)
        self.assertIn('already on D-Bus: com.victronenergy.battery.ttyUSB0', out)
        self.assertNotIn('AA:BB:CC:00:00:01', out)
        self.assertIn('1 device(s) without Instant Readout frame hidden', out)
        self.assertIn('AA:BB:CC:00:00:01', run('discover', '--seen', self.seen, '--all')[1])
        self.assertEqual(json.loads(run('discover', '--seen', self.seen, '--json')[1])['pid'], 1)

    def test_discover_without_service(self):
        code, out = run('discover', '--seen', os.path.join(self.dir, 'nope.json'))
        self.assertEqual(code, 1)
        self.assertIn('is the victron-ble service running?', out)

    def test_add_checks_the_key_against_the_broadcast_byte(self):
        code, out = run('add', self.ORION, '--key', ORION_KEY, '-c', self.config, '--seen', self.seen)
        self.assertEqual(code, 1)
        self.assertIn('broadcasts key check 9c but this key starts with 64', out)
        self.assertFalse(os.path.exists(self.config))
        code, out = run('add', self.ORION, '--key', ORION_KEY, '--force', '-c', self.config, '--seen', self.seen)
        self.assertEqual(code, 0, out)

    def test_add_type_from_seen_then_remove(self):
        key = '9c' + 'ab' * 15
        code, out = run('add', self.ORION.lower(), '--key', key, '--name', 'Orion-Tr Smart',
                        '-c', self.config, '--seen', self.seen)
        self.assertEqual(code, 0, out)
        self.assertIn('added as dcdc "Orion-Tr Smart"', out)
        dev = registry.load(self.config).config.devices[0]
        self.assertEqual((dev.mac, dev.type, dev.name, dev.key), (self.ORION, 'dcdc', 'Orion-Tr Smart', key))
        self.assertEqual(run('add', self.ORION, '--key', key, '-c', self.config, '--seen', self.seen)[0], 1)
        code, out = run('remove', self.ORION, '-c', self.config)
        self.assertEqual(code, 0, out)
        self.assertEqual(registry.load(self.config).config.devices, [])
        self.assertEqual(run('remove', self.ORION, '-c', self.config)[0], 1)

    def test_add_refuses_a_vedirect_duplicate_and_unsupported_types(self):
        code, out = run('add', 'FE:00:00:00:00:03', '--key', '93' + '00' * 15, '--type', 'dcdc',
                        '-c', self.config, '--seen', self.seen)
        self.assertEqual(code, 1)
        self.assertIn('already published by com.victronenergy.battery.ttyUSB0', out)
        code, out = run('add', 'FE:00:00:00:00:03', '--key', '93' + '00' * 15, '-c', self.config, '--seen', self.seen)
        self.assertEqual(code, 2)
        self.assertIn('give --type', out)

    def test_add_refuses_to_edit_an_invalid_file(self):
        with open(self.config, 'w') as f:
            f.write('{broken')
        code, out = run('add', self.ORION, '--key', '9c' + '00' * 15, '-c', self.config, '--seen', self.seen)
        self.assertEqual(code, 1)
        self.assertIn('fix it first', out)


if __name__ == '__main__':
    unittest.main()
