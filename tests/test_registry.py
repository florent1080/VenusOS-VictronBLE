import json
import os
import shutil
import tempfile
import unittest

import _path  # noqa: F401
import registry

KEY1 = '0123456789abcdef0123456789abcdef'
KEY2 = 'fedcba9876543210fedcba9876543210'


def sample():
    return {
        'version': 1,
        'timeout_s': 60,
        'devices': [
            {'mac': 'AA:BB:CC:DD:EE:FF', 'key': KEY1, 'type': 'dcdc', 'name': 'Orion-Tr Smart'},
            {'mac': '11:22:33:44:55:66', 'key': KEY2, 'type': 'charger', 'name': 'Blue Smart IP22'},
        ],
    }


class ValidateTests(unittest.TestCase):
    def assertError(self, data, fragment):
        res = registry.validate(data)
        self.assertFalse(res.ok, 'expected an error containing %r' % fragment)
        self.assertTrue(any(fragment in e for e in res.errors), res.errors)
        for e in res.errors:   # keys never leak into messages
            self.assertNotIn(KEY1, e)
            self.assertNotIn(KEY2, e)
        return res

    def test_sample_from_the_spec(self):
        res = registry.validate(sample())
        self.assertTrue(res.ok, res.errors)
        self.assertEqual(res.warnings, [])
        c = res.config
        self.assertEqual((c.version, c.timeout_s, c.log_level), (1, 60, 'INFO'))
        self.assertEqual([d.type for d in c.devices], ['dcdc', 'charger'])

    def test_normalization(self):
        data = sample()
        data['devices'][0].update(mac=' aa:bb:cc:dd:ee:ff ', key=KEY1.upper(), name='  Orion  ')
        data['log_level'] = 'debug'
        c = registry.validate(data).config
        d = c.devices[0]
        self.assertEqual((d.mac, d.key, d.name, c.log_level), ('AA:BB:CC:DD:EE:FF', KEY1, 'Orion', 'DEBUG'))
        self.assertEqual(d.key_bytes, bytes.fromhex(KEY1))

    def test_defaults(self):
        c = registry.validate({'version': 1}).config
        self.assertEqual((c.timeout_s, c.log_level, c.scanner, c.devices), (60, 'INFO', 'auto', []))

    def test_scanner(self):
        for mode in ('auto', 'venus', 'bluez', 'none'):
            self.assertEqual(registry.validate({'version': 1, 'scanner': mode}).config.scanner, mode)
        self.assertError({'version': 1, 'scanner': 'advmon'}, 'scanner: expected one of')

    def test_version(self):
        self.assertError({}, 'version: missing')
        self.assertError({'version': 2}, 'version: 2 not supported')
        self.assertError({'version': True}, 'not supported')
        self.assertError({'version': '1'}, 'not supported')

    def test_timeout_and_log_level(self):
        for bad in (0, 4, 3601, '60', True, None):
            self.assertError({'version': 1, 'timeout_s': bad}, 'timeout_s')
        self.assertTrue(registry.validate({'version': 1, 'timeout_s': 7.5}).ok)
        self.assertError({'version': 1, 'log_level': 'LOUD'}, 'log_level')

    def test_not_an_object(self):
        self.assertError([], 'JSON object')
        self.assertError({'version': 1, 'devices': {}}, 'devices: expected a list')
        self.assertError({'version': 1, 'devices': ['x']}, 'devices[0]: expected an object')

    def test_mac(self):
        for bad in ('AA-BB-CC-DD-EE-FF', 'AABBCCDDEEFF', 'AA:BB:CC:DD:EE', 'GG:BB:CC:DD:EE:FF', 12):
            data = sample()
            data['devices'][0]['mac'] = bad
            self.assertError(data, 'devices[0].mac')
        data = sample()
        del data['devices'][0]['mac']
        self.assertError(data, 'devices[0].mac: missing')

    def test_key(self):
        for bad, fragment in ((KEY1[:31], 'got 31 characters'), ('z' * 32, 'not all hexadecimal'),
                              (KEY1 + '0', 'got 33'), (42, 'got 0')):
            data = sample()
            data['devices'][1]['key'] = bad
            self.assertError(data, fragment)
        data = sample()
        del data['devices'][1]['key']
        self.assertError(data, 'devices[1].key: missing')

    def test_type(self):
        data = sample()
        data['devices'][0]['type'] = 'toaster'
        res = self.assertError(data, "unknown type 'toaster'")
        self.assertIn('known types: charger, dcdc', res.errors[0])
        del data['devices'][0]['type']
        self.assertError(data, 'type: missing')

    def test_name(self):
        data = sample()
        data['devices'][0]['name'] = 'x' * 65
        self.assertError(data, 'longer than 64')
        data['devices'][0]['name'] = 3
        self.assertError(data, 'name: expected a string')
        del data['devices'][0]['name']
        self.assertEqual(registry.validate(data).config.devices[0].name, '')

    def test_duplicates(self):
        data = sample()
        data['devices'][1]['mac'] = 'aa:bb:cc:dd:ee:ff'
        self.assertError(data, 'devices[1].mac: AA:BB:CC:DD:EE:FF already whitelisted in devices[0]')
        data = sample()
        data['devices'][1]['key'] = KEY1
        res = registry.validate(data)
        self.assertTrue(res.ok)
        self.assertTrue(any('same key as devices[0]' in w for w in res.warnings))

    def test_unknown_fields_are_warnings(self):
        data = sample()
        data['colour'] = 'blue'
        data['devices'][0]['tpye'] = 'dcdc'
        res = registry.validate(data)
        self.assertTrue(res.ok)
        self.assertEqual(len(res.warnings), 2)

    def test_repr_hides_key(self):
        d = registry.validate(sample()).config.devices[0]
        self.assertNotIn(KEY1, repr(d))
        self.assertNotIn(KEY1, repr(registry.validate(sample()).config))
        self.assertTrue(d.key_hint.startswith('01'))

    def test_loads_invalid_json(self):
        res = registry.loads('{"version": 1,\n "devices": [}')
        self.assertFalse(res.ok)
        self.assertIn('line 2', res.errors[0])


class FileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='vble-test-')
        self.path = os.path.join(self.dir, 'conf', 'victron-ble.json')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write_raw(self, text):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w', encoding='utf-8') as f:
            f.write(text)

    def test_load_missing(self):
        res = registry.load(self.path)
        self.assertFalse(res.ok)
        self.assertIn('file not found', res.errors[0])

    def test_save_and_load_round_trip(self):
        written = registry.save(sample(), self.path)
        self.assertEqual(len(written.devices), 2)
        res = registry.load(self.path)
        self.assertTrue(res.ok)
        self.assertEqual(res.config.to_dict(), written.to_dict())
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ['victron-ble.json'])   # no temp left
        with open(self.path, 'rb') as f:
            self.assertNotIn(b'\r', f.read())
        if os.name == 'posix':
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_save_refuses_invalid_and_keeps_file(self):
        registry.save(sample(), self.path)
        with open(self.path, encoding='utf-8') as f:
            before = f.read()
        bad = sample()
        bad['devices'][0]['key'] = 'nope'
        with self.assertRaises(ValueError):
            registry.save(bad, self.path)
        with open(self.path, encoding='utf-8') as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ['victron-ble.json'])

    def test_add_and_remove_are_pure(self):
        base = sample()
        snapshot = json.dumps(base, sort_keys=True)
        res = registry.add_device(base, 'de:ad:be:ef:00:01', KEY2, 'dcdc', 'Second Orion')
        self.assertTrue(res.ok, res.errors)
        self.assertEqual(len(res.config.devices), 3)
        self.assertEqual(json.dumps(base, sort_keys=True), snapshot)
        self.assertFalse(registry.add_device(base, 'AA:BB:CC:DD:EE:FF', KEY2, 'dcdc').ok)   # duplicate
        res = registry.remove_device(base, 'aa:bb:cc:dd:ee:ff')
        self.assertTrue(res.ok)
        self.assertEqual([d.mac for d in res.config.devices], ['11:22:33:44:55:66'])
        self.assertIn('not whitelisted', registry.remove_device(base, '00:00:00:00:00:00').errors[0])
        self.assertFalse(registry.remove_device(base, 'garbage').ok)
        self.assertTrue(registry.add_device(None, 'AA:BB:CC:DD:EE:FF', KEY1, 'dcdc').ok)

    def test_diff(self):
        old = registry.validate(sample()).config
        data = sample()
        data['devices'][0]['name'] = 'Orion renamed'
        data['devices'][1]['mac'] = '11:22:33:44:55:77'
        new = registry.validate(data).config
        self.assertEqual(registry.diff(old, new), (['11:22:33:44:55:77'], ['11:22:33:44:55:66'], ['AA:BB:CC:DD:EE:FF']))
        self.assertEqual(registry.diff(None, old), (['11:22:33:44:55:66', 'AA:BB:CC:DD:EE:FF'], [], []))

    def bump_mtime(self):
        st = os.stat(self.path)
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 2000000000))

    def test_watcher(self):
        with self.assertLogs('victronble.registry', level='WARNING') as logs:
            self._watcher_scenario()
        text = '\n'.join(logs.output)
        self.assertIn('file not found, keeping the current configuration', text)
        self.assertIn('invalid, keeping the current configuration', text)

    def _watcher_scenario(self):
        w = registry.ConfigWatcher(self.path)
        self.assertEqual(w.poll()[0], w.MISSING)
        self.assertIsNone(w.current)

        registry.save(sample(), self.path)
        status, res = w.poll()
        self.assertEqual(status, w.RELOADED)
        self.assertEqual(len(w.current.devices), 2)
        self.assertEqual(w.poll()[0], w.UNCHANGED)

        good = w.current
        self.write_raw('{"version": 1, "devices": [')        # half-written file
        self.bump_mtime()
        self.assertEqual(w.poll()[0], w.INVALID)
        self.assertIs(w.current, good)                       # still running on the last valid one

        registry.save(sample(), self.path)                   # typo undone: same content as before
        self.bump_mtime()
        status, res = w.poll()
        self.assertEqual(status, w.UNCHANGED)
        self.assertTrue(res.ok)

        data = sample()
        data['timeout_s'] = 120
        registry.save(data, self.path)
        self.bump_mtime()
        self.assertEqual(w.poll()[0], w.RELOADED)
        self.assertEqual(w.current.timeout_s, 120)

        self.bump_mtime()                                    # touched, not changed
        self.assertEqual(w.poll()[0], w.UNCHANGED)

        os.unlink(self.path)
        self.assertEqual(w.poll()[0], w.MISSING)
        self.assertEqual(w.current.timeout_s, 120)


if __name__ == '__main__':
    unittest.main()
