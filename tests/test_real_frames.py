"""Frames recorded on the van (tools/venus-ble-diag.sh, 2026-11-06), under fictitious addresses.

Without a key, only the clear header and the rejection paths can be checked.
To also decrypt them, create tests/fixtures/keys.local.json (ignored by git):
    {"FC:00:00:00:00:01": "<Orion-Tr Smart key>", "CC:00:00:00:00:02": "<Blue Smart key>"}
"""

import json
import os
import unittest

import _path
import parsers

ORION = 'FC:00:00:00:00:01'
CHARGER = 'CC:00:00:00:00:02'      # Blue Smart IP65 Charger 12|25
BMV = 'FE:00:00:00:00:03'
MPPT = 'D4:00:00:00:00:04'
KEYS_FILE = os.path.join(_path.FIXTURES, 'keys.local.json')


def load_frames():
    with open(os.path.join(_path.FIXTURES, 'recorded_frames.jsonl'), encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


class RecordedFramesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames = load_frames()
        cls.orion = [f for f in cls.frames if f['mac'] == ORION]

    def test_fixture_present(self):
        self.assertGreaterEqual(len(self.orion), 100)

    def test_orion_headers(self):
        for f in self.orion:
            h = parsers.parse_header(bytes.fromhex(f['mfg']))
            self.assertEqual((h.model_id, h.record_type, h.key_check, len(h.ciphertext)),
                             (0xA3C0, 0x04, 0x9C, 10), f['mfg'])
            self.assertEqual(parsers.type_for_record(h.record_type), 'dcdc')

    def test_charger_headers(self):
        charger = [f for f in self.frames if f['mac'] == CHARGER]
        self.assertGreaterEqual(len(charger), 40)
        for f in charger:
            h = parsers.parse_header(bytes.fromhex(f['mfg']))
            self.assertEqual((h.model_id, h.record_type, h.key_check, len(h.ciphertext)),
                             (0xA30A, 0x08, 0xEE, 13), f['mfg'])
        self.assertEqual(parsers.model_name(0xA30A), 'Blue Smart IP65 Charger 12|25')

    def test_orion_nonce_advances_within_a_capture(self):
        by_phase = {}
        for f in self.orion:
            by_phase.setdefault((f['source'], f['phase']), []).append(f)
        for frames in by_phase.values():
            nonces = [parsers.parse_header(bytes.fromhex(f['mfg'])).nonce
                      for f in sorted(frames, key=lambda f: f['t'])]
            self.assertTrue(all((b - a) % 0x10000 < 100 for a, b in zip(nonces, nonces[1:])), nonces)

    def test_other_devices(self):
        for f in self.frames:
            if f['mac'] not in (BMV, MPPT):
                continue
            mfg = bytes.fromhex(f['mfg'])
            if mfg[0] == 0x10:       # Instant Readout of a record type we do not publish (yet)
                with self.assertRaises(parsers.UnsupportedRecord):
                    parsers.decode(mfg, bytes([mfg[7]]) + bytes(15))
            else:                    # the other Victron frames these devices interleave
                with self.assertRaises(parsers.NotInstantReadout):
                    parsers.decode(mfg, bytes(16))

    def test_orion_with_wrong_key(self):
        with self.assertRaises(parsers.KeyMismatch):
            parsers.decode(bytes.fromhex(self.orion[0]['mfg']), '00' * 16)


@unittest.skipUnless(os.path.exists(KEYS_FILE), 'no tests/fixtures/keys.local.json: real-frame decryption skipped')
class RecordedFramesWithKeyTests(unittest.TestCase):
    def frames_for(self, mac, dtype):
        with open(KEYS_FILE, encoding='utf-8') as f:
            keys = dict((k.upper(), v) for k, v in json.load(f).items())
        if mac not in keys:
            self.skipTest('no key for %s in keys.local.json' % mac)
        frames = [f for f in load_frames() if f['mac'] == mac]
        self.assertTrue(frames)
        return [(f, parsers.decode(bytes.fromhex(f['mfg']), keys[mac], dtype)) for f in frames]

    def test_charger_values_are_plausible(self):
        # captured while charging a discharged battery: bulk, ~13 V, close to 25 A
        for f, r in self.frames_for(CHARGER, 'charger'):
            v = r.values
            self.assertIn(v['state'], parsers.codes.OPERATION_MODES, f['mfg'])
            self.assertEqual(v['error'], 0, f['mfg'])
            self.assertTrue(10.0 < v['output_voltage1'] < 16.0, v)
            self.assertTrue(0.0 <= v['output_current1'] <= 26.0, v)
            self.assertIsNone(v['output_voltage2'])   # single-output model
            self.assertIsNone(v['output_voltage3'])

    def test_orion_values_are_plausible(self):
        for f, r in self.frames_for(ORION, 'dcdc'):
            v = r.values
            self.assertIn(v['state'], parsers.codes.OPERATION_MODES, f['mfg'])
            self.assertEqual(v['error'], 0, f['mfg'])
            self.assertTrue(v['input_voltage'] is None or 8.0 < v['input_voltage'] < 17.0, v)
            self.assertTrue(v['output_voltage'] is None or 8.0 < v['output_voltage'] < 16.0, v)


if __name__ == '__main__':
    unittest.main()
