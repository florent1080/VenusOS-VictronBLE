import random
import unittest

import _path  # noqa: F401
import parsers
from parsers import aes, codes
from parsers.base import BitReader

# Public test vectors of victron_ble 0.9.3 (tests/test_dcdc_converter.py, tests/test_ac_charger.py)
ORION_FRAME = bytes.fromhex('1000c0a304121d64ca8d442b90bbdf6a8cba')
ORION_KEY = '64ba49f1a8562e45197a8e1fe50d7658'
CHARGER_FRAME = bytes.fromhex('100030a308f926c1b5170a0d2280335bf12d5ed083')
CHARGER_KEY = 'c129cf8f75c3fe5a1655b481e205fb7d'


class HeaderTests(unittest.TestCase):
    def test_orion_header(self):
        h = parsers.parse_header(ORION_FRAME)
        self.assertEqual((h.prefix, h.model_id, h.record_type, h.nonce, h.key_check),
                         (0x0010, 0xA3C0, 0x04, 0x1D12, 0x64))
        self.assertEqual(len(h.ciphertext), 10)

    def test_not_instant_readout(self):
        # real BMV-712 frame of another Victron record type (captured on the van)
        with self.assertRaises(parsers.NotInstantReadout):
            parsers.parse_header(bytes.fromhex('02e7b5147898fe1894487858454c721fe0ccbe5e264e'))
        for bad in (b'', b'\x10', ORION_FRAME[:7], None, 'not bytes'):
            with self.assertRaises(parsers.NotInstantReadout):
                parsers.parse_header(bad)


class EndToEndTests(unittest.TestCase):
    def test_orion_every_backend(self):
        for name in aes.available_backends():
            r = parsers.decode(ORION_FRAME, ORION_KEY, backend=aes.get_backend(name))
            self.assertEqual(r.device_type, 'dcdc')
            self.assertEqual(r.model_name, 'Orion Smart 12V/12V-18A DC-DC Converter')
            self.assertEqual(r.values, {'state': 0, 'error': 0, 'input_voltage': 13.15,
                                        'output_voltage': None, 'off_reason': 0x80}, name)

    def test_charger_every_backend(self):
        for name in aes.available_backends():
            r = parsers.decode(CHARGER_FRAME, CHARGER_KEY, backend=aes.get_backend(name))
            self.assertEqual(r.device_type, 'charger')
            self.assertEqual(r.model_name, 'Blue Smart IP22 Charger 12/30 (1)')
            v = r.values
            self.assertEqual((v['state'], v['error'], v['output_voltage1'], v['output_current1'], v['temperature']),
                             (6, 0, 13.49, 0.4, 21), name)
            self.assertIsNone(v['output_current2'])
            self.assertIsNone(v['ac_current'])

    def test_key_as_bytes(self):
        self.assertEqual(parsers.decode(ORION_FRAME, bytes.fromhex(ORION_KEY)).values['input_voltage'], 13.15)

    def test_wrong_key(self):
        with self.assertRaises(parsers.KeyMismatch):
            parsers.decode(ORION_FRAME, CHARGER_KEY)

    def test_key_with_right_check_byte_but_wrong_rest_decodes_garbage_without_crash(self):
        r = parsers.decode(ORION_FRAME, '64' + '00' * 15)
        self.assertEqual(r.device_type, 'dcdc')

    def test_bad_key_format(self):
        for key in ('zz' * 16, '64ba'):
            with self.assertRaises(parsers.ParseError):
                parsers.decode(ORION_FRAME, key)

    def test_configured_type_mismatch(self):
        with self.assertRaises(parsers.UnsupportedRecord):
            parsers.decode(ORION_FRAME, ORION_KEY, 'charger')
        with self.assertRaises(parsers.UnsupportedRecord):
            parsers.decode(ORION_FRAME, ORION_KEY, 'toaster')

    def test_unsupported_record(self):
        # real BMV-712 Instant Readout frame (battery monitor record, not parsed yet)
        bmv = bytes.fromhex('100283a3027d799366aa6b293cf97ab63d76e27d5a4690')
        with self.assertRaises(parsers.UnsupportedRecord):
            parsers.decode(bmv, '93' + '00' * 15)

    def test_truncated(self):
        with self.assertRaises(parsers.TruncatedFrame):
            parsers.decode(ORION_FRAME[:15], ORION_KEY)

    def test_longer_payload_ignored(self):
        r = parsers.decode(ORION_FRAME + b'\x00\x00', ORION_KEY)
        self.assertEqual(r.values['input_voltage'], 13.15)


class DecryptedPayloadTests(unittest.TestCase):
    """Decrypted vectors of victron_ble (padded to 16 bytes: the extra bytes are ignored)."""

    def test_dcdc(self):
        v = parsers.dcdc.parse(bytes.fromhex('00002305ff7f80000000cbdd494cc5d1'))
        self.assertEqual(v, {'state': 0, 'error': 0, 'input_voltage': 13.15, 'output_voltage': None,
                             'off_reason': 0x80})

    def test_charger(self):
        v = parsers.ac_charger.parse(bytes.fromhex('060046a500ffffffffffffbdffeb3d1f'))
        self.assertEqual((v['state'], v['error'], v['output_voltage1'], v['output_current1'], v['temperature']),
                         (6, 0, 13.5, 0.5, 21))
        self.assertIsNone(v['output_current2'])

    def test_unknown_codes_kept_as_integers(self):
        # state 8 and error 99 are not in the Victron tables: no exception, raw values kept
        payload = bytes([8, 99]) + (1234).to_bytes(2, 'little') + (1380).to_bytes(2, 'little') + (0x81).to_bytes(4, 'little')
        v = parsers.dcdc.parse(payload)
        self.assertEqual((v['state'], v['error'], v['input_voltage'], v['output_voltage'], v['off_reason']),
                         (8, 99, 12.34, 13.8, 0x81))
        text = parsers.format_values(v)
        self.assertIn('state=?(8)', text)
        self.assertIn('NO_INPUT_POWER+ENGINE_SHUTDOWN', text)

    def test_not_available_markers(self):
        payload = bytes([0xFF, 0xFF]) + b'\xff\xff' + (0x7FFF).to_bytes(2, 'little') + bytes(4)
        v = parsers.dcdc.parse(payload)
        self.assertEqual((v['state'], v['error'], v['input_voltage'], v['output_voltage']), (None, None, None, None))

    def test_negative_output_voltage(self):
        payload = bytes(4) + (-5 & 0xFFFF).to_bytes(2, 'little') + bytes(4)
        self.assertEqual(parsers.dcdc.parse(payload)['output_voltage'], -0.05)


class BitReaderTests(unittest.TestCase):
    """Same cases as victron_ble tests/test_base.py."""

    def test_to_signed_int(self):
        cases = [(0x000, 12, 0), (0x7FF, 12, 0x7FF), (0x800, 12, -0x800), (0xCAD, 12, -0x353),
                 (0xFFF, 12, -1), (0x0F, 5, 0x0F), (0x10, 5, -0x10), (0x1F, 5, -1)]
        for value, bits, expected in cases:
            self.assertEqual(BitReader.to_signed_int(value, bits), expected)

    def test_read(self):
        r = BitReader(bytes.fromhex('1a2b3c4d5e6f7890'))
        self.assertEqual([r.read_bit(), r.read_bit(), r.read_bit(), r.read_bit()], [0, 1, 0, 1])
        self.assertEqual(r.read_unsigned_int(6), 0x31)
        self.assertEqual(r.read_signed_int(6), 0x0A)
        self.assertEqual(r.read_signed_int(4), -0x04)
        self.assertEqual(r.read_unsigned_int(11), 0x4D3)
        self.assertEqual(r.read_bit(), 0)
        self.assertEqual(r.read_unsigned_int(32), 0x90786F5E)
        with self.assertRaises(parsers.TruncatedFrame):
            r.read_bit()


class RobustnessTests(unittest.TestCase):
    def test_random_frames_only_raise_parse_errors(self):
        rnd = random.Random(42)
        backend = aes.get_backend('python')
        for i in range(3000):
            n = rnd.randint(0, 40)
            data = bytearray(rnd.getrandbits(8) for _ in range(n))
            if n >= 5 and i % 2:            # half of them look like real Instant Readout headers
                data[0] = 0x10
                data[4] = rnd.choice([0x04, 0x08, 0x02, 0x01])
            key = bytes([data[7] if n > 7 and i % 3 == 0 else rnd.getrandbits(8)]) + bytes(15)
            try:
                parsers.decode(bytes(data), key, backend=backend)
            except parsers.ParseError:
                pass

    def test_parser_bug_becomes_parse_error(self):
        original = parsers.DEVICE_TYPES['dcdc'].parse

        def broken(plain):
            raise ZeroDivisionError('boom')
        parsers.DEVICE_TYPES['dcdc'].parse = broken
        try:
            with self.assertRaises(parsers.ParseError):
                parsers.decode(ORION_FRAME, ORION_KEY)
        finally:
            parsers.DEVICE_TYPES['dcdc'].parse = original


class TablesTests(unittest.TestCase):
    def test_registry_of_types(self):
        self.assertEqual(sorted(parsers.DEVICE_TYPES), ['charger', 'dcdc'])
        self.assertEqual(parsers.type_for_record(0x04), 'dcdc')
        self.assertEqual(parsers.type_for_record(0x08), 'charger')
        self.assertIsNone(parsers.type_for_record(0x02))

    def test_payload_sizes_match_the_van(self):
        # Orion-Tr frames captured on the van carry 10 bytes of ciphertext
        self.assertEqual(parsers.DEVICE_TYPES['dcdc'].payload_bits, 80)
        self.assertEqual(parsers.DEVICE_TYPES['charger'].payload_bits, 104)

    def test_names(self):
        self.assertEqual(parsers.model_name(0xA3C0), 'Orion Smart 12V/12V-18A DC-DC Converter')
        self.assertEqual(parsers.model_name(0x1234), 'Victron device 0x1234')
        self.assertEqual(codes.OPERATION_MODES[3], 'BULK')
        self.assertEqual(parsers.record_type_name(0x02), 'Battery monitor')
        self.assertEqual(parsers.off_reason_names(0x14), ['SWITCHED_OFF_REGISTER', 'PROTECTION_ACTIVE'])


if __name__ == '__main__':
    unittest.main()
