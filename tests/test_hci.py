"""Monitor-channel parsing, fed with a real capture.

capture_sensors_60s.btsnoop: btmon -w on the van, 2026-11-06 18:14 UTC, 60 s with the
Venus OS Bluetooth sensors scanning. Each btsnoop record is turned back into the
packet the monitor socket delivers (hci_mon_hdr + payload).
The Bluetooth addresses (devices and the GX adapter) were replaced by fictitious ones.
"""

import os
import struct
import unittest
from collections import Counter

import _path
import hci
from listener import HciMonitorListener
from loop import SimpleLoop

CAPTURE = os.path.join(_path.FIXTURES, 'capture_sensors_60s.btsnoop')
# from the diagnostic's own analysis of the same capture (victron_adv.jsonl)
EXPECTED = {'FE:00:00:00:00:03': 175, 'D4:00:00:00:00:04': 131, 'FC:00:00:00:00:01': 65, 'CC:00:00:00:00:02': 62}


def monitor_packets(path):
    with open(path, 'rb') as f:
        assert f.read(16)[:8] == b'btsnoop\x00'
        while True:
            rh = f.read(24)
            if len(rh) < 24:
                return
            _orig, incl, flags, _drops, _ts = struct.unpack('>IIIIq', rh)
            data = f.read(incl)
            yield struct.pack('<HHH', flags & 0xFFFF, flags >> 16, len(data)) + data


def legacy_event(mac, ad, rssi=-60, evt=0):
    addr = bytes(reversed(bytes.fromhex(mac.replace(':', ''))))
    p = bytes([hci.LE_ADV_REPORT, 1, evt, 1]) + addr + bytes([len(ad)]) + ad + struct.pack('b', rssi)
    return bytes([hci.EVT_LE_META, len(p)]) + p


def victron_ad(payload):
    return bytes([2, 1, 6, len(payload) + 3, 0xFF, 0xE1, 0x02]) + payload


def as_monitor(event, opcode=hci.MON_EVENT):
    return struct.pack('<HHH', opcode, 0, len(event)) + event


class RealCaptureTests(unittest.TestCase):
    def test_capture_gives_the_same_frames_as_btmon(self):
        got = []
        lst = HciMonitorListener(SimpleLoop(virtual=True), got.append)
        for pkt in monitor_packets(CAPTURE):
            lst.handle_packet(pkt)
        self.assertEqual(dict(Counter(a.mac for a in got)), EXPECTED)
        self.assertEqual(lst.stats['malformed'], 0)
        self.assertEqual(lst.stats['adverts'], sum(EXPECTED.values()))
        orion = [a for a in got if a.mac == 'FC:00:00:00:00:01']
        self.assertTrue(all(a.mfg[:5] == bytes.fromhex('1000c0a304') for a in orion))
        self.assertTrue(all(-100 < a.rssi < 0 for a in got))


class ParsingTests(unittest.TestCase):
    def test_split_monitor_packet(self):
        self.assertEqual(hci.split_monitor_packet(b'\x03\x00\x00\x00\x02\x00ab'), (3, 0, b'ab'))
        for bad in (b'', b'\x03\x00', b'\x03\x00\x00\x00\x05\x00ab'):
            with self.assertRaises(ValueError):
                hci.split_monitor_packet(bad)

    def test_manufacturer_data(self):
        ad = victron_ad(b'\x10\x00\xc0\xa3')
        self.assertEqual(hci.manufacturer_data(ad, 0x02E1), b'\x10\x00\xc0\xa3')
        self.assertIsNone(hci.manufacturer_data(ad, 0x004C))
        self.assertIsNone(hci.manufacturer_data(b'\x02\x01\x06', 0x02E1))
        self.assertIsNone(hci.manufacturer_data(b'\x1e\xff\xe1\x02', 0x02E1))     # length overruns
        self.assertIsNone(hci.manufacturer_data(b'\x00\x05', 0x02E1))
        self.assertIsNone(hci.manufacturer_data(b'\x02\xff\xe1', 0x02E1))         # no room for the id
        self.assertEqual(hci.manufacturer_data(b'\x03\xff\xe1\x02', 0x02E1), b'')

    def test_two_reports_in_one_event(self):
        a = bytes(reversed(bytes.fromhex('AABBCC000001')))
        b = bytes(reversed(bytes.fromhex('C40000000002')))
        ad1, ad2 = b'\x02\x01\x06', victron_ad(b'\x10\x02')
        p = bytes([hci.LE_ADV_REPORT, 2, 0, 0]) + a + bytes([len(ad1)]) + ad1 + b'\xb0' + \
            bytes([3, 0]) + b + bytes([len(ad2)]) + ad2 + b'\xc4'
        reports = hci.adv_reports(bytes([hci.EVT_LE_META, len(p)]) + p)
        self.assertEqual([r.mac for r in reports], ['AA:BB:CC:00:00:01', 'C4:00:00:00:00:02'])
        self.assertEqual([r.rssi for r in reports], [-80, -60])
        self.assertEqual(reports[1].event_type, 'ADV_NONCONN_IND')

    def test_malformed_events(self):
        good = legacy_event('FC:00:00:00:00:01', victron_ad(b'\x10\x00'))
        with self.assertRaises(ValueError):
            hci.adv_reports(good[:-3])                     # cut inside the report
        self.assertEqual(hci.adv_reports(b'\x0e\x04\x01\x0c\x20\x00'), [])   # command complete
        self.assertEqual(hci.adv_reports(b'\x3e\x01\x0b'), [])             # other LE sub-event


class ListenerRobustnessTests(unittest.TestCase):
    def test_garbage_never_reaches_the_callback(self):
        got = []
        lst = HciMonitorListener(SimpleLoop(virtual=True), got.append)
        good = as_monitor(legacy_event('FC:00:00:00:00:01', victron_ad(b'\x10\x00\xc0\xa3\x04')))
        for pkt in (b'', b'\x03', good[:9], good[:-2], as_monitor(b'\x3e\x05\x02\x01'),
                    as_monitor(good[6:], opcode=hci.MON_COMMAND), good):
            lst.handle_packet(pkt)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].mac, 'FC:00:00:00:00:01')
        self.assertGreaterEqual(lst.stats['malformed'], 3)

    def test_callback_exception_does_not_stop_the_listener(self):
        calls = []

        def boom(advert):
            calls.append(advert)
            raise RuntimeError('mapper bug')
        lst = HciMonitorListener(SimpleLoop(virtual=True), boom)
        pkt = as_monitor(legacy_event('FC:00:00:00:00:01', victron_ad(b'\x10\x00')))
        with self.assertLogs('victronble.listener', level='ERROR'):
            lst.handle_packet(pkt)
            lst.handle_packet(pkt)
        self.assertEqual(len(calls), 2)
        self.assertEqual(lst.stats['callback_errors'], 2)

    def test_rssi_unavailable(self):
        got = []
        lst = HciMonitorListener(SimpleLoop(virtual=True), got.append)
        lst.handle_packet(as_monitor(legacy_event('FC:00:00:00:00:01', victron_ad(b'\x10'), rssi=127)))
        self.assertIsNone(got[0].rssi)


if __name__ == '__main__':
    unittest.main()
