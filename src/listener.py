"""Advertisement sources. Each delivers Victron frames as Advert objects to one callback.

HciMonitorListener  live: reads the Linux HCI monitor channel itself (no btmon process).
                    It only sees what the controller receives while someone scans:
                    Venus OS Bluetooth sensors or our own BlueZ discovery (scanner.py).
ReplayListener      offline: replays a jsonl file, e.g. the victron_adv.jsonl written
                    by tools/venus-ble-diag.sh, to exercise the whole chain away from the van.

Both share the same contract: whatever arrives, the callback is called only with
well-formed Advert objects, and an exception in the callback never stops the source.
"""

import ctypes
import json
import logging
import os
import socket
import struct
import time

import hci

log = logging.getLogger('victronble.listener')

VICTRON_COMPANY_ID = 0x02E1
HCI_DEV_NONE = 0xFFFF
HCI_CHANNEL_MONITOR = 2


class Advert(object):
    __slots__ = ('mac', 'rssi', 'mfg', 't', 'source')

    def __init__(self, mac, rssi, mfg, t, source):
        self.mac = mac          # 'AA:BB:CC:DD:EE:FF'
        self.rssi = rssi        # dBm, None when unavailable
        self.mfg = mfg          # manufacturer data without the 0x02E1 company id
        self.t = t              # reception time (seconds since the epoch)
        self.source = source    # 'hci' or 'replay'

    def __repr__(self):
        return 'Advert(%s, rssi=%s, %s)' % (self.mac, self.rssi, self.mfg.hex())


class _Source(object):
    def __init__(self, on_advert):
        self.on_advert = on_advert
        self.stats = {'adverts': 0, 'callback_errors': 0, 'last_advert': None}

    def _deliver(self, advert):
        self.stats['adverts'] += 1
        self.stats['last_advert'] = advert.t
        try:
            self.on_advert(advert)
        except Exception:
            self.stats['callback_errors'] += 1
            log.exception('advertisement from %s not processed', advert.mac)


def _bind_monitor(sock):
    """bind(sockaddr_hci{AF_BLUETOOTH, HCI_DEV_NONE, HCI_CHANNEL_MONITOR}) through libc:
    Python's socket module cannot express the channel field."""
    af = getattr(socket, 'AF_BLUETOOTH', 31)
    addr = struct.pack('=HHH', af, HCI_DEV_NONE, HCI_CHANNEL_MONITOR)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.bind.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if libc.bind(sock.fileno(), addr, len(addr)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


class HciMonitorListener(_Source):
    REOPEN_DELAYS_S = (1, 2, 5, 10, 30, 60)
    MAX_PACKETS_PER_WAKEUP = 500

    def __init__(self, loop, on_advert, company_id=VICTRON_COMPANY_ID, clock=time.time):
        _Source.__init__(self, on_advert)
        self.loop = loop
        self.company_id = company_id
        self.clock = clock
        self.sock = None
        self._watch = None
        self._reopen_timer = None
        self._failures = 0
        self.stats.update(packets=0, adv_reports=0, malformed=0, opens=0)

    def start(self):
        self._open()

    def stop(self):
        if self._reopen_timer is not None:
            self.loop.source_remove(self._reopen_timer)
            self._reopen_timer = None
        self._close()

    def _open(self):
        self._reopen_timer = None
        try:
            af = getattr(socket, 'AF_BLUETOOTH', 31)
            s = socket.socket(af, socket.SOCK_RAW, getattr(socket, 'BTPROTO_HCI', 1))
            try:
                _bind_monitor(s)
                s.setblocking(False)
            except Exception:
                s.close()
                raise
        except (OSError, AttributeError) as e:
            delay = self.REOPEN_DELAYS_S[min(self._failures, len(self.REOPEN_DELAYS_S) - 1)]
            self._failures += 1
            log.error('cannot open the HCI monitor channel (%s), retrying in %d s', e, delay)
            self._reopen_timer = self.loop.timeout_add_seconds(delay, self._open, repeat_on_error=False)
            return False
        self.sock = s
        self.stats['opens'] += 1
        if self._failures:
            log.info('HCI monitor channel open again')
        self._failures = 0
        self._watch = self.loop.io_add_watch(s.fileno(), self._readable)
        return False

    def _close(self):
        if self._watch is not None:
            self.loop.source_remove(self._watch)
            self._watch = None
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _reopen(self, reason):
        log.warning('HCI monitor channel lost (%s), reopening', reason)
        self._close()
        self._reopen_timer = self.loop.timeout_add_seconds(1, self._open, repeat_on_error=False)

    def _readable(self, fd, condition=None):
        if condition and condition & (8 | 16) and not condition & 1:   # IO_ERR / IO_HUP without data
            self._reopen('socket error')
            return False
        for _ in range(self.MAX_PACKETS_PER_WAKEUP):
            try:
                pkt = self.sock.recv(65535)
            except (BlockingIOError, InterruptedError):
                return True
            except OSError as e:
                self._reopen(e)
                return False
            if not pkt:
                self._reopen('end of stream')
                return False
            self.handle_packet(pkt)
        return True

    def handle_packet(self, pkt):
        """One monitor packet (also used by the tests with recorded captures)."""
        self.stats['packets'] += 1
        try:
            opcode, _index, payload = hci.split_monitor_packet(pkt)
            if opcode != hci.MON_EVENT or not payload or payload[0] != hci.EVT_LE_META:
                return
            reports = hci.adv_reports(payload)
        except ValueError:
            self.stats['malformed'] += 1
            return
        now = self.clock()
        for r in reports:
            self.stats['adv_reports'] += 1
            mfg = hci.manufacturer_data(r.data, self.company_id)
            if mfg is not None:
                self._deliver(Advert(r.mac, None if r.rssi == hci.RSSI_UNAVAILABLE else r.rssi, mfg, now, 'hci'))


class ReplayListener(_Source):
    """Replays {"mac", "mfg"[, "rssi", "t"]} lines; t (seconds) sets the pace.

    speed 1.0 = real time, 10 = ten times faster, 0 = everything at once.
    on_end() is called after the last frame (e.g. to stop the service).
    """
    TICK_MS = 50

    def __init__(self, loop, on_advert, path, speed=1.0, repeat=False, on_end=None, clock=None):
        _Source.__init__(self, on_advert)
        self.loop = loop
        self.path = path
        self.speed = speed
        self.repeat = repeat
        self.on_end = on_end
        self.clock = clock or loop.now
        self.frames = []
        self.stats.update(malformed_lines=0, rounds=0)
        self._i = 0
        self._t0 = None
        self._timer = None

    def load(self):
        frames = []
        with open(self.path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    mac = str(rec['mac']).upper()
                    mfg = bytes.fromhex(rec['mfg'])
                    t = float(rec.get('t') or 0.0)
                    rssi = rec.get('rssi')
                    rssi = int(rssi) if rssi is not None and int(rssi) != hci.RSSI_UNAVAILABLE else None
                except (ValueError, KeyError, TypeError):
                    self.stats['malformed_lines'] += 1
                    continue
                frames.append((t, mac, rssi, mfg))
        frames.sort(key=lambda fr: fr[0])
        self.frames = frames
        if self.stats['malformed_lines']:
            log.warning('%s: %d malformed lines skipped', self.path, self.stats['malformed_lines'])
        return len(frames)

    def start(self):
        if not self.frames:
            self.load()
        log.info('replaying %d frames from %s (speed %s)', len(self.frames), self.path, self.speed or 'max')
        self._begin_round()
        self._timer = self.loop.timeout_add(self.TICK_MS, self._tick)

    def stop(self):
        if self._timer is not None:
            self.loop.source_remove(self._timer)
            self._timer = None

    def _begin_round(self):
        self._i = 0
        self._t0 = self.loop.now()
        self.stats['rounds'] += 1

    def _tick(self):
        if not self.frames:
            return self._finish()
        base = self.frames[0][0]
        elapsed = self.loop.now() - self._t0
        while self._i < len(self.frames):
            t, mac, rssi, mfg = self.frames[self._i]
            if self.speed and (t - base) / self.speed > elapsed:
                return True
            self._i += 1
            self._deliver(Advert(mac, rssi, mfg, self.clock(), 'replay'))
        if self.repeat:
            self._begin_round()
            return True
        return self._finish()

    def _finish(self):
        self._timer = None
        log.info('replay finished: %d frames delivered', self.stats['adverts'])
        if self.on_end:
            self.on_end()
        return False
