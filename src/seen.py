"""Every Victron device heard, whitelisted or not, for `victron-ble discover` and a future UI.

Written to /run/victron-ble/seen.json (tmpfs) atomically, at most every few seconds.
It never contains a key: only the key check byte, which every frame broadcasts in clear.
Nothing in this table is ever added to the whitelist automatically.

Per device: MAC, model and readout type from the clear header, RSSI, first/last time
heard, whether it is whitelisted, and the outcome of the last decryption attempt:
  ok                 decrypted and parsed with the whitelisted key
  key_mismatch       whitelisted, but the key check byte differs (key changed? PIN reset?)
  type_mismatch      whitelisted with a type that does not match the advertised record
  error              whitelisted, frame rejected by the parser (see "error")
  not_whitelisted    heard only
"""

import json
import logging
import os
import tempfile
import time

import parsers

log = logging.getLogger('victronble.seen')

DEFAULT_PATH = '/run/victron-ble/seen.json'
FORMAT_VERSION = 1


class SeenTable(object):
    MAX_DEVICES = 200
    FORGET_AFTER_S = 3600          # devices not heard for an hour leave the table

    def __init__(self, path=DEFAULT_PATH, write_interval_s=5.0, clock=time.time):
        self.path = path
        self.write_interval_s = write_interval_s
        self.clock = clock
        self.devices = {}
        self.whitelist = {}
        self.vedirect = {}         # model id -> [D-Bus services publishing that product]
        self.extra = {}            # scanner / listener status, set by the service
        self._dirty = True
        self._last_write = 0.0

    # ------------------------------------------------------------- updates ----

    def set_whitelist(self, config):
        self.whitelist = config.by_mac() if config else {}
        for mac, d in self.devices.items():
            self._apply_whitelist(mac, d)
        self._dirty = True

    def set_vedirect(self, products):
        self.vedirect = dict(products or {})
        for d in self.devices.values():
            self._apply_vedirect(d)
        self._dirty = True

    def set_dbus(self, mac, service, note):
        """D-Bus service publishing this device (None when not published) and why not."""
        d = self.devices.get(mac)
        if d is not None and (d.get('dbus'), d.get('dbus_note')) != (service, note):
            d['dbus'] = service
            d['dbus_note'] = note
            self._dirty = True

    def _apply_whitelist(self, mac, d):
        entry = self.whitelist.get(mac)
        d['whitelisted'] = entry is not None
        d['name'] = entry.name if entry else None
        d['configured_type'] = entry.type if entry else None
        if entry is None:
            d['status'] = 'not_whitelisted'
            d['values'] = None
            d['error'] = None

    def _apply_vedirect(self, d):
        services = self.vedirect.get(d.get('model_id_int')) if d.get('model_id_int') is not None else None
        d['vedirect_duplicate'] = list(services) if services else None

    def update(self, advert, header=None, status=None, reading=None, error=None):
        """Record one frame. `header` is None for Victron frames that are not Instant Readout."""
        d = self.devices.get(advert.mac)
        if d is None:
            if len(self.devices) >= self.MAX_DEVICES:
                self._forget(force=True)
            d = self.devices[advert.mac] = {
                'mac': advert.mac, 'first_seen': advert.t, 'frames': 0, 'ir_frames': 0,
                'model_id': None, 'model_id_int': None, 'model_name': None,
                'record_type': None, 'record_name': None, 'key_check': None,
                'status': 'not_whitelisted', 'values': None, 'error': None, 'last_decoded': None}
            self._apply_whitelist(advert.mac, d)
            self._apply_vedirect(d)
        d['frames'] += 1
        d['last_seen'] = advert.t
        if advert.rssi is not None:
            d['rssi'] = advert.rssi
        if header is not None:
            d['ir_frames'] += 1
            if d['model_id_int'] != header.model_id:
                d['model_id_int'] = header.model_id
                d['model_id'] = '0x%04X' % header.model_id
                d['model_name'] = parsers.model_name(header.model_id)
                self._apply_vedirect(d)
            d['record_type'] = '0x%02X' % header.record_type
            d['record_name'] = parsers.record_type_name(header.record_type)
            d['supported_type'] = parsers.type_for_record(header.record_type)
            d['key_check'] = '%02x' % header.key_check
            if status is not None:
                d['status'] = status
                d['error'] = error
                if reading is not None:
                    d['values'] = reading.values
                    d['last_decoded'] = advert.t
        self._dirty = True

    def _forget(self, force=False):
        now = self.clock()
        old = [m for m, d in self.devices.items()
               if m not in self.whitelist and now - d.get('last_seen', 0) > self.FORGET_AFTER_S]
        if force and not old:   # table full: drop the oldest non-whitelisted device
            others = [d for m, d in self.devices.items() if m not in self.whitelist]
            if others:
                old = [min(others, key=lambda d: d.get('last_seen', 0))['mac']]
        for m in old:
            del self.devices[m]
        if old:
            self._dirty = True

    # -------------------------------------------------------------- output ----

    def to_dict(self):
        now = self.clock()
        devices = []
        for d in sorted(self.devices.values(), key=lambda d: (not d.get('whitelisted'), d['mac'])):
            out = dict((k, v) for k, v in d.items() if k != 'model_id_int')
            out['age_s'] = round(now - d.get('last_seen', now), 1)
            devices.append(out)
        doc = {'version': FORMAT_VERSION, 'updated': round(now, 1), 'pid': os.getpid(), 'devices': devices}
        doc.update(self.extra)
        return doc

    def flush(self, force=False):
        """Write the file when something changed and the interval elapsed. Never raises."""
        now = self.clock()
        if not force and (not self._dirty or now - self._last_write < self.write_interval_s):
            return False
        self._forget()
        try:
            directory = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix='.seen.', suffix='.tmp', dir=directory)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
                    json.dump(self.to_dict(), f, indent=1, sort_keys=True)
                    f.write('\n')
                os.chmod(tmp, 0o644)                 # no secret inside: readable by a web UI
                os.replace(tmp, self.path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except Exception as e:
            log.error('cannot write %s: %s', self.path, e)
            return False
        self._dirty = False
        self._last_write = now
        return True


def load(path=DEFAULT_PATH):
    with open(path, encoding='utf-8') as f:
        return json.load(f)
