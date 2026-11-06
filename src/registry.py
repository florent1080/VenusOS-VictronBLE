"""Whitelist configuration: loading, validation, atomic writes and hot reload.

The service, the command line and a future web UI all go through these
functions, so the rules live in one place. Nothing here is ever added from
what is seen on the air: only what the user puts in the file is whitelisted.

/data/conf/victron-ble.json:
    {
      "version": 1,
      "timeout_s": 60,
      "log_level": "INFO",
      "scanner": "auto",
      "devices": [
        {"mac": "AA:BB:CC:DD:EE:FF", "key": "<32 hex>", "type": "dcdc", "name": "Orion-Tr Smart"}
      ]
    }
"""

import hashlib
import json
import logging
import os
import re
import tempfile

import parsers

log = logging.getLogger('victronble.registry')

DEFAULT_PATH = '/data/conf/victron-ble.json'
CONFIG_VERSION = 1
DEFAULT_TIMEOUT_S = 60
TIMEOUT_MIN_S, TIMEOUT_MAX_S = 5, 3600
DEFAULT_LOG_LEVEL = 'INFO'
LOG_LEVELS = ('DEBUG', 'INFO', 'WARNING', 'ERROR')
DEFAULT_SCANNER = 'auto'
SCANNERS = ('auto', 'venus', 'bluez', 'none')     # see scanner.py
NAME_MAX = 64

TOP_FIELDS = ('version', 'timeout_s', 'log_level', 'scanner', 'devices')
DEVICE_FIELDS = ('mac', 'key', 'type', 'name', 'allow_duplicate')
_MAC_RE = re.compile(r'^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$')
_KEY_RE = re.compile(r'^[0-9A-Fa-f]{32}$')


class DeviceEntry(object):
    """One whitelisted device. The key is never shown in repr() or logs.

    allow_duplicate: publish on D-Bus even when the same model is already published by
    another service (e.g. over VE.Direct). Off by default: the device would show twice.
    """
    __slots__ = ('mac', 'key', 'type', 'name', 'allow_duplicate')

    def __init__(self, mac, key, type, name='', allow_duplicate=False):
        self.mac = mac
        self.key = key
        self.type = type
        self.name = name
        self.allow_duplicate = allow_duplicate

    @property
    def key_bytes(self):
        return bytes.fromhex(self.key)

    @property
    def key_hint(self):
        """First key byte only: it is broadcast in clear in every frame anyway (key check)."""
        return self.key[:2] + '*' * 30

    def to_dict(self):
        d = {'mac': self.mac, 'key': self.key, 'type': self.type, 'name': self.name}
        if self.allow_duplicate:
            d['allow_duplicate'] = True
        return d

    def __eq__(self, other):
        return isinstance(other, DeviceEntry) and self.to_dict() == other.to_dict()

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return 'DeviceEntry(%s, %s, %r, key=%s)' % (self.mac, self.type, self.name, self.key_hint)


class Config(object):
    __slots__ = ('version', 'timeout_s', 'log_level', 'scanner', 'devices')

    def __init__(self, version=CONFIG_VERSION, timeout_s=DEFAULT_TIMEOUT_S,
                 log_level=DEFAULT_LOG_LEVEL, devices=None, scanner=DEFAULT_SCANNER):
        self.version = version
        self.timeout_s = timeout_s
        self.log_level = log_level
        self.scanner = scanner
        self.devices = list(devices or [])

    def by_mac(self):
        return dict((d.mac, d) for d in self.devices)

    def to_dict(self):
        return {'version': self.version, 'timeout_s': self.timeout_s, 'log_level': self.log_level,
                'scanner': self.scanner, 'devices': [d.to_dict() for d in self.devices]}

    def __repr__(self):
        return 'Config(timeout_s=%s, log_level=%s, scanner=%s, devices=%r)' % (
            self.timeout_s, self.log_level, self.scanner, self.devices)


class Result(object):
    """Outcome of a validation: `config` is set only when there is no error."""

    def __init__(self, config=None, errors=None, warnings=None):
        self.config = config
        self.errors = list(errors or [])
        self.warnings = list(warnings or [])

    @property
    def ok(self):
        return not self.errors

    def __repr__(self):
        return 'Result(ok=%s, errors=%r, warnings=%r)' % (self.ok, self.errors, self.warnings)


def normalize_mac(mac):
    """'aa:bb:...' -> 'AA:BB:...'; raises ValueError on any other format."""
    if not isinstance(mac, str) or not _MAC_RE.match(mac.strip()):
        raise ValueError('expected a MAC address like AA:BB:CC:DD:EE:FF')
    return mac.strip().upper()


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def validate(data, known_types=None):
    """Check a decoded JSON document; returns a Result with a normalized Config.

    Error messages name the faulty field and never contain a key value.
    """
    known = sorted(known_types if known_types is not None else parsers.DEVICE_TYPES)
    errors, warnings = [], []
    if not isinstance(data, dict):
        return Result(errors=['the configuration must be a JSON object'])

    for k in data:
        if k not in TOP_FIELDS:
            warnings.append('unknown field %r ignored' % k)

    version = data.get('version')
    if version is None:
        errors.append('version: missing (expected %d)' % CONFIG_VERSION)
    elif not isinstance(version, int) or isinstance(version, bool) or version != CONFIG_VERSION:
        errors.append('version: %r not supported (expected %d)' % (version, CONFIG_VERSION))

    timeout_s = data.get('timeout_s', DEFAULT_TIMEOUT_S)
    if not _is_number(timeout_s) or not TIMEOUT_MIN_S <= timeout_s <= TIMEOUT_MAX_S:
        errors.append('timeout_s: expected a number of seconds between %d and %d'
                      % (TIMEOUT_MIN_S, TIMEOUT_MAX_S))

    log_level = data.get('log_level', DEFAULT_LOG_LEVEL)
    if not isinstance(log_level, str) or log_level.upper() not in LOG_LEVELS:
        errors.append('log_level: expected one of %s' % ', '.join(LOG_LEVELS))
    else:
        log_level = log_level.upper()

    scanner = data.get('scanner', DEFAULT_SCANNER)
    if scanner not in SCANNERS:
        errors.append('scanner: expected one of %s' % ', '.join(SCANNERS))

    devices = []
    raw_devices = data.get('devices', [])
    if not isinstance(raw_devices, list):
        errors.append('devices: expected a list')
        raw_devices = []
    seen_macs, seen_keys = {}, {}
    for i, raw in enumerate(raw_devices):
        where = 'devices[%d]' % i
        if not isinstance(raw, dict):
            errors.append('%s: expected an object' % where)
            continue
        for k in raw:
            if k not in DEVICE_FIELDS:
                warnings.append('%s: unknown field %r ignored' % (where, k))
        bad = False

        try:
            mac = normalize_mac(raw.get('mac'))
        except ValueError as e:
            errors.append('%s.mac: %s' % (where, 'missing' if raw.get('mac') is None else e))
            mac, bad = None, True

        key = raw.get('key')
        if key is None:
            errors.append('%s.key: missing (Instant Readout key, 32 hexadecimal characters)' % where)
            bad = True
        elif not isinstance(key, str) or not _KEY_RE.match(key.strip()):
            n = len(key.strip()) if isinstance(key, str) else 0
            errors.append('%s.key: expected 32 hexadecimal characters (got %d characters%s)'
                          % (where, n, ', not all hexadecimal' if n == 32 else ''))
            bad = True
        else:
            key = key.strip().lower()

        dtype = raw.get('type')
        if dtype not in known:
            errors.append('%s.type: %s (known types: %s)' % (
                where, 'missing' if dtype is None else 'unknown type %r' % (dtype,), ', '.join(known)))
            bad = True

        name = raw.get('name', '')
        if not isinstance(name, str):
            errors.append('%s.name: expected a string' % where)
            bad = True
        else:
            name = name.strip()
            if len(name) > NAME_MAX:
                errors.append('%s.name: longer than %d characters' % (where, NAME_MAX))
                bad = True

        allow_duplicate = raw.get('allow_duplicate', False)
        if not isinstance(allow_duplicate, bool):
            errors.append('%s.allow_duplicate: expected true or false' % where)
            bad = True

        if mac is not None:
            if mac in seen_macs:
                errors.append('%s.mac: %s already whitelisted in devices[%d]' % (where, mac, seen_macs[mac]))
                bad = True
            else:
                seen_macs[mac] = i
        if not bad:
            if key in seen_keys:
                warnings.append('%s.key: same key as devices[%d] (unusual: keys are per device)'
                                % (where, seen_keys[key]))
            seen_keys.setdefault(key, i)
            devices.append(DeviceEntry(mac, key, dtype, name, allow_duplicate))

    if errors:
        return Result(errors=errors, warnings=warnings)
    return Result(Config(CONFIG_VERSION, timeout_s, log_level, devices, scanner), warnings=warnings)


def loads(text, known_types=None):
    try:
        data = json.loads(text)
    except ValueError as e:
        line, col = getattr(e, 'lineno', None), getattr(e, 'colno', None)
        where = ' (line %s, column %s)' % (line, col) if line else ''
        return Result(errors=['invalid JSON%s: %s' % (where, getattr(e, 'msg', e))])
    return validate(data, known_types)


def load(path=DEFAULT_PATH, known_types=None):
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
    except FileNotFoundError:
        return Result(errors=['%s: file not found' % path])
    except OSError as e:
        return Result(errors=['%s: %s' % (path, e.strerror or e)])
    except UnicodeDecodeError:
        return Result(errors=['%s: not UTF-8 text' % path])
    return loads(text, known_types)


def dumps(config):
    return json.dumps(config.to_dict(), indent=2) + '\n'


def save(config, path=DEFAULT_PATH):
    """Validate, then write atomically (temporary file + fsync + rename) with mode 0600.

    `config`: Config or plain dict. Raises ValueError when invalid; the existing
    file is then left untouched. Returns the normalized Config that was written.
    """
    data = config.to_dict() if isinstance(config, Config) else config
    res = validate(data)
    if not res.ok:
        raise ValueError('invalid configuration: ' + '; '.join(res.errors))
    text = dumps(res.config)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.victron-ble.', suffix='.tmp', dir=directory)   # mode 0600
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if hasattr(os, 'O_DIRECTORY'):   # make the rename durable (not available on Windows)
        try:
            dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    return res.config


def _as_dict(config):
    if config is None:
        return Config().to_dict()
    if isinstance(config, Config):
        return config.to_dict()
    return json.loads(json.dumps(config))   # deep copy: the caller's dict is never modified


def add_device(config, mac, key, type, name='', allow_duplicate=False):
    """New configuration with one more device (validated, not written)."""
    data = _as_dict(config)
    devices = data.get('devices')
    entry = {'mac': mac, 'key': key, 'type': type, 'name': name}
    if allow_duplicate:
        entry['allow_duplicate'] = True
    data['devices'] = (list(devices) if isinstance(devices, list) else []) + [entry]
    return validate(data)


def remove_device(config, mac):
    """New configuration without `mac` (validated, not written)."""
    data = _as_dict(config)
    try:
        target = normalize_mac(mac)
    except ValueError as e:
        return Result(errors=['mac: %s' % e])
    devices = data.get('devices') if isinstance(data.get('devices'), list) else []
    kept = [d for d in devices if not (isinstance(d, dict) and isinstance(d.get('mac'), str)
                                       and d['mac'].strip().upper() == target)]
    if len(kept) == len(devices):
        return Result(errors=['mac: %s is not whitelisted' % target])
    data['devices'] = kept
    return validate(data)


def diff(old, new):
    """(added, removed, changed) MAC lists between two Configs (None = empty)."""
    a = old.by_mac() if old else {}
    b = new.by_mac() if new else {}
    added = sorted(m for m in b if m not in a)
    removed = sorted(m for m in a if m not in b)
    changed = sorted(m for m in b if m in a and a[m] != b[m])
    return added, removed, changed


class ConfigWatcher(object):
    """Hot reload: poll() re-reads the file when it changes and keeps the last valid config.

    An invalid or missing file never replaces a working configuration, so a typo
    made while editing does not stop the devices already published.
    """
    UNCHANGED, RELOADED, INVALID, MISSING = 'unchanged', 'reloaded', 'invalid', 'missing'

    def __init__(self, path=DEFAULT_PATH, known_types=None):
        self.path = path
        self.known_types = known_types
        self.current = None
        self.last_result = None
        self._valid_result = None
        self._stamp = None
        self._digest = None
        self._reported = None

    def poll(self):
        """Returns (status, Result or None)."""
        try:
            st = os.stat(self.path)
        except OSError:
            if self._report('missing'):
                log.warning('%s: file not found, keeping the current configuration', self.path)
            self._stamp = self._digest = None
            return self.MISSING, None
        stamp = (st.st_mtime_ns, st.st_size)
        if stamp == self._stamp:
            return self.UNCHANGED, self.last_result
        try:
            with open(self.path, 'rb') as f:
                raw = f.read()
        except OSError as e:
            log.warning('%s: %s', self.path, e)
            return self.MISSING, None
        self._stamp = stamp
        digest = hashlib.sha256(raw).hexdigest()
        if digest == self._digest:   # same content as the configuration in use (e.g. a typo undone)
            self.last_result = self._valid_result
            self._reported = None
            return self.UNCHANGED, self.last_result
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            res = Result(errors=['not UTF-8 text'])
        else:
            res = loads(text, self.known_types)
        self.last_result = res
        if not res.ok:
            if self._report(digest):
                log.error('%s invalid, keeping the current configuration: %s', self.path, '; '.join(res.errors))
            return self.INVALID, res
        self._digest = digest
        self._valid_result = res
        self._reported = None
        for w in res.warnings:
            log.warning('%s: %s', self.path, w)
        self.current = res.config
        return self.RELOADED, res

    def _report(self, what):
        """True the first time a given problem is seen (keeps logs quiet while it persists)."""
        if self._reported == what:
            return False
        self._reported = what
        return True
