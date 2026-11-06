"""Victron Instant Readout parsers.

Parsing logic derived from victron_ble 0.9.3 (https://github.com/keshavdv/victron-ble,
keshavdv and contributors), released under the Unlicense: see LICENSE-victron_ble.txt.

Adding a device type: write a module with RECORD_TYPE, LABEL and parse(plain) -> dict
(see dcdc.py), then register it in DEVICE_TYPES below; a mapper is added separately.
"""

from . import ac_charger, codes, dcdc, models
from .base import (HEADER_LEN, INSTANT_READOUT, Header, KeyMismatch, NotInstantReadout,
                   ParseError, TruncatedFrame, UnsupportedRecord, decrypt, parse_header)

__all__ = [
    'HEADER_LEN', 'INSTANT_READOUT', 'VICTRON_COMPANY_ID', 'DEVICE_TYPES', 'RECORD_TYPE_NAMES',
    'Header', 'Reading', 'DeviceType',
    'ParseError', 'NotInstantReadout', 'TruncatedFrame', 'KeyMismatch', 'UnsupportedRecord',
    'parse_header', 'decrypt', 'decode', 'model_name', 'record_type_name', 'type_for_record',
    'code_name', 'off_reason_names', 'format_values', 'ac_charger', 'codes', 'dcdc', 'models',
]

VICTRON_COMPANY_ID = 0x02E1


class DeviceType(object):
    def __init__(self, name, module):
        self.name = name
        self.record_type = module.RECORD_TYPE
        self.label = module.LABEL
        self.payload_bits = module.PAYLOAD_BITS
        self.parse = module.parse

    def __repr__(self):
        return 'DeviceType(%s, record 0x%02X)' % (self.name, self.record_type)


# Configuration type name -> parser. Only these can be whitelisted.
DEVICE_TYPES = {
    'dcdc': DeviceType('dcdc', dcdc),
    'charger': DeviceType('charger', ac_charger),
}
_BY_RECORD = dict((t.record_type, t) for t in DEVICE_TYPES.values())

# Every readout type known to victron_ble, parsed or not (used to describe seen devices)
RECORD_TYPE_NAMES = {
    0x01: 'Solar charger', 0x02: 'Battery monitor', 0x03: 'Inverter', 0x04: 'DC/DC converter',
    0x05: 'SmartLithium', 0x06: 'Inverter RS', 0x08: 'AC charger', 0x09: 'Smart BatteryProtect',
    0x0A: 'Lynx Smart BMS', 0x0B: 'Multi RS', 0x0C: 'VE.Bus', 0x0D: 'DC energy meter',
    0x0F: 'Orion XS',
}


class Reading(object):
    """One decoded advertisement."""
    __slots__ = ('device_type', 'model_id', 'record_type', 'nonce', 'values')

    def __init__(self, device_type, model_id, record_type, nonce, values):
        self.device_type = device_type
        self.model_id = model_id
        self.record_type = record_type
        self.nonce = nonce
        self.values = values

    @property
    def model_name(self):
        return model_name(self.model_id)

    def __repr__(self):
        return 'Reading(%s, model=0x%04X, nonce=0x%04X, %s)' % (
            self.device_type, self.model_id, self.nonce, self.values)


def model_name(model_id):
    return models.MODEL_NAMES.get(model_id, 'Victron device 0x%04X' % model_id)


def record_type_name(record_type):
    return RECORD_TYPE_NAMES.get(record_type, 'record 0x%02X' % record_type)


def type_for_record(record_type):
    """Configuration type name handling this readout type, or None."""
    t = _BY_RECORD.get(record_type)
    return t.name if t else None


def _key_bytes(key):
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    try:
        return bytes.fromhex(key)
    except (TypeError, ValueError):
        raise ParseError('advertisement key is not hexadecimal')


def decode(mfg, key, device_type=None, backend=None):
    """Decode Victron manufacturer data (without the company id) into a Reading.

    `key`: 16 bytes or 32 hex characters. `device_type`: configured type name; when
    given, a frame of another readout type is refused. Only ParseError (and its
    subclasses) can escape: callers must never be brought down by a bad frame.
    """
    header = parse_header(mfg)
    if device_type is not None:
        dt = DEVICE_TYPES.get(device_type)
        if dt is None:
            raise UnsupportedRecord('unknown device type %r' % (device_type,))
        if header.record_type != dt.record_type:
            raise UnsupportedRecord('device configured as %s but advertises %s (0x%02X)' % (
                device_type, record_type_name(header.record_type), header.record_type))
    else:
        dt = _BY_RECORD.get(header.record_type)
        if dt is None:
            raise UnsupportedRecord('no parser for %s (0x%02X)' % (
                record_type_name(header.record_type), header.record_type))
    plain = decrypt(header, _key_bytes(key), backend)
    try:
        values = dt.parse(plain)
    except ParseError:
        raise
    except Exception as e:   # a parser bug must not become a crash of the service
        raise ParseError('%s parser failed: %s: %s' % (dt.name, type(e).__name__, e))
    return Reading(dt.name, header.model_id, header.record_type, header.nonce, values)


def code_name(table, value):
    if value is None:
        return '-'
    return '%s(%d)' % (table.get(value, '?'), value)


def off_reason_names(mask):
    """Names of the single bits set in a VE.Direct off-reason mask."""
    return [name for bit, name in sorted(codes.OFF_REASONS.items())
            if bit and not bit & (bit - 1) and mask & bit]


_UNITS = {'voltage': 'V', 'current': 'A', 'temperature': 'C'}


def format_values(values):
    """One-line human description of Reading.values (logs, CLI)."""
    parts = []
    for k in sorted(values):
        v = values[k]
        if k == 'state':
            parts.append('state=%s' % code_name(codes.OPERATION_MODES, v))
        elif k == 'error':
            parts.append('error=%s' % code_name(codes.CHARGER_ERRORS, v))
        elif k == 'off_reason':
            names = off_reason_names(v)
            parts.append('off_reason=0x%08X%s' % (v, (' ' + '+'.join(names)) if names else ''))
        elif v is None:
            parts.append('%s=-' % k)
        else:
            unit = next((u for frag, u in _UNITS.items() if frag in k), '')
            parts.append('%s=%s%s' % (k, v, (' ' + unit) if unit else ''))
    return ' '.join(parts)
