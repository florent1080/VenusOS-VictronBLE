"""Instant Readout container, decryption and bit-level reader.

Derived from victron_ble 0.9.3, victron_ble/devices/base.py
(https://github.com/keshavdv/victron-ble, keshavdv and contributors),
released under the Unlicense: see LICENSE-victron_ble.txt.

Changes from victron_ble:
  - no third-party dependency: struct and our own aes module;
  - frames whose first byte is not 0x10 (not an Instant Readout record) are
    rejected instead of being decrypted into garbage;
  - a payload shorter than the record needs is rejected instead of padded;
  - every failure is a ParseError subclass, so a caller only catches one type.

Manufacturer data layout, after the 0x02E1 company id:
  0     record type, 0x10 = product advertisement (Instant Readout)
  1     unknown, 0x00 on Orion-Tr Smart, 0x02 on SmartSolar / BMV
  2-3   model id, little-endian (= /ProductId on D-Bus)
  4     readout (record) type: 0x04 DC/DC converter, 0x08 AC charger, ...
  5-6   nonce / IV, little-endian; changes when the data changes (about 1 Hz)
  7     first byte of the advertisement key (key check)
  8-    AES-128-CTR ciphertext
"""

import struct

from . import aes

INSTANT_READOUT = 0x10
HEADER_LEN = 8
_HEADER = struct.Struct('<HHBHB')


class ParseError(ValueError):
    """Advertisement that cannot be decoded. Never fatal for the caller."""


class NotInstantReadout(ParseError):
    """Victron manufacturer data that is not an Instant Readout record."""


class TruncatedFrame(ParseError):
    """Payload shorter than the record layout requires."""


class KeyMismatch(ParseError):
    """The key check byte does not match the configured key."""


class UnsupportedRecord(ParseError):
    """Record type with no parser, or different from the configured device type."""


class Header(object):
    """Clear-text part of an Instant Readout frame."""
    __slots__ = ('prefix', 'model_id', 'record_type', 'nonce', 'key_check', 'ciphertext')

    def __init__(self, prefix, model_id, record_type, nonce, key_check, ciphertext):
        self.prefix = prefix
        self.model_id = model_id
        self.record_type = record_type
        self.nonce = nonce
        self.key_check = key_check
        self.ciphertext = ciphertext

    def __repr__(self):
        return ('Header(model=0x%04X, record=0x%02X, nonce=0x%04X, key_check=0x%02X, %d bytes)'
                % (self.model_id, self.record_type, self.nonce, self.key_check, len(self.ciphertext)))


def parse_header(mfg):
    """`mfg`: manufacturer data without the company id, as BlueZ exposes ManufacturerData[0x02E1]."""
    try:
        data = bytes(mfg)
    except (TypeError, ValueError):
        raise NotInstantReadout('manufacturer data is not a byte string')
    if len(data) < HEADER_LEN:
        raise NotInstantReadout('%d bytes, an Instant Readout frame has at least %d' % (len(data), HEADER_LEN))
    if data[0] != INSTANT_READOUT:
        raise NotInstantReadout('record type 0x%02X, not 0x%02X (Instant Readout)' % (data[0], INSTANT_READOUT))
    prefix, model_id, record_type, nonce, key_check = _HEADER.unpack_from(data, 0)
    return Header(prefix, model_id, record_type, nonce, key_check, data[HEADER_LEN:])


def decrypt(header, key, backend=None):
    """Plain payload of `header` with the 16-byte `key`. Raises KeyMismatch on a wrong key."""
    if len(key) != 16:
        raise ParseError('advertisement key must be 16 bytes, got %d' % len(key))
    if header.key_check != key[0]:
        raise KeyMismatch('key check byte 0x%02X does not match the configured key' % header.key_check)
    return aes.ctr_le_decrypt(key, header.nonce, header.ciphertext, backend)


class BitReader(object):
    """Reads bit fields packed LSB first, in the order of the Victron documentation."""

    def __init__(self, data):
        self._data = data
        self._index = 0
        self._bits = len(data) * 8

    def read_bit(self):
        if self._index >= self._bits:
            raise TruncatedFrame('payload too short (%d bytes)' % len(self._data))
        bit = (self._data[self._index >> 3] >> (self._index & 7)) & 1
        self._index += 1
        return bit

    def read_unsigned_int(self, num_bits):
        if self._index + num_bits > self._bits:
            raise TruncatedFrame('payload too short: %d bits needed at bit %d, %d available'
                                 % (num_bits, self._index, self._bits))
        value = 0
        for position in range(num_bits):
            value |= self.read_bit() << position
        return value

    def read_signed_int(self, num_bits):
        return self.to_signed_int(self.read_unsigned_int(num_bits), num_bits)

    @staticmethod
    def to_signed_int(value, num_bits):
        return value - (1 << num_bits) if value & (1 << (num_bits - 1)) else value
