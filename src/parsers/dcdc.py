"""DC/DC converter record (readout type 0x04): Orion-Tr Smart, Orion Smart.

Derived from victron_ble 0.9.3, victron_ble/devices/dcdc_converter.py
(https://github.com/keshavdv/victron-ble), released under the Unlicense: see
LICENSE-victron_ble.txt. Codes are kept as integers (unknown values never raise).

The Orion-Tr does not measure current: the record carries none.
"""

from .base import BitReader

RECORD_TYPE = 0x04
LABEL = 'DC/DC converter'
PAYLOAD_BITS = 8 + 8 + 16 + 16 + 32


def parse(plain):
    """Plain payload -> dict. None means 'not available' in the advertisement."""
    r = BitReader(plain)
    state = r.read_unsigned_int(8)           # VE.Direct CS: 0 off, 3 bulk, 4 absorption, 5 float, ...
    error = r.read_unsigned_int(8)           # VE.Direct ERR
    input_voltage = r.read_unsigned_int(16)  # 0.01 V
    output_voltage = r.read_signed_int(16)   # 0.01 V
    off_reason = r.read_unsigned_int(32)     # VE.Direct OR bit mask
    return {
        'state': None if state == 0xFF else state,
        'error': None if error == 0xFF else error,
        'input_voltage': None if input_voltage == 0xFFFF else round(input_voltage / 100.0, 2),
        'output_voltage': None if output_voltage == 0x7FFF else round(output_voltage / 100.0, 2),
        'off_reason': off_reason,
    }
