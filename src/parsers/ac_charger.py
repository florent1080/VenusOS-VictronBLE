"""AC charger record (readout type 0x08): Blue Smart IP22 / IP65 / IP67, Phoenix Smart.

Derived from victron_ble 0.9.3, victron_ble/devices/ac_charger.py
(https://github.com/keshavdv/victron-ble), released under the Unlicense: see
LICENSE-victron_ble.txt. Codes are kept as integers (unknown values never raise).

Single-output models report outputs 2 and 3 as not available (None).
"""

from .base import BitReader

RECORD_TYPE = 0x08
LABEL = 'AC charger'
PAYLOAD_BITS = 8 + 8 + 3 * (13 + 11) + 7 + 9


def parse(plain):
    """Plain payload -> dict. None means 'not available' in the advertisement."""
    r = BitReader(plain)
    state = r.read_unsigned_int(8)
    error = r.read_unsigned_int(8)
    out = {}
    for n in (1, 2, 3):
        voltage = r.read_unsigned_int(13)    # 0.01 V
        current = r.read_unsigned_int(11)    # 0.1 A
        out['output_voltage%d' % n] = None if voltage == 0x1FFF else round(voltage / 100.0, 2)
        out['output_current%d' % n] = None if current == 0x7FF else round(current / 10.0, 1)
    temperature = r.read_unsigned_int(7)     # degrees Celsius + 40
    ac_current = r.read_unsigned_int(9)      # 0.1 A
    out.update({
        'state': None if state == 0xFF else state,
        'error': None if error == 0xFF else error,
        'temperature': None if temperature == 0x7F else temperature - 40,
        'ac_current': None if ac_current == 0x1FF else round(ac_current / 10.0, 1),
    })
    return out
