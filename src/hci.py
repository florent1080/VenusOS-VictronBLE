"""Bluetooth HCI advertising reports, as delivered by the Linux monitor channel.

The monitor channel (HCI_CHANNEL_MONITOR, the one btmon reads) gives every reader
a copy of every HCI packet of every controller. It is read-only by design: nothing
can be sent to a controller through it, so listening there cannot disturb Venus
OS's own Bluetooth services, whoever is scanning.

Layouts follow the Linux kernel (hci_ev_le_advertising_info / hci_ev_le_ext_adv_info).
"""

import struct

MON_HEADER = struct.Struct('<HHH')      # hci_mon_hdr: opcode, controller index, payload length
MON_NEW_INDEX, MON_DEL_INDEX, MON_COMMAND, MON_EVENT = 0, 1, 2, 3
EVT_LE_META = 0x3E
LE_ADV_REPORT, LE_EXT_ADV_REPORT = 0x02, 0x0D
AD_MANUFACTURER_DATA = 0xFF
RSSI_UNAVAILABLE = 127

_LEGACY_EVT = {0: 'ADV_IND', 1: 'ADV_DIRECT_IND', 2: 'ADV_SCAN_IND', 3: 'ADV_NONCONN_IND', 4: 'SCAN_RSP'}


class AdvReport(object):
    __slots__ = ('address', 'address_type', 'event_type', 'rssi', 'data')

    def __init__(self, address, address_type, event_type, rssi, data):
        self.address = address          # 6 bytes, little-endian as on the wire
        self.address_type = address_type
        self.event_type = event_type
        self.rssi = rssi
        self.data = data                # advertising data (AD structures)

    @property
    def mac(self):
        return fmt_mac(self.address)


def fmt_mac(addr):
    return ':'.join('%02X' % b for b in reversed(addr))


def split_monitor_packet(pkt):
    """hci_mon_hdr + payload -> (opcode, index, payload). ValueError when malformed."""
    if len(pkt) < MON_HEADER.size:
        raise ValueError('monitor packet shorter than its header')
    opcode, index, length = MON_HEADER.unpack_from(pkt, 0)
    payload = pkt[MON_HEADER.size:MON_HEADER.size + length]
    if len(payload) < length:
        raise ValueError('monitor packet truncated')
    return opcode, index, payload


def _legacy(p):
    off, out = 2, []
    for _ in range(p[1]):
        evt, atype, addr, dlen = p[off], p[off + 1], p[off + 2:off + 8], p[off + 8]
        data = p[off + 9:off + 9 + dlen]
        if len(addr) < 6 or len(data) < dlen or off + 9 + dlen >= len(p):
            raise ValueError('truncated advertising report')
        rssi = struct.unpack_from('b', p, off + 9 + dlen)[0]
        out.append(AdvReport(bytes(addr), atype, _LEGACY_EVT.get(evt, 'evt0x%02x' % evt), rssi, bytes(data)))
        off += 10 + dlen
    return out


def _extended(p):
    off, out = 2, []
    for _ in range(p[1]):
        if off + 24 > len(p):
            raise ValueError('truncated extended advertising report')
        evt, atype = struct.unpack_from('<HB', p, off)
        addr = p[off + 3:off + 9]
        rssi = struct.unpack_from('b', p, off + 13)[0]
        dlen = p[off + 23]
        data = p[off + 24:off + 24 + dlen]
        if len(data) < dlen:
            raise ValueError('truncated extended advertising report')
        out.append(AdvReport(bytes(addr), atype, 'ext/0x%04x' % evt, rssi, bytes(data)))
        off += 24 + dlen
    return out


def adv_reports(event):
    """HCI event (code, length, parameters) -> advertising reports ([] for other events).

    Raises ValueError on a malformed advertising event.
    """
    if len(event) < 3 or event[0] != EVT_LE_META:
        return []
    p = event[2:2 + event[1]]
    try:
        if p[0] == LE_ADV_REPORT:
            return _legacy(p)
        if p[0] == LE_EXT_ADV_REPORT:
            return _extended(p)
    except (IndexError, struct.error) as e:
        raise ValueError('malformed advertising event: %s' % e)
    return []


def manufacturer_data(ad, company_id):
    """Payload of the manufacturer specific AD structure of `company_id` (company id removed),
    or None. Malformed AD data gives None, never an exception."""
    i, n = 0, len(ad)
    while i < n:
        length = ad[i]
        if length == 0 or i + 1 + length > n:
            return None
        if ad[i + 1] == AD_MANUFACTURER_DATA and length >= 3 and \
                ad[i + 2] | (ad[i + 3] << 8) == company_id:
            return bytes(ad[i + 4:i + 1 + length])
        i += 1 + length
    return None
