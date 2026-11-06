#!/usr/bin/python3 -u
"""victron-ble command line.

  victron-ble validate [-c CONFIG]
      Check the whitelist file; exit code 0 when valid, 1 otherwise.

  victron-ble discover [--seen PATH] [--all] [--json]
      List the Victron devices the service hears (from /run/victron-ble/seen.json).

  victron-ble add MAC [--key HEX] [--type TYPE] [--name NAME] [--force] [-c CONFIG]
      Whitelist a device. Without --key the key is asked without echo (keeps it out
      of the shell history). The running service picks the change up within seconds.

  victron-ble remove MAC [-c CONFIG]

  victron-ble decode (--key HEX | -c CONFIG --mac MAC) [--type TYPE] [--mac MAC] (FRAME_HEX... | --jsonl FILE)
      Decode recorded Instant Readout frames (manufacturer data without the
      0x02E1 company id, e.g. the "mfg" field of the diagnostic's victron_adv.jsonl).
"""

import argparse
import getpass
import json
import logging
import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import parsers            # noqa: E402
import registry           # noqa: E402
import seen as seen_mod   # noqa: E402
from parsers import aes   # noqa: E402

STALE_AFTER_S = 30


def _load_seen(path, out):
    try:
        return seen_mod.load(path)
    except FileNotFoundError:
        print('%s not found: is the victron-ble service running?' % path, file=out)
    except (OSError, ValueError) as e:
        print('cannot read %s: %s' % (path, e), file=out)
    return None


def _age(seconds):
    if seconds is None:
        return '-'
    if seconds < 90:
        return '%.0f s' % seconds
    if seconds < 5400:
        return '%.0f min' % (seconds / 60)
    return '%.1f h' % (seconds / 3600)


def _describe(d):
    """Status column of `discover`."""
    if d.get('whitelisted'):
        label = d.get('name') or 'whitelisted'
        status = d.get('status')
        if status == 'ok' and d.get('values'):
            text = '%s: ok, %s' % (label, parsers.format_values(d['values']))
        elif status == 'key_mismatch':
            text = '%s: KEY REJECTED (device key check %s): key changed? copy it again' % (label, d.get('key_check'))
        elif status in ('type_mismatch', 'error'):
            text = '%s: %s' % (label, d.get('error') or status)
        else:
            text = '%s: waiting for an Instant Readout frame' % label
    elif d.get('supported_type'):
        text = 'not whitelisted (victron-ble add %s --type %s)' % (d['mac'], d['supported_type'])
    elif d.get('record_type'):
        text = 'not whitelisted (%s: not supported yet)' % d.get('record_name')
    else:
        text = 'no Instant Readout frame (enable it in VictronConnect: Product info)'
    if d.get('dbus'):
        text += ' | published as %s' % d['dbus']
    elif d.get('whitelisted') and d.get('dbus_note'):
        text += ' | not published: %s' % d['dbus_note']
    if d.get('vedirect_duplicate'):
        text += ' | already on D-Bus: %s' % ', '.join(d['vedirect_duplicate'])
    return text


def cmd_discover(args, out):
    doc = _load_seen(args.seen, out)
    if doc is None:
        return 1
    if args.json:
        json.dump(doc, out, indent=1, sort_keys=True)
        out.write('\n')
        return 0
    age = time.time() - doc.get('updated', 0)
    scan = doc.get('scanner') or {}
    svc = doc.get('service') or {}
    print('seen.json updated %s ago by pid %s; scanning: %s (mode %s, Venus OS Bluetooth sensors %s); '
          'configuration %s' % (_age(age), doc.get('pid'), scan.get('state', '?'), scan.get('mode', '?'),
                                {1: 'on', 0: 'off'}.get(scan.get('ble_sensors'), 'unknown'),
                                svc.get('config_status', '?')), file=out)
    if age > STALE_AFTER_S:
        print('WARNING: not updated for %s: the service is probably stopped' % _age(age), file=out)
    devices = [d for d in doc.get('devices', []) if args.all or d.get('record_type') or d.get('whitelisted')]
    hidden = len(doc.get('devices', [])) - len(devices)
    if not devices:
        print('no Victron device heard%s' % (' (%d without Instant Readout, see --all)' % hidden if hidden else ''),
              file=out)
        return 0
    print('%-17s  %-40s  %-16s  %5s  %7s  %s' % ('MAC', 'MODEL', 'TYPE', 'RSSI', 'HEARD', 'STATUS'), file=out)
    for d in devices:
        print('%-17s  %-40s  %-16s  %5s  %7s  %s' % (
            d['mac'], (d.get('model_name') or '-')[:40], (d.get('record_name') or '-')[:16],
            d.get('rssi', '-'), _age(d.get('age_s')), _describe(d)), file=out)
    if hidden:
        print('(%d device(s) without Instant Readout frame hidden, see --all)' % hidden, file=out)
    return 0


def _config_for_edit(path, out):
    res = registry.load(path)
    if res.ok:
        return res.config
    if any('file not found' in e for e in res.errors):
        return registry.Config()
    print('%s is invalid, fix it first:' % path, file=out)
    for e in res.errors:
        print('  error: %s' % e, file=out)
    return None


def cmd_add(args, out):
    try:
        mac = registry.normalize_mac(args.mac)
    except ValueError as e:
        print('add: %s' % e, file=out)
        return 2
    config = _config_for_edit(args.config, out)
    if config is None:
        return 1
    try:
        heard = dict((d['mac'], d) for d in seen_mod.load(args.seen).get('devices', []))
    except (OSError, ValueError):
        heard = {}
    d = heard.get(mac, {})
    dtype = args.type or d.get('supported_type')
    if not dtype:
        print('add: give --type (%s): %s was not heard with a supported Instant Readout record'
              % (', '.join(sorted(parsers.DEVICE_TYPES)), mac), file=out)
        return 2
    key = args.key if args.key is not None else getpass.getpass('Instant Readout key of %s (hidden): ' % mac)
    key = key.strip().lower()
    problems = []
    if d.get('key_check') and key[:2] != d['key_check']:
        problems.append('the device broadcasts key check %s but this key starts with %s: wrong key?'
                        % (d['key_check'], key[:2]))
    if d.get('vedirect_duplicate'):
        problems.append('model %s is already published by %s: it would show twice'
                        % (d.get('model_id'), ', '.join(d['vedirect_duplicate'])))
    if problems and not args.force:
        for p in problems:
            print('add: %s' % p, file=out)
        print('add: nothing written (use --force to add anyway)', file=out)
        return 1
    res = registry.add_device(config, mac, key, dtype, args.name or '',
                              allow_duplicate=bool(args.force and d.get('vedirect_duplicate')))
    if not res.ok:
        for e in res.errors:
            print('add: %s' % e, file=out)
        return 1
    registry.save(res.config, args.config)
    print('%s added as %s%s to %s; the service reloads it within seconds'
          % (mac, dtype, (' "%s"' % args.name) if args.name else '', args.config), file=out)
    return 0


def cmd_remove(args, out):
    config = _config_for_edit(args.config, out)
    if config is None:
        return 1
    res = registry.remove_device(config, args.mac)
    if not res.ok:
        for e in res.errors:
            print('remove: %s' % e, file=out)
        return 1
    registry.save(res.config, args.config)
    print('%s removed from %s' % (registry.normalize_mac(args.mac), args.config), file=out)
    return 0


def cmd_validate(args, out):
    res = registry.load(args.config)
    for w in res.warnings:
        print('warning: %s' % w, file=out)
    if not res.ok:
        print('%s: INVALID' % args.config, file=out)
        for e in res.errors:
            print('  error: %s' % e, file=out)
        return 1
    c = res.config
    print('%s: OK, %d device(s), timeout %s s, log level %s'
          % (args.config, len(c.devices), c.timeout_s, c.log_level), file=out)
    for d in c.devices:
        print('  %s  %-8s key %s  %s' % (d.mac, d.type, d.key_hint, d.name or '-'), file=out)
    return 0


def _frames(args):
    """(t, mac, mfg bytes) from the command line or a jsonl file."""
    if args.jsonl:
        with open(args.jsonl, encoding='utf-8') as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    yield rec.get('t'), (rec.get('mac') or '').upper(), bytes.fromhex(rec['mfg'])
                except (ValueError, KeyError, TypeError) as e:
                    yield None, '', ValueError('line %d: %s' % (n, e))
    for h in args.frames:
        try:
            data = bytes.fromhex(h.replace(':', '').replace(' ', ''))
        except ValueError as e:
            yield None, '', ValueError('%r: %s' % (h, e))
            continue
        if data[:3] == b'\xe1\x02\x10':   # pasted with the company id: strip it
            data = data[2:]
        yield None, args.mac or '', data


def cmd_decode(args, out):
    key, dtype = args.key, args.type
    mac = registry.normalize_mac(args.mac) if args.mac else None
    if key is None:
        if not (args.config and mac):
            print('decode: give --key, or --config with --mac', file=out)
            return 2
        res = registry.load(args.config)
        if not res.ok:
            print('decode: %s is invalid: %s' % (args.config, '; '.join(res.errors)), file=out)
            return 2
        dev = res.config.by_mac().get(mac)
        if dev is None:
            print('decode: %s is not whitelisted in %s' % (mac, args.config), file=out)
            return 2
        key, dtype = dev.key, dtype or dev.type
    backend = aes.get_backend(args.aes) if args.aes else aes.get_backend()
    print('AES backend: %s' % backend.name, file=out)

    stats, shown = Counter(), Counter()
    for t, frame_mac, mfg in _frames(args):
        if isinstance(mfg, Exception):
            stats['unreadable input'] += 1
            print('  skipped: %s' % mfg, file=out)
            continue
        if mac and frame_mac and frame_mac != mac:
            continue
        when = ('+%7.2f s ' % t) if isinstance(t, (int, float)) else ''
        try:
            r = parsers.decode(mfg, key, dtype, backend)
        except parsers.ParseError as e:
            kind = type(e).__name__
            stats[kind] += 1
            if shown[kind] < 3:                 # a few examples per kind, not one line per frame
                shown[kind] += 1
                print('  %s%s %s: %s' % (when, frame_mac or '-', kind, e), file=out)
            continue
        stats['decoded'] += 1
        print('  %s%s nonce 0x%04X %s | %s' % (when, frame_mac or '-', r.nonce, r.model_name,
                                              parsers.format_values(r.values)), file=out)
    print('summary: %s' % (', '.join('%s %d' % kv for kv in sorted(stats.items())) or 'no frame'), file=out)
    return 0 if stats['decoded'] else 1


def build_parser():
    p = argparse.ArgumentParser(prog='victron-ble', description='VenusOS-VictronBLE command line')
    sub = p.add_subparsers(dest='command')
    v = sub.add_parser('validate', help='check the whitelist file')
    v.add_argument('-c', '--config', default=registry.DEFAULT_PATH)
    s = sub.add_parser('discover', help='list the Victron devices heard by the service')
    s.add_argument('--seen', default=seen_mod.DEFAULT_PATH)
    s.add_argument('--all', action='store_true', help='also devices without Instant Readout frames')
    s.add_argument('--json', action='store_true', help='raw seen.json')
    a = sub.add_parser('add', help='whitelist a device')
    a.add_argument('mac')
    a.add_argument('--key', help='32 hexadecimal characters (asked without echo when omitted)')
    a.add_argument('--type', choices=sorted(parsers.DEVICE_TYPES), help='default: from what was heard')
    a.add_argument('--name', help='name shown in Venus OS')
    a.add_argument('--force', action='store_true', help='add despite a key check or duplicate warning')
    a.add_argument('-c', '--config', default=registry.DEFAULT_PATH)
    a.add_argument('--seen', default=seen_mod.DEFAULT_PATH)
    r = sub.add_parser('remove', help='remove a device from the whitelist')
    r.add_argument('mac')
    r.add_argument('-c', '--config', default=registry.DEFAULT_PATH)
    d = sub.add_parser('decode', help='decode recorded Instant Readout frames')
    d.add_argument('frames', nargs='*', help='manufacturer data in hexadecimal')
    d.add_argument('--jsonl', help='file with one JSON object per line ("mfg", optional "mac" and "t")')
    d.add_argument('--key', help='advertisement key, 32 hexadecimal characters')
    d.add_argument('-c', '--config', help='take key and type from this whitelist (needs --mac)')
    d.add_argument('--mac', help='only frames from this device')
    d.add_argument('--type', choices=sorted(parsers.DEVICE_TYPES), help='expected device type')
    d.add_argument('--aes', choices=aes.BACKEND_ORDER, help='force an AES backend')
    return p


def main(argv=None, out=None):
    out = out or sys.stdout
    logging.basicConfig(format='%(levelname)-8s %(message)s', level=logging.WARNING)
    args = build_parser().parse_args(argv)
    if args.command == 'validate':
        return cmd_validate(args, out)
    if args.command == 'discover':
        return cmd_discover(args, out)
    if args.command == 'add':
        return cmd_add(args, out)
    if args.command == 'remove':
        return cmd_remove(args, out)
    if args.command == 'decode':
        if not args.frames and not args.jsonl:
            print('decode: give frames in hexadecimal or --jsonl FILE', file=out)
            return 2
        try:
            return cmd_decode(args, out)
        except ValueError as e:
            print('decode: %s' % e, file=out)
            return 2
    build_parser().print_help(out)
    return 2


if __name__ == '__main__':
    sys.exit(main())
