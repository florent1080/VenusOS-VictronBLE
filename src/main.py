#!/usr/bin/python3 -u
"""VenusOS-VictronBLE service.

Hears Victron Instant Readout advertisements (read only: no GATT connection, no
pairing), decrypts the whitelisted devices, publishes each one as a read-only Venus OS
D-Bus service (mappers/) and keeps /run/victron-ble/seen.json up to date for
`victron-ble discover`.

  main.py [--config PATH] [--seen PATH] [--scanner auto|venus|bluez|none]
          [--replay FILE [--replay-speed X] [--replay-repeat]] [--duration S]
          [--log-level LEVEL]
"""

import argparse
import logging
import os
import signal
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import listener as listener_mod   # noqa: E402
import loop as loop_mod           # noqa: E402
import mappers                    # noqa: E402
import parsers                    # noqa: E402
import registry                   # noqa: E402
import scanner as scanner_mod     # noqa: E402
import seen as seen_mod           # noqa: E402
from parsers import aes           # noqa: E402

VERSION = '1.1'

# Problems a good frame solves: logged again if they come back. The other notes
# ('no_mapper', 'duplicate', 'duplicate_blocked') are logged once per whitelisting.
DECODE_PROBLEMS = frozenset(('key_mismatch', 'type_mismatch', 'error', 'never'))
log = logging.getLogger('victronble')

# D-Bus service classes whose /ProductId reveals a device already published (VE.Direct, ...)
PRODUCT_CLASSES = ('solarcharger', 'battery', 'inverter', 'vebus', 'multi', 'dcdc', 'charger',
                   'acsystem', 'alternator', 'dcsource', 'dcload')


def _same_but_name(a, b):
    """True when two whitelist entries of one MAC differ by their name only."""
    return (a.key, a.type, a.allow_duplicate) == (b.key, b.type, b.allow_duplicate)


def find_products(bus):
    """model id -> [service names] for the devices already on D-Bus, our own excepted."""
    out = {}
    try:
        names = [str(n) for n in bus.list_names()]
    except Exception as e:
        log.debug('list_names failed: %s', e)
        return None
    for name in names:
        parts = name.split('.')
        if len(parts) < 4 or parts[:2] != ['com', 'victronenergy'] or parts[2] not in PRODUCT_CLASSES:
            continue
        if parts[3].startswith('ble_'):          # ours (step 4)
            continue
        try:
            pid = bus.get_object(name, '/ProductId', introspect=False).GetValue(
                dbus_interface='com.victronenergy.BusItem', timeout=2)
            out.setdefault(int(pid), []).append(name)
        except Exception:
            continue
    return out


class Service(object):
    CONFIG_POLL_S = 5
    SEEN_FLUSH_S = 5
    TIMEOUT_CHECK_S = 5
    PRODUCTS_SCAN_S = 60
    PUBLISH_RETRY_S = 30

    def __init__(self, loop, config_path, seen_path, bus=None, clock=time.time,
                 aes_backend=None, scanner_override=None, log_level_override=None, mapper_factory=None):
        self.loop = loop
        self.clock = clock
        self.bus = bus
        self.config_path = config_path
        self.watcher = registry.ConfigWatcher(config_path)
        self.config = registry.Config()          # empty whitelist until a valid file is read
        self.config_status = 'not read'
        self.seen = seen_mod.SeenTable(seen_path, write_interval_s=self.SEEN_FLUSH_S, clock=clock)
        self.backend = aes.get_backend(aes_backend)
        self.scanner_override = scanner_override
        self.log_level_override = log_level_override
        self.listener = None
        self.scan = None
        self.state = {}                          # mac -> per-device runtime state
        self.whitelisted_at = {}                 # mac -> when it entered the whitelist
        # mapper_factory(device, first reading) -> mappers.Mapper; None: nothing published
        self.mapper_factory = mapper_factory
        self.mappers = {}                        # mac -> published Mapper
        self.publish_retry = {}                  # mac -> earliest time for a new publishing attempt
        self.products = {}                       # model id -> services already on D-Bus
        self.counters = Counter()
        self.started = clock()
        self._timers = []

    # ----------------------------------------------------------- lifecycle ----

    def start(self, listener=None, scan=None):
        self.listener, self.scan = listener, scan
        log.info('victron-ble %s starting (AES backend %s)', VERSION, self.backend.name)
        self.reload_config()
        if self.scan:
            if self.scanner_override is None:
                self.scan.mode = self.config.scanner
            self.scan.start()
        if self.listener:
            self.listener.start()
        self._timers = [self.loop.timeout_add_seconds(self.CONFIG_POLL_S, self.reload_config),
                        self.loop.timeout_add_seconds(self.TIMEOUT_CHECK_S, self.check_timeouts),
                        self.loop.timeout_add_seconds(self.SEEN_FLUSH_S, self.flush)]
        if self.bus is not None:
            self.scan_products()
            self._timers.append(self.loop.timeout_add_seconds(self.PRODUCTS_SCAN_S, self.scan_products))
        self.flush(force=True)

    def stop(self):
        for t in self._timers:
            self.loop.source_remove(t)
        self._timers = []
        if self.listener:
            self.listener.stop()
        if self.scan:
            self.scan.stop()
        for mac in list(self.mappers):
            self._unpublish(mac)
        self.flush(force=True)
        log.info('victron-ble stopped (%s)', ', '.join('%s %d' % kv for kv in sorted(self.counters.items())))

    # -------------------------------------------------------- configuration ----

    def reload_config(self):
        status, res = self.watcher.poll()
        if status == self.watcher.RELOADED:
            old, new = self.config, res.config
            added, removed, changed = registry.diff(old if self.config_status == 'ok' else None, new)
            old_by, new_by = old.by_mac(), new.by_mac()
            renamed = [m for m in changed if _same_but_name(old_by[m], new_by[m])]
            changed = [m for m in changed if m not in renamed]
            self.config, self.config_status = new, 'ok'
            if self.log_level_override is None:
                logging.getLogger().setLevel(new.log_level)
            for mac in renamed:                   # a new name only: updated in place, no republishing
                if mac in self.mappers:
                    self.mappers[mac].set_name(new_by[mac])
            for mac in removed + changed:
                self.state.pop(mac, None)
                self.whitelisted_at.pop(mac, None)
                self._unpublish(mac)
            for mac in added + changed:
                self.whitelisted_at[mac] = self.clock()
            self.seen.set_whitelist(new)
            if self.scan and self.scanner_override is None:
                self.scan.set_mode(new.scanner)
            if added or removed or changed or renamed:
                log.info('whitelist: %d device(s)%s%s%s%s', len(new.devices),
                         ', added %s' % ' '.join(added) if added else '',
                         ', removed %s' % ' '.join(removed) if removed else '',
                         ', changed %s' % ' '.join(changed) if changed else '',
                         ', renamed %s' % ' '.join(renamed) if renamed else '')
            elif old is not new:
                log.info('configuration reloaded (%d device(s))', len(new.devices))
        elif status == self.watcher.UNCHANGED:
            if res is not None and res.ok and self.config_status != 'ok':   # a mistake undone
                self.config_status = 'ok'
                log.info('configuration valid again (%d device(s))', len(self.config.devices))
        elif status == self.watcher.INVALID:
            self.config_status = 'invalid (previous configuration kept)' if self.config_status == 'ok' else 'invalid'
        elif status == self.watcher.MISSING and self.config_status != 'ok':
            self.config_status = 'missing'
        return True

    # ------------------------------------------------------- advertisements ----

    def on_advert(self, advert):
        self.counters['frames'] += 1
        if self.scan:
            self.scan.note_advert(advert.t)
        try:
            header = parsers.parse_header(advert.mfg)
        except parsers.ParseError:
            self.counters['other_victron_frames'] += 1    # e.g. the 0x01/0x02 frames of a BMV
            self.seen.update(advert)
            return
        dev = self.config.by_mac().get(advert.mac) if self.config.devices else None
        if dev is None:
            self.seen.update(advert, header, 'not_whitelisted')
            return
        st = self.state.setdefault(advert.mac, {'last': None, 'connected': False, 'mfg': None,
                                                 'status': None, 'reading': None, 'reported': set()})
        if advert.mfg == st['mfg'] and st['status'] == 'ok' and st['connected']:
            st['last'] = advert.t                         # same payload repeated: nothing new to decrypt
            self.seen.update(advert, header, 'ok', st['reading'])
            return
        st['mfg'] = advert.mfg
        try:
            reading = parsers.decode(advert.mfg, dev.key_bytes, dev.type, self.backend)
        except parsers.KeyMismatch:
            self._problem(advert, header, dev, st, 'key_mismatch',
                          'key rejected for %s: its frames carry key check %02x, the configured key starts '
                          'with %s. The key changes when the Bluetooth PIN is changed or reset: copy it '
                          'again from VictronConnect' % (self._label(dev), header.key_check, dev.key[:2]))
            return
        except parsers.UnsupportedRecord as e:
            self._problem(advert, header, dev, st, 'type_mismatch', '%s: %s' % (self._label(dev), e))
            return
        except parsers.ParseError as e:
            self.counters['parse_errors'] += 1
            self._problem(advert, header, dev, st, 'error', '%s: frame rejected: %s' % (self._label(dev), e))
            return
        self.counters['decoded'] += 1
        if not st['connected']:
            log.info('%s heard, %s: %s', self._label(dev), reading.model_name,
                     parsers.format_values(reading.values))
        st.update(last=advert.t, connected=True, status='ok', reading=reading)
        st['reported'] -= DECODE_PROBLEMS      # solved by this frame; publishing notes stay reported
        log.debug('%s nonce 0x%04X %s', dev.mac, reading.nonce, parsers.format_values(reading.values))
        self.seen.update(advert, header, 'ok', reading)
        mapper = self._publish(dev, reading)
        if mapper is not None:
            try:
                mapper.update(reading)
            except Exception:
                log.exception('%s: D-Bus update failed', self._label(dev))

    # ---------------------------------------------------------------- D-Bus ----

    def rename(self, mac, name):
        """A name typed for `mac` in the GUI / VRM: written to the configuration file, like a native
        device keeps its custom name. Returns False (D-Bus then refuses the value) when it cannot be."""
        res = registry.load(self.config_path)
        if not res.ok:   # being edited by hand: never overwrite it
            log.warning('rename of %s refused: %s is invalid right now (%s)', mac, self.config_path,
                        '; '.join(res.errors))
            return False
        data = res.config.to_dict()
        entry = next((d for d in data['devices'] if d['mac'] == mac), None)
        if entry is None:
            log.warning('rename of %s refused: no longer whitelisted', mac)
            return False
        entry['name'] = name
        try:
            registry.save(data, self.config_path)
        except ValueError as e:
            log.warning('rename of %s refused: %s', mac, e)
            return False
        except OSError as e:
            log.error('rename of %s: cannot write %s: %s', mac, self.config_path, e)
            return False
        log.info('%s renamed to %r from the GUI', mac, name.strip())
        # picked up right after this D-Bus call returns (not from inside it)
        self.loop.timeout_add(10, lambda: (self.reload_config(), False)[1], repeat_on_error=False)
        return True

    def _publish(self, dev, reading):
        """Mapper of `dev`, created on its first decoded reading (its model is known then)."""
        mapper = self.mappers.get(dev.mac)
        if mapper is not None or self.mapper_factory is None:
            return mapper
        st = self.state[dev.mac]
        if dev.type not in mappers.MAPPERS:
            if 'no_mapper' not in st['reported']:
                st['reported'].add('no_mapper')
                log.warning('%s: no D-Bus mapper for type %s yet, decoded but not published',
                            self._label(dev), dev.type)
            self.seen.set_dbus(dev.mac, None, 'no D-Bus mapper for %s yet' % dev.type)
            return None
        duplicates = self.products.get(reading.model_id)
        if duplicates and not dev.allow_duplicate:
            if 'duplicate_blocked' not in st['reported']:
                st['reported'].add('duplicate_blocked')
                log.warning('%s: NOT published, model 0x%04X is already published by %s and would show '
                            'twice. Set "allow_duplicate": true for this device to publish it anyway',
                            self._label(dev), reading.model_id, ', '.join(duplicates))
            self.seen.set_dbus(dev.mac, None, 'duplicate of %s' % ', '.join(duplicates))
            return None
        now = self.clock()
        if now < self.publish_retry.get(dev.mac, 0):
            return None
        try:
            mapper = self.mapper_factory(dev, reading)
            mapper.publish()
        except Exception as e:
            self.publish_retry[dev.mac] = now + self.PUBLISH_RETRY_S
            log.error('%s: publishing on D-Bus failed (%s: %s), retrying in %d s', self._label(dev),
                      type(e).__name__, e, self.PUBLISH_RETRY_S)
            self.seen.set_dbus(dev.mac, None, 'publishing failed: %s' % e)
            return None
        self.publish_retry.pop(dev.mac, None)
        mapper.rename_cb = self.rename
        self.mappers[dev.mac] = mapper
        self.seen.set_dbus(dev.mac, mapper.service_name, None)
        return mapper

    def _unpublish(self, mac):
        mapper = self.mappers.pop(mac, None)
        self.publish_retry.pop(mac, None)
        if mapper is not None:
            try:
                mapper.destroy()
            except Exception:
                log.exception('%s: removal from D-Bus failed', mac)
        self.seen.set_dbus(mac, None, None)

    def _problem(self, advert, header, dev, st, status, message):
        st['status'] = status
        if status not in st['reported']:            # once per problem, not once per frame
            st['reported'].add(status)
            log.warning(message)
        self.seen.update(advert, header, status, error=message)

    @staticmethod
    def _label(dev):
        return '%s (%s)' % (dev.name, dev.mac) if dev.name else dev.mac

    # -------------------------------------------------------------- timers ----

    def check_timeouts(self):
        now = self.clock()
        timeout = self.config.timeout_s
        for dev in self.config.devices:
            st = self.state.get(dev.mac)
            if st is None:
                # counted from when the device entered the whitelist, not from the service start
                if now - self.whitelisted_at.get(dev.mac, self.started) > timeout:
                    self.state[dev.mac] = {'last': None, 'connected': False, 'mfg': None, 'status': None,
                                           'reading': None, 'reported': {'never'}}
                    log.warning('%s: no Instant Readout heard since it was whitelisted (%d s)',
                                self._label(dev), timeout)
                continue
            if st['connected'] and st['last'] is not None and now - st['last'] > timeout:
                st['connected'] = False
                log.warning('%s: nothing heard for %d s, marked disconnected', self._label(dev), timeout)
                mapper = self.mappers.get(dev.mac)
                if mapper is not None:      # /Connected = 0, the D-Bus service itself stays
                    try:
                        mapper.disconnect()
                    except Exception:
                        log.exception('%s: D-Bus disconnect failed', self._label(dev))
        return True

    def scan_products(self):
        products = find_products(self.bus)
        if products is None:
            return True
        self.products = products
        self.seen.set_vedirect(products)
        for dev in self.config.devices:
            d = self.seen.devices.get(dev.mac)
            model = d.get('model_id_int') if d else None
            st = self.state.get(dev.mac)
            if model in products and st is not None and 'duplicate' not in st['reported']:
                st['reported'].add('duplicate')
                log.warning('%s: model 0x%04X is already published by %s: whitelisting it would show '
                            'the device twice', self._label(dev), model, ', '.join(products[model]))
        return True

    def flush(self, force=False):
        self.seen.extra = {
            'service': {'version': VERSION, 'started': round(self.started, 1), 'config': self.config_path,
                        'config_status': self.config_status, 'aes_backend': self.backend.name,
                        'counters': dict(self.counters)},
            'scanner': self.scan.status() if self.scan else None,
            'listener': dict(self.listener.stats) if self.listener else None,
        }
        self.seen.flush(force=force)
        return True


def build_parser():
    p = argparse.ArgumentParser(prog='main.py', description='VenusOS-VictronBLE service')
    p.add_argument('--config', default=registry.DEFAULT_PATH)
    p.add_argument('--seen', default=seen_mod.DEFAULT_PATH)
    p.add_argument('--scanner', choices=scanner_mod.MODES, help='override the "scanner" of the configuration')
    p.add_argument('--replay', metavar='FILE', help='read advertisements from a jsonl file instead of Bluetooth')
    p.add_argument('--replay-speed', type=float, default=1.0, help='1 = real time, 0 = as fast as possible')
    p.add_argument('--replay-repeat', action='store_true')
    p.add_argument('--duration', type=float, help='stop after this many seconds')
    p.add_argument('--log-level', choices=registry.LOG_LEVELS, help='override the configuration')
    p.add_argument('--aes', choices=aes.BACKEND_ORDER, help='force an AES backend')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(format='%(levelname)-8s %(name)s: %(message)s',
                        level=args.log_level or registry.DEFAULT_LOG_LEVEL)

    loop = loop_mod.make_loop(prefer_glib=not args.replay)
    bus = None
    if not args.replay:
        try:
            import dbus
            from dbus.mainloop.glib import DBusGMainLoop
            DBusGMainLoop(set_as_default=True)
            bus = dbus.SystemBus()
        except Exception as e:
            log.error('no system D-Bus (%s): scanning control and duplicate detection disabled', e)

    scanner_override = args.scanner or ('none' if args.replay else None)   # a replay never scans
    def private_connection():
        import dbus
        return dbus.SystemBus(private=True)

    def factory(dev, reading):
        return mappers.MAPPERS[dev.type](dev, reading.model_id, reading.model_name, bus, VERSION,
                                         first_values=reading.values, bus_factory=private_connection)
    svc = Service(loop, args.config, args.seen, bus=bus, aes_backend=args.aes,
                  scanner_override=scanner_override, log_level_override=args.log_level,
                  mapper_factory=factory if bus is not None else None)

    def finish():
        loop.quit()

    if args.replay:
        src = listener_mod.ReplayListener(loop, svc.on_advert, args.replay, speed=args.replay_speed,
                                          repeat=args.replay_repeat, on_end=finish)
        scan = scanner_mod.ScanDriver(loop, scanner_override)
    else:
        src = listener_mod.HciMonitorListener(loop, svc.on_advert)
        scan = scanner_mod.ScanDriver(loop, scanner_override or registry.DEFAULT_SCANNER,
                                      sensors=scanner_mod.VenusSensorsSetting(bus) if bus else None,
                                      discovery=scanner_mod.BluezDiscovery(bus) if bus else None)
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal(signum, finish)
    if args.duration:
        loop.timeout_add(int(args.duration * 1000), lambda: finish() or False, repeat_on_error=False)

    svc.start(src, scan)
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
