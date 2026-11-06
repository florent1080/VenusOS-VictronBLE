import unittest

import _path  # noqa: F401
from loop import SimpleLoop
from scanner import ScanDriver


class FakeSensors(object):
    def __init__(self, value=1):
        self.value = value
        self.writes = 0          # the driver must never change the user's setting

    def get(self):
        return self.value


class FakeDiscovery(object):
    def __init__(self, ok=True):
        self.ok = ok
        self.running = False
        self.starts = 0
        self.stops = 0
        self.discovering = True

    def start(self):
        self.starts += 1
        self.running = self.ok
        return self.ok

    def stop(self):
        self.stops += 1
        self.running = False

    def adapter_discovering(self):
        return self.discovering


class Clock(object):
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def driver(mode='auto', value=1, ok=True):
    sensors, disc, clock = FakeSensors(value), FakeDiscovery(ok), Clock()
    d = ScanDriver(SimpleLoop(virtual=True), mode, sensors, disc, clock=clock)
    return d, sensors, disc, clock


class AutoModeTests(unittest.TestCase):
    def test_relies_on_venus_sensors_when_on(self):
        d, sensors, disc, _ = driver(value=1)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
        self.assertEqual(d.state, 'venus')
        self.assertEqual(disc.starts, 0)

    def test_follows_the_user_without_touching_the_setting(self):
        d, sensors, disc, _ = driver(value=1)
        with self.assertLogs('victronble.scanner', level='INFO') as logs:
            d.check()
            sensors.value = 0                 # the user turns the Venus sensors off
            d.check()
            self.assertEqual((d.state, disc.running, disc.starts), ('bluez', True, 1))
            sensors.value = 1                 # and back on
            d.check()
        self.assertEqual((d.state, disc.running, disc.stops), ('venus', False, 1))
        self.assertEqual(sensors.writes, 0)
        text = '\n'.join(logs.output)
        self.assertIn('turned off by the user', text)
        self.assertIn('their setting is left unchanged', text)

    def test_unreadable_setting_waits_then_scans_itself(self):
        d, sensors, disc, _ = driver(value=None)
        for _ in range(ScanDriver.UNKNOWN_SETTING_LIMIT - 1):   # boot: localsettings not up yet
            d.check()
        self.assertEqual((d.state, disc.starts), ('idle', 0))
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
        self.assertEqual(d.state, 'bluez')

    def test_discovery_failure_is_retried(self):
        d, sensors, disc, _ = driver(value=0, ok=False)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
        self.assertEqual(d.state, 'idle')
        disc.ok = True
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
        self.assertEqual((d.state, disc.starts), ('bluez', 2))

    def test_restarts_a_lost_discovery(self):
        d, sensors, disc, _ = driver(value=0)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
        disc.discovering = False              # bluetoothd restarted: our session is gone
        with self.assertLogs('victronble.scanner', level='WARNING'):
            d.check()
        self.assertEqual(disc.starts, 2)

    def test_stop_ends_our_discovery(self):
        d, sensors, disc, _ = driver(value=0)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
            d.stop()
        self.assertEqual((disc.running, d.state), (False, 'idle'))


class OtherModesTests(unittest.TestCase):
    def test_venus_mode_never_scans(self):
        d, sensors, disc, _ = driver('venus', value=0)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
        self.assertEqual((d.state, disc.starts), ('venus', 0))

    def test_bluez_mode_warns_when_both_scan(self):
        d, sensors, disc, _ = driver('bluez', value=1)
        with self.assertLogs('victronble.scanner', level='WARNING') as logs:
            d.check()
        self.assertEqual(d.state, 'bluez')
        self.assertIn('two scans run', '\n'.join(logs.output))

    def test_none_mode(self):
        d, sensors, disc, _ = driver('none', value=0)
        d.check()
        self.assertEqual((d.state, disc.starts), ('idle', 0))

    def test_mode_change_at_run_time(self):
        d, sensors, disc, _ = driver('auto', value=0)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
            d.set_mode('venus')
        self.assertEqual((d.state, disc.running), ('venus', False))

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            ScanDriver(SimpleLoop(virtual=True), 'loud')


class SilenceTests(unittest.TestCase):
    def test_warns_once_then_recovers(self):
        d, sensors, disc, clock = driver(value=1)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.check()
        clock.t += 200
        with self.assertLogs('victronble.scanner', level='WARNING') as logs:
            d.check()
            d.check()
        self.assertEqual(sum('no Victron advertisement' in m for m in logs.output), 1)
        with self.assertLogs('victronble.scanner', level='INFO'):
            d.note_advert()
        self.assertIsNotNone(d.status()['last_advert'])


if __name__ == '__main__':
    unittest.main()
