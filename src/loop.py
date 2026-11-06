"""Event loop used by the service: GLib on Venus OS, a small stand-in elsewhere.

Every callback goes through _guard(): an exception is logged and the source keeps
running. With plain GLib an exception in a callback silently removes the source
(this is what disables vesmart-server's PIN protection when it meets an unknown
mgmt event): one bad frame must never stop the listener or a timer.

Interface (both loops):
    timeout_add(ms, cb, *args) / timeout_add_seconds(s, cb, *args) -> id
        cb returns True to be called again, anything else to stop.
    io_add_watch(fd, cb) -> id      cb(fd, condition) returns True to keep watching.
    source_remove(id), add_signal(signum, cb), now(), run(), quit()
"""

import heapq
import logging
import select
import signal
import time

log = logging.getLogger('victronble.loop')

IO_IN, IO_ERR, IO_HUP = 1, 8, 16   # same values as GLib.IOCondition


def _guard(cb, args, name, repeat_on_error):
    def wrapper(*cb_args):
        try:
            return cb(*(cb_args + args))
        except Exception:
            log.exception('callback %s failed%s', name, ' (kept running)' if repeat_on_error else '')
            return repeat_on_error
    return wrapper


class GLibLoop(object):
    def __init__(self):
        from gi.repository import GLib
        self.GLib = GLib
        self._loop = GLib.MainLoop()

    def now(self):
        return time.time()

    def timeout_add(self, ms, cb, *args, **kw):
        return self.GLib.timeout_add(int(ms), _guard(cb, args, getattr(cb, '__name__', 'timer'),
                                                     kw.get('repeat_on_error', True)))

    def timeout_add_seconds(self, s, cb, *args, **kw):
        return self.GLib.timeout_add_seconds(int(s), _guard(cb, args, getattr(cb, '__name__', 'timer'),
                                                            kw.get('repeat_on_error', True)))

    def io_add_watch(self, fd, cb):
        G = self.GLib
        return G.io_add_watch(fd, G.PRIORITY_DEFAULT, G.IO_IN | G.IO_ERR | G.IO_HUP,
                              _guard(lambda f, cond: cb(f, int(cond)), (), getattr(cb, '__name__', 'io'), True))

    def source_remove(self, sid):
        try:
            self.GLib.source_remove(sid)
        except Exception:
            pass

    def add_signal(self, signum, cb):
        self.GLib.unix_signal_add(self.GLib.PRIORITY_HIGH, signum,
                                  _guard(lambda: (cb(), False)[1], (), 'signal', False))

    def run(self):
        self._loop.run()

    def quit(self):
        self._loop.quit()


class SimpleLoop(object):
    """Timers and socket watches without GLib (PC, replay, tests).

    virtual=True: time jumps straight to the next timer instead of sleeping, so a
    replay of minutes of recorded frames runs instantly in a test.
    """

    def __init__(self, virtual=False, start=None):
        self.virtual = virtual
        self._now = start if start is not None else time.time()
        self._timers = []       # heap of (when, seq, sid)
        self._sources = {}      # sid -> ('timer', interval, cb) | ('io', fd, cb)
        self._seq = 0
        self._quit = False

    def now(self):
        return self._now if self.virtual else time.time()

    def _add(self, entry):
        self._seq += 1
        self._sources[self._seq] = entry
        return self._seq

    def timeout_add(self, ms, cb, *args, **kw):
        g = _guard(cb, args, getattr(cb, '__name__', 'timer'), kw.get('repeat_on_error', True))
        sid = self._add(('timer', ms / 1000.0, g))
        heapq.heappush(self._timers, (self.now() + ms / 1000.0, sid, sid))
        return sid

    def timeout_add_seconds(self, s, cb, *args, **kw):
        return self.timeout_add(s * 1000, cb, *args, **kw)

    def io_add_watch(self, fd, cb):
        return self._add(('io', fd, _guard(cb, (), getattr(cb, '__name__', 'io'), True)))

    def source_remove(self, sid):
        self._sources.pop(sid, None)

    def add_signal(self, signum, cb):
        try:
            signal.signal(signum, lambda *a: cb())
        except (ValueError, OSError, AttributeError):   # not in the main thread / not on this OS
            pass

    def quit(self):
        self._quit = True

    def run(self):
        self._quit = False
        while not self._quit:
            while self._timers and self._timers[0][2] not in self._sources:
                heapq.heappop(self._timers)               # drop removed timers
            ios = dict((sid, e) for sid, e in self._sources.items() if e[0] == 'io')
            if not self._timers and (not ios or self.virtual):
                return                                    # nothing left to wait for
            due = self._timers[0][0] if self._timers else None
            wait = None if due is None else max(0.0, due - self.now())
            if ios:
                fds = [e[1] for e in ios.values()]
                ready = select.select(fds, [], [], 0 if self.virtual else wait)[0]
                for sid, e in list(ios.items()):
                    if e[1] in ready and sid in self._sources and e[2](e[1], IO_IN) is not True:
                        self._sources.pop(sid, None)
                if ready:
                    continue
            elif wait and not self.virtual:
                time.sleep(wait)
            if due is None:
                continue
            if self.virtual:
                self._now = max(self._now, due)
            if self.now() < due:
                continue
            _, _, sid = heapq.heappop(self._timers)
            entry = self._sources.get(sid)
            if entry is None:
                continue
            if entry[2]() is True and sid in self._sources:
                heapq.heappush(self._timers, (due + entry[1], sid, sid))
            else:
                self._sources.pop(sid, None)


def make_loop(prefer_glib=True):
    if prefer_glib:
        try:
            return GLibLoop()
        except ImportError:
            log.info('GLib not available: using the simple event loop')
    return SimpleLoop()
