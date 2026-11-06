import unittest

import _path  # noqa: F401
from loop import SimpleLoop


class SimpleLoopTests(unittest.TestCase):
    def test_timers_in_order_and_virtual_time(self):
        loop = SimpleLoop(virtual=True, start=1000.0)
        seen = []
        loop.timeout_add(300, lambda: seen.append(('b', loop.now())))
        loop.timeout_add(100, lambda: seen.append(('a', loop.now())))
        loop.run()
        self.assertEqual(seen, [('a', 1000.1), ('b', 1000.3)])

    def test_repeat_and_remove(self):
        loop = SimpleLoop(virtual=True)
        n = []

        def tick():
            n.append(1)
            if len(n) == 3:
                loop.source_remove(sid)
            return True
        sid = loop.timeout_add_seconds(5, tick)
        loop.run()
        self.assertEqual(len(n), 3)

    def test_exception_keeps_a_repeating_timer(self):
        loop = SimpleLoop(virtual=True)
        n = []

        def flaky():
            n.append(1)
            if len(n) == 4:
                loop.quit()
            raise ValueError('bad frame')
        loop.timeout_add(10, flaky)
        with self.assertLogs('victronble.loop', level='ERROR'):
            loop.run()
        self.assertEqual(len(n), 4)

    def test_one_shot_on_error_when_asked(self):
        loop = SimpleLoop(virtual=True)
        n = []

        def once():
            n.append(1)
            raise ValueError('x')
        loop.timeout_add(10, once, repeat_on_error=False)
        with self.assertLogs('victronble.loop', level='ERROR'):
            loop.run()
        self.assertEqual(n, [1])

    def test_arguments_and_quit(self):
        loop = SimpleLoop(virtual=True)
        got = []
        loop.timeout_add(10, lambda a, b: got.append(a + b), 2, 3)
        loop.timeout_add(20, loop.quit)
        loop.timeout_add(30, lambda: got.append('never'))
        loop.run()
        self.assertEqual(got, [5])


if __name__ == '__main__':
    unittest.main()
