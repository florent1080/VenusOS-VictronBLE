import os
import random
import unittest

import _path  # noqa: F401
from parsers import aes

# FIPS-197 appendix C.1 and NIST SP 800-38A F.1.1 (ECB-AES128, blocks 1 and 2)
VECTORS = [
    ('000102030405060708090a0b0c0d0e0f', '00112233445566778899aabbccddeeff', '69c4e0d86a7b0430d8cdb78070b4c55a'),
    ('2b7e151628aed2a6abf7158809cf4f3c', '6bc1bee22e409f96e93d7e117393172a', '3ad77bb40d7a3660a89ecaf32466ef97'),
    ('2b7e151628aed2a6abf7158809cf4f3c', 'ae2d8a571e03ac9c9eb76fac45af8e51', 'f5d3d58503b9699de785895a96fdbaaf'),
]


def backend_or_skip(test, name):
    try:
        return aes.get_backend(name)
    except aes.BackendUnavailable as e:
        test.skipTest('%s unavailable here: %s' % (name, e))


class BackendTests(unittest.TestCase):
    def check_vectors(self, name):
        b = backend_or_skip(self, name)
        for key, pt, ct in VECTORS:
            self.assertEqual(b.encrypt_blocks(bytes.fromhex(key), bytes.fromhex(pt)).hex(), ct)
        # several blocks at once
        key, pt1, ct1 = VECTORS[1]
        _, pt2, ct2 = VECTORS[2]
        self.assertEqual(b.encrypt_blocks(bytes.fromhex(key), bytes.fromhex(pt1 + pt2)).hex(), ct1 + ct2)

    def test_python(self):
        self.check_vectors('python')

    def test_cryptography(self):
        self.check_vectors('cryptography')

    def test_libcrypto(self):
        self.check_vectors('libcrypto')

    def test_backends_agree(self):
        names = aes.available_backends()
        self.assertIn('python', names)
        rnd = random.Random(1)
        for _ in range(50):
            key = bytes(rnd.getrandbits(8) for _ in range(16))
            data = bytes(rnd.getrandbits(8) for _ in range(16 * rnd.randint(1, 4)))
            results = set(aes.get_backend(n).encrypt_blocks(key, data) for n in names)
            self.assertEqual(len(results), 1, 'backends disagree: %s' % names)

    def test_default_is_first_available(self):
        self.assertEqual(aes.get_backend().name, aes.available_backends()[0])

    def test_unknown_backend(self):
        with self.assertRaises(ValueError):
            aes.get_backend('rot13')

    def test_python_rejects_bad_key(self):
        with self.assertRaises(ValueError):
            aes.get_backend('python').encrypt_blocks(b'short', bytes(16))


class CounterModeTests(unittest.TestCase):
    """The Instant Readout counter is a 128-bit little-endian integer starting at the nonce."""

    def setUp(self):
        self.key = bytes(range(16))
        self.py = aes.get_backend('python')

    def test_keystream_blocks(self):
        nonce = 0x1A2B
        ks = aes.ctr_le_keystream(self.key, nonce, 40, self.py)
        self.assertEqual(len(ks), 40)
        for i in range(3):
            block = self.py.encrypt_blocks(self.key, (nonce + i).to_bytes(16, 'little'))
            self.assertEqual(ks[16 * i:16 * (i + 1)], block[:len(ks[16 * i:16 * (i + 1)])])

    def test_counter_carries_past_16_bits(self):
        ks = aes.ctr_le_keystream(self.key, 0xFFFF, 32, self.py)
        second = self.py.encrypt_blocks(self.key, bytes([0, 0, 1]) + bytes(13))   # 0x10000 little-endian
        self.assertEqual(ks[16:], second)

    def test_decrypt_is_involution(self):
        data = os.urandom(23)
        enc = aes.ctr_le_decrypt(self.key, 0x0102, data, self.py)
        self.assertNotEqual(enc, data)
        self.assertEqual(aes.ctr_le_decrypt(self.key, 0x0102, enc, self.py), data)

    def test_empty_payload(self):
        self.assertEqual(aes.ctr_le_decrypt(self.key, 0, b'', self.py), b'')

    def test_matches_pycryptodome_when_installed(self):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util import Counter
        except ImportError:
            self.skipTest('pycryptodome not installed (only used as an independent reference)')
        data = os.urandom(37)
        ref = AES.new(self.key, AES.MODE_CTR,
                      counter=Counter.new(128, initial_value=0x1D12, little_endian=True)).decrypt(data)
        self.assertEqual(aes.ctr_le_decrypt(self.key, 0x1D12, data, self.py), ref)


if __name__ == '__main__':
    unittest.main()
