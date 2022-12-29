import unittest
import random
import hashlib
import hmac

from Crypto.Random import get_random_bytes


class HashTests(unittest.TestCase):
    def test_sha1(self):
        from Utils.Hash import SHA1

        for i in range(5000):
            msg = random.randbytes(random.randint(1, 1000))
            my_digestion = SHA1(msg)

            m = hashlib.sha1()
            m.update(msg)
            digestion = m.digest()

            self.assertEqual(my_digestion, digestion, 'digestion differ')

    def test_hmac_sha1(self):
        from Utils.Hash import HMAC

        for i in range(5000):
            msg = random.randbytes(random.randint(1, 1000))
            key = get_random_bytes(random.randint(1, 1000))
            my_digestion = HMAC.sha1(key=key, msg=msg)

            py_digestion = hmac.digest(key=key, msg=msg, digest='sha1')

            self.assertEqual(my_digestion, py_digestion, 'digestion differ')


if __name__ == '__main__':
    unittest.main()
