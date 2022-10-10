import hashlib
import math
import random

from Crypto.Util.number import getPrime

from Utils.Number import invmod


class RsaBase:
    def __init__(self, key_len: int = 1024):
        # key gen
        while True:
            # repeat until we find et which is co-prime to e
            try:
                # Generate 2 random primes
                p, q = getPrime(key_len//2), getPrime(key_len//2)

                # RSA math is modulo n
                n = p * q

                # calc the "totient"
                et = (p - 1) * (q - 1)
                e = 3

                # calc private key
                d = invmod(e, et)
                break

            except ValueError:
                continue

        # keys summery
        self.n = n
        self.e = e
        self._d = d

        # length of modulus in octets
        self.k = math.ceil(math.log2(n) / 8)

    def encrypt_base(self, m: int) -> int:
        c = pow(m, self.e, self.n)
        return c

    def decrypt_base(self, c: int) -> int:
        m = pow(c, self._d, self.n)
        return m

    @staticmethod
    def bytes_to_integer(stream: bytes) -> int:
        return int.from_bytes(stream, byteorder='big')

    def integer_to_bytes_padded(self, num: int) -> bytes:
        return int.to_bytes(num, self.k, byteorder='big')

    @staticmethod
    def integer_to_bytes_squeezed(num: int) -> bytes:
        bytes_len = math.ceil(num.bit_length() / 8)
        return int.to_bytes(num, bytes_len, byteorder='big')


class RSA(RsaBase):
    def __init__(self, key_len: int = 1024, squeeze_output: bool = True):
        super().__init__(key_len)

        # choose integer-to-bytes conversion
        if squeeze_output:
            self.integer_to_bytes = self.integer_to_bytes_squeezed
        else:
            self.integer_to_bytes = self.integer_to_bytes_padded

    def encrypt(self, m, input_bytes=True, output_bytes=False):
        if input_bytes:
            m = self.bytes_to_integer(m)

        c = self.encrypt_base(m)

        if output_bytes:
            c = self.integer_to_bytes(c)

        return c

    def decrypt(self, c, input_bytes=False, output_bytes=True):
        if input_bytes:
            c = self.bytes_to_integer(c)

        m = self.decrypt_base(c)

        if output_bytes:
            m = self.integer_to_bytes(m)

        return m


class DSA:
    p = int('800000000000000089e1855218a0e7dac38136ffafa72eda7'
            '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
            '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
            'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
            'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
            '1a584471bb1', 16)

    q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

    g = int('5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
            '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
            '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
            '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
            '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
            '9fc95302291', 16)

    def __init__(self):
        # Per-user keys
        self.x = random.randint(1, self.q - 1)  # private key
        self.y = pow(self.g, self.x, self.p)  # public key

    @staticmethod
    def H(x):
        return int(hashlib.sha1(x).hexdigest(), 16)

    def sign(self, msg: bytes) -> (int, int):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue

            k_inv = invmod(k, self.q)
            s = (k_inv * (self.H(msg) + self.x * r)) % self.q
            if s != 0:
                break

        return r, s

    def verify(self, msg: bytes, sig: (int, int)) -> bool:
        # unpack sig
        r, s = sig

        # check signature bounds
        if not (0 < r < self.q and 0 < s < self.q):
            return False

        w = invmod(s, self.q)
        u1 = (self.H(msg) * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q

        return v == r
