import math
from Crypto.Util.number import getPrime

from Utils.number import invmod


class RSA:
    def __init__(self, key_len: int = 1024):
        # key gen
        while True:
            # repeat until we find et which is co-prime to e
            try:
                # Generate 2 random primes
                p, q = getPrime(key_len), getPrime(key_len)

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
        self.d = d
        self.e = e

        # length of modulus in octets
        self.k = math.ceil(math.log2(n) / 8)

    def encrypt(self, m: bytes) -> int:
        m = self.bytes_to_integer(m)
        c = pow(m, self.e, self.n)
        return c

    def decrypt(self, c: int) -> bytes:
        m = pow(c, self.d, self.n)
        m = self.integer_to_bytes(m)
        return m

    def sign(self, m: bytes) -> int:
        m = self.bytes_to_integer(m)
        c = pow(m, self.d, self.n)
        return c

    def verify_sign(self, c: int) -> bytes:
        m = pow(c, self.e, self.n)
        m = self.integer_to_bytes(m)
        return m

    @staticmethod
    def bytes_to_integer(stream: bytes) -> int:
        return int.from_bytes(stream, byteorder='big')

    def integer_to_bytes(self, num: int) -> bytes:
        return int.to_bytes(num, self.k, 'big')
