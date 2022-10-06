"""
Orel Ben-Reuven
https://cryptopals.com/sets/6/challenges/45

DSA parameter tampering

Take your DSA code from the previous exercise.
Imagine it as part of an algorithm in which the client was allowed to propose domain parameters
(the p and q moduli, and the g generator).

This would be bad, because attackers could trick victims into accepting bad parameters.
Vaudenay gave two examples of bad generator parameters: generators that were 0 mod p, and generators that were 1 mod p.

Use the parameters from the previous exercise, but substitute 0 for "g".
Generate a signature. You will notice something bad. Verify the signature.
Now verify any other signature, for any other string.

Now, try (p+1) as "g".
With this "g", you can generate a magic signature s, r for any DSA public key that will validate against any string.
For arbitrary z:

  r = ((y**z) % p) % q

        r
  s =  --- % q
        z

Sign "Hello, world". And "Goodbye, world".
"""

import hashlib
import random

from Utils.Number import invmod


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

    def __init__(self, override_g=None):
        # Per-user keys
        self.x = random.randint(1, self.q - 1)  # private key
        self.y = pow(self.g, self.x, self.p)  # public key

        if override_g is not None:
            self.g = override_g

    @staticmethod
    def H(x):
        return int(hashlib.sha1(x).hexdigest(), 16)

    def sign(self, msg: bytes) -> (int, int):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q

            k_inv = invmod(k, self.q)
            s = (k_inv * (self.H(msg) + self.x * r)) % self.q
            if s != 0:
                break

        return r, s

    def verify(self, msg: bytes, sig: (int, int)) -> bool:
        # unpack sig
        r, s = sig

        w = invmod(s, self.q)
        u1 = (self.H(msg) * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q

        return v == r


def main():
    # example 1
    dsa = DSA(override_g=0)
    msg = b'Whats Wrong??'

    sig = dsa.sign(msg)
    print(sig)

    print(dsa.verify(msg, sig))
    print(dsa.verify(b'what is going on in here', (0, 85478656467)))

    # example 2
    dsa = DSA(override_g=DSA.p+1)

    z = 4
    z_inv = invmod(z, dsa.q)
    r = pow(dsa.y, z, dsa.p) % dsa.q
    s = (z_inv * r) % dsa.q
    magic_sig = (r, s)

    print(dsa.verify(b'Whattttt ???????', magic_sig))


if __name__ == '__main__':
    main()
