"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/39

Implement RSA
There are two annoying things about implementing RSA.
Both of them involve key generation; the actual encryption/decryption in RSA is trivial.

First, you need to generate random primes. You can't just agree on a prime ahead of time, like you do in DH.
You can write this algorithm yourself, but I just cheat and use OpenSSL's BN library to do the work.

The second is that you need an "invmod" operation (the multiplicative inverse),
which is not an operation that is wired into your language.
The algorithm is just a couple lines, but I always lose an hour getting it to work.

I recommend you not bother with primegen, but do take the time to get your own EGCD and invmod algorithm working.

Now:
- Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a prime table.
  Call them "p" and "q".
- Let n be p * q. Your RSA math is modulo n.
- Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
- Let e be 3.
- Compute d = invmod(e, et). invmod(17, 3120) is 2753.
- Your public key is [e, n]. Your private key is [d, n].
- To encrypt: c = m**e%n. To decrypt: m = c**d%n
- Test this out with a number, like "42".
- Repeat with bignum primes (keep e=3).

Finally, to encrypt a string, do something cheesy, like convert the string to hex and put "0x" on the front of it
to turn it into a number. The math cares not how stupidly you feed it strings.
"""

from Crypto.Util.number import getPrime

from Utils.Number import invmod


class RSA:
    def __init__(self, key_len: int = 100):
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

    def encrypt(self, m: bytes) -> int:
        m = self.bytes_to_num(m)
        c = pow(m, self.e, self.n)
        return c

    def decrypt(self, c: int) -> bytes:
        m = pow(c, self.d, self.n)
        m = self.num_to_bytes(m)
        return m

    @staticmethod
    def bytes_to_num(seq: bytes) -> int:
        return int(seq.hex(), 16)

    @staticmethod
    def num_to_bytes(seq: int) -> bytes:
        hex_rep = hex(seq)[2:]
        hex_rep = '0'*(len(hex_rep) % 2) + hex_rep
        return bytes.fromhex(hex_rep)


def main():
    rsa_obj = RSA(key_len=1024)
    m = b'RSA implementation'
    c = rsa_obj.encrypt(m)
    print(f'{c=}')

    m_rec = rsa_obj.decrypt(c)
    print(f'{m_rec=}')


if __name__ == '__main__':
    main()
