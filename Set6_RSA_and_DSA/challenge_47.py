"""
Orel Ben-Reuven
https://cryptopals.com/sets/6/challenges/47

Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

Degree of difficulty: moderate
These next two challenges are the hardest in the entire set.

Let us Google this for you: "Chosen ciphertext attacks against protocols based on the RSA encryption standard"

This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps versions on the first search page.

Read the paper. It describes a padding oracle attack on PKCS#1v1.5.
The attack is similar in spirit to the CBC padding oracle you built earlier;
it's an "adaptive chosen ciphertext attack", which means you start with a valid ciphertext and repeatedly corrupt it,
bouncing the adulterated ciphertexts off the target to learn things about the original.

This is a common flaw even in modern cryptosystems that use RSA.

It's also the most fun you can have building a crypto attack. It involves 9th grade math,
but also has you implementing an algorithm that is complex on par with finding a minimum cost spanning tree.

The setup:
- Build an oracle function, just like you did in the last exercise,
  but have it check for plaintext[0] == 0 and plaintext[1] == 2.
- Generate a 256 bit keypair (that is, p and q will each be 128 bit primes), [n, e, d].
- Plug d and n into your oracle function.
- PKCS1.5-pad a short message, like "kick it, CC", and call it "m". Encrypt to to get "c".
- Decrypt "c" using your padding oracle.

For this challenge, we've used an untenably small RSA modulus (you could factor this keypair instantly).
That's because this exercise targets a specific step in the Bleichenbacher paper --- Step 2c, which implements a fast,
nearly O(log n) search for the plaintext.

Things you want to keep in mind as you read the paper:
- RSA ciphertexts are just numbers.
- RSA is "homomorphic" with respect to multiplication, which means you can multiply c * RSA(2) to get a c' that will
  decrypt to plaintext * 2. This is mindbending but easy to see if you play with it in code ---
  try multiplying ciphertexts with the RSA encryptions of numbers so you know you grok it.
- What you need to grok for this challenge is that Bleichenbacher uses multiplication on ciphertexts
  the way the CBC oracle uses XORs of random blocks.
- A PKCS#1v1.5 conformant plaintext, one that starts with 00:02, must be a number between 02:00:00...00 and
  02:FF:FF..FF --- in other words, 2B and 3B-1, where B is the bit size of the modulus minus the first 16 bits.
  When you see 2B and 3B, that's the idea the paper is playing with.

To decrypt "c", you'll need Step 2a from the paper (the search for the first "s" that,
when encrypted and multiplied with the ciphertext, produces a conformant plaintext),
Step 2c, the fast O(log n) search, and Step 3.

Your Step 3 code is probably not going to need to handle multiple ranges.

We recommend you just use the raw math from paper (check, check, double check your translation to code)
and not spend too much time trying to grok how the math works.
"""

from Utils.Number import invmod, integer_division_ceil
from Utils.PublicKey import RsaBase

from Crypto.Random.random import randint


class RSA_PKCS1_Type2_Oracle(RsaBase):
    """
    Implementation of RSA Encryption Scheme.
    Based on the standard PKCS #1 Version 1.5 for type-2 blocks
    https://www.rfc-editor.org/rfc/rfc2313
    """
    def __init__(self, key_len=1024):
        super().__init__(key_len)

    def pkcs_padding(self, msg: bytes) -> bytes:
        # check bounds
        if len(msg) > self.k - 11:
            raise ValueError(f'Message length must not exceeds {self.k - 11} octets')

        # encode the data
        prefix = b'\x00\x02'
        padding = bytes([randint(1, 2 ** 8 - 1) for _ in range(self.k - 3 - len(msg))])
        suffix = b'\x00'

        # EB = 00 || BT || PS || 00 || D
        msg_encoded = prefix + padding + suffix + msg
        assert len(msg_encoded) == self.k

        return msg_encoded

    def pkcs_unpadding(self, msg: bytes) -> bytes:
        """
        Un-pad the PKCS message.
        raise [AttributeError] is mark is incorrect.
        raise [ValueError] if \x00 sep is not included.
        """
        # verify the PKCS mark
        if msg[0:2] != b'\x00\x02':
            raise AttributeError('Cipher is not PKCS conforming')

        # find the 00 separator between the padding and the payload
        sep_idx = msg.index(b'\x00', 2)
        sep_idx += 1

        # decode the message block
        msg = msg[sep_idx:]
        return msg

    def encrypt(self, msg: bytes) -> int:
        # encode the message
        msg_encoded = self.pkcs_padding(msg)

        # convert to integer and encrypt
        msg_encoded = self.bytes_to_integer(msg_encoded)
        cipher = self.encrypt_base(msg_encoded)

        return cipher

    def validate_msg(self, cipher: int) -> bool:
        """ Return True if the message starts with \x00\x02 """
        # decrypt cipher and convert to bytes
        msg = self.decrypt_base(cipher)
        msg = self.integer_to_bytes_padded(msg)
        assert len(msg) == self.k

        # verify the PKCS mark
        if msg[0:2] == b'\x00\x02':
            return True
        else:
            return False


def bleichenbacher98_attack_partial(oracle: RSA_PKCS1_Type2_Oracle, c: int):
    # Set consts
    e, n = oracle.e, oracle.n
    B = 2 ** (8 * (oracle.k-2))

    # Initialize variables
    i = 1
    M_prev = [(2*B, 3*B - 1)]
    s_prev = None

    # Step 1: Blinding.
    # (In our case, c in already PKCS conforming)
    s0 = 1
    c0 = (c * pow(s0, e, n)) % n

    while True:
        print(f'Iteration number {i} ...')

        # Step 2: Searching for PKCS conforming messages.
        # Step 2.a: find the smallest positive integer s1 >= n/3B
        if i == 1:
            s = integer_division_ceil(n, (3*B))
            while not oracle.validate_msg((c0 * pow(s, e, n)) % n):
                s += 1

        # Step 2.b: Searching with more than one interval left.
        elif len(M_prev) > 1:
            raise NotImplementedError

        # Step 2.c: Searching with one interval left.
        else:
            a, b = M_prev[0]
            r = integer_division_ceil(2 * (b * s_prev - 2 * B), n)
            s = integer_division_ceil((2 * B + r * n), b)

            while True:
                if oracle.validate_msg((c0 * pow(s, e, n)) % n):
                    break

                if s < (3 * B + r * n) // a:
                    s += 1

                else:
                    r += 1
                    s = integer_division_ceil((2 * B + r * n), b)

        # verify step 2 result
        assert oracle.validate_msg((c0 * pow(s, e, n)) % n)

        # Step 3: Narrowing the set of solutions.
        a, b = M_prev[0]

        r_up = (b*s - 2*B) // n
        r_dwn = integer_division_ceil((a*s - 3*B + 1), n)
        assert r_up == r_dwn
        r = r_dwn

        dwn = max(a, integer_division_ceil((2*B + r*n), s))
        up = min(b, (3*B - 1 + r*n) // s)

        M = [(dwn, up)]

        # Step 4: Computing the solution.
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = (M[0][0] * invmod(s0, n)) % n
            return m

        # Update prev variables
        s_prev = s
        M_prev = M
        i += 1


def main():
    oracle = RSA_PKCS1_Type2_Oracle(key_len=256)
    msg = b'kick it, CC'

    cipher = oracle.encrypt(msg)
    print(f'{cipher=}')

    assert oracle.validate_msg(cipher)
    assert not oracle.validate_msg(cipher + 1)

    decryption = bleichenbacher98_attack_partial(oracle, cipher)
    decryption = oracle.integer_to_bytes_padded(decryption)
    decryption = oracle.pkcs_unpadding(decryption)
    assert decryption == msg
    print(f'{decryption=}')


if __name__ == '__main__':
    main()
