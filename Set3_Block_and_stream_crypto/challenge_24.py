"""
Orel Ben-Reuven
https://cryptopals.com/sets/3/challenges/24

Create the MT19937 stream cipher and break it
You can create a trivial stream cipher out of any PRNG;
use it to generate a sequence of 8 bit outputs and call those outputs a keystream.
XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed.
Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters)
prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

Write a function to check if any given password token is actually the
product of an MT19937 PRNG seeded with the current time.
"""

import math
from Crypto.Random import get_random_bytes, random

from challenge_21 import MT19937
from Utils.BytesLogic import xor_bytes


class MT19937Cipher:
    def __init__(self, seed: int):
        # verify input
        if seed > (2**16 - 1):
            raise ValueError('seed value exceeds 16 bits')

        self.seed = seed

    def generate_key_stream(self, input_len: int) -> bytes:
        # number of 4-bytes number to generate
        num_words = math.ceil(input_len / 4)

        # generate random sequence
        key_stream_gen = (i.to_bytes(4, byteorder='little') for i in MT19937(seed=self.seed, length=num_words))
        key_stream = b''.join(key_stream_gen)

        # trim and return
        key_stream = key_stream[:input_len]
        return key_stream

    def encrypt(self, plaintext: bytes) -> bytes:
        key_stream = self.generate_key_stream(len(plaintext))
        ciphertext = xor_bytes((plaintext, key_stream))
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        key_stream = self.generate_key_stream(len(ciphertext))
        plaintext = xor_bytes((ciphertext, key_stream))
        return plaintext


def detect_seed(ciphertext: bytes, known_plaintext: bytes) -> int:
    """ Brute force all 16-bit seed possibilities"""
    for seed in range(2**16):
        cipher_obj = MT19937Cipher(seed=seed)
        decryption = cipher_obj.decrypt(ciphertext)
        if known_plaintext in decryption:
            return seed


def main():
    # Randomize key
    key = random.getrandbits(16)
    cipher_obj = MT19937Cipher(seed=key)

    # Generate input
    prefix = get_random_bytes(random.randrange(5, 15))
    plaintext = b'A' * 14
    ciphertext = cipher_obj.encrypt(prefix + plaintext)

    # Recover seed
    detected_seed = detect_seed(ciphertext, b'A'*14)
    print(detected_seed == key)


if __name__ == '__main__':
    main()
