"""
Orel Ben-Reuven
https://cryptopals.com/sets/3/challenges/18

Implement CTR, the stream cipher mode
The string: L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
... decrypts to something approximating English in CTR mode,
which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:

key=YELLOW SUBMARINE
nonce=0
format=64 bit unsigned little endian nonce,
       64 bit little endian block count (byte count / 16)

CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream,
which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
... for the next 16 bytes:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
... and then:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

CTR mode does not require padding; when you run out of plaintext,
you just stop XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.

This is the only block cipher mode that matters in good code.
Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers,
because most of what we want to encrypt is better described as a stream than as a sequence of blocks.
Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt" transforms.
Constructions like CTR are what he was talking about.
"""

import base64
import math
import random
from typing import Literal
from Crypto.Cipher import AES

from Utils.bytes_logic import xor_bytes


class AesCtr:
    def __init__(self, key: bytes, nonce: bytes = None, byteorder: Literal["little", "big"] = "little"):
        # verify input
        if byteorder not in ["big", "little"]:
            raise ValueError('byteorder must be "big" or "little"')

        if nonce is None:
            self.nonce = random.randbytes(8)
        else:
            self.nonce = nonce

        # init vals
        self.key = key
        self.byteorder = byteorder
        self.cipher_obj = AES.new(self.key, AES.MODE_ECB)

    def generate_key_stream(self, input_len: int) -> bytes:
        key_stream = bytes()
        counter = 0
        for _ in range(math.ceil(input_len / AES.block_size)):
            # create and encrypt counter block
            counter_block = self.nonce + counter.to_bytes(AES.block_size // 2, byteorder=self.byteorder)
            key_stream += self.cipher_obj.encrypt(counter_block)

            # update for next block
            counter += 1

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


def main():
    ciphertext = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

    aes_ctr = AesCtr(b'YELLOW SUBMARINE', nonce=bytes(8), byteorder='little')
    plaintext = aes_ctr.decrypt(ciphertext)
    print(plaintext)


if __name__ == '__main__':
    main()
