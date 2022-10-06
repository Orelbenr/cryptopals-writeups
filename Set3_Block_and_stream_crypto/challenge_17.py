"""
Orel Ben-Reuven
https://cryptopals.com/sets/3/challenges/17

The CBC padding oracle
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future encryptions),
pad the string out to the 16-byte AES block size and CBC-encrypt it under that key,
providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding,
and return true or false depending on whether the padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications;
the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.
The decryption here depends on a side-channel leak by the decryption function.
The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding,
and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
02h in isolation is not valid padding.
02h 02h is valid padding, but is much less likely to occur randomly than 01h.
03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded".
Padding oracles have nothing to do with the actual padding on a CBC plaintext.
It's an attack that targets a specific bit of code that handles decryption.
You can mount a padding oracle on any CBC block, whether it's padded or not.
"""

import random
from Crypto.Random import get_random_bytes

from Utils.AES import aes_cbc_decrypt, aes_cbc_encrypt
from Utils.bytes_logic import xor_bytes
from Utils.Padding import pkcs7_unpad

# globals
AES_BLOCK_SIZE = 16


class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.nonce = get_random_bytes(AES_BLOCK_SIZE)
        self.data = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                     b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                     b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                     b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                     b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                     b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                     b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                     b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                     b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                     b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

    def encrypt(self) -> tuple[bytes, bytes]:
        # select rand string
        plaintext = random.choice(self.data)
        # pad and encrypt
        ciphertext = aes_cbc_encrypt(plaintext, key=self.key, nonce=self.nonce, add_padding=True)
        return ciphertext, self.nonce

    def decrypt(self, ciphertext: bytes) -> bool:
        try:
            aes_cbc_decrypt(ciphertext, key=self.key, nonce=self.nonce, remove_padding=True)
            return True
        except ValueError:
            return False


def decrypt_block_mask(oracle: Oracle, current_block: bytes) -> bytes:
    # initialize empty mask
    mask = bytearray(AES_BLOCK_SIZE)

    # decrypt byte at a time from end to start
    for byte_idx in range(AES_BLOCK_SIZE-1, -1, -1):
        # build previous block
        pad_value = AES_BLOCK_SIZE - byte_idx
        last_block = bytearray(xor_bytes((bytes([pad_value] * AES_BLOCK_SIZE), mask)))

        # iterate values until the padding is correct
        for byte_val in range(2**8):
            last_block[byte_idx] = byte_val
            sequence = last_block + current_block

            # stop when the padding is correct
            if oracle.decrypt(sequence):
                # we know the plaintext byte value, so we calc the mask byte value
                mask[byte_idx] = byte_val ^ pad_value
                break

    return mask


def padding_attack(oracle: Oracle, ciphertext: bytes, iv: bytes) -> bytes:
    # verify input
    if len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError('ciphertext doesnt have proper padding')

    plaintext = bytes()
    last_block = iv
    for block_loc in range(0, len(ciphertext), AES_BLOCK_SIZE):
        # decrypt current block
        current_block = ciphertext[block_loc:block_loc+AES_BLOCK_SIZE]
        mask = decrypt_block_mask(oracle, current_block)
        plaintext += xor_bytes((last_block, mask))

        # update last block for next iteration
        last_block = current_block

    # remove padding and return
    return pkcs7_unpad(plaintext, AES_BLOCK_SIZE)


def main():
    oracle = Oracle()
    for _ in range(100):
        ciphertext, iv = oracle.encrypt()
        plaintext = padding_attack(oracle, ciphertext, iv)
        assert plaintext in oracle.data

    print('All tests passed successfully')


if __name__ == '__main__':
    main()
