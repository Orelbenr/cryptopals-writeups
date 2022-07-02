"""
Orel Ben-Reuven
https://cryptopals.com/sets/2/challenges/10

Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block,
is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier,
making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test),
and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE"
with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
What's the point of even doing this stuff if you aren't going to learn from it?
"""

import base64
import random

from Crypto.Cipher import AES

# globals
AES_BLOCK_SIZE = 16


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])


def aes_cbc_encrypt(plaintext: bytes, key: bytes, nonce: bytes = bytes(AES_BLOCK_SIZE)) -> bytes:
    # verify input
    if len(nonce) != AES_BLOCK_SIZE:
        raise ValueError(f"Nonce must be of size {AES_BLOCK_SIZE}")
    if len(plaintext) % AES_BLOCK_SIZE != 0:
        raise ValueError(f"plaintext must have length multiple of the block size")

    # create AES ECB mode object
    cipher_obj = AES.new(key, AES.MODE_ECB)

    # loop blocks to generate cipher
    prev_iv = nonce
    cipher = bytes()
    for i in range(0, len(plaintext), AES_BLOCK_SIZE):
        # extract block and XOR with last ciphertext block
        extracted_block = plaintext[i:i+AES_BLOCK_SIZE]
        extracted_block = xor_bytes(extracted_block, prev_iv)
        encrypted_block = cipher_obj.encrypt(extracted_block)
        cipher += encrypted_block

        # update prev block
        prev_iv = encrypted_block

    return cipher


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, nonce: bytes = bytes(AES_BLOCK_SIZE)) -> bytes:
    # verify input
    if len(nonce) != AES_BLOCK_SIZE:
        raise ValueError(f"Nonce must be of size {AES_BLOCK_SIZE}")
    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext must have length multiple of the block size")

    # create AES ECB mode object
    cipher_obj = AES.new(key, AES.MODE_ECB)

    # loop blocks to generate cipher
    prev_iv = nonce
    plaintext = bytes()
    for i in range(0, len(ciphertext), AES_BLOCK_SIZE):
        # extract block, decrypt and XOR with last plaintext block
        extracted_block = ciphertext[i:i+AES_BLOCK_SIZE]
        plaintext_block = cipher_obj.decrypt(extracted_block)
        plaintext_block = xor_bytes(plaintext_block, prev_iv)
        plaintext += plaintext_block

        # update prev block
        prev_iv = extracted_block

    return plaintext


def main():
    # load cipher and decode base64 to bytes
    with open('10.txt', 'r') as fh:
        ciphertext = base64.b64decode(fh.read())

    key = b"YELLOW SUBMARINE"
    plaintext = aes_cbc_decrypt(ciphertext=ciphertext, key=key)
    print(f'{plaintext=}')


if __name__ == '__main__':
    main()
