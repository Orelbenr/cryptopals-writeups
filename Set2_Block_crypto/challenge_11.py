"""
Orel Ben-Reuven
https://cryptopals.com/sets/2/challenges/11

An ECB/CBC detection oracle
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key
--- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext
and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time,
and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time.
You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC,
tells you which one is happening.
"""

import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from challenge_9 import pkcs7_pad

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


def gen_rand_aes_key():
    return get_random_bytes(AES_BLOCK_SIZE)


def encryption_oracle(plaintext: bytes) -> tuple[bytes, str]:
    # generates a random key
    key = gen_rand_aes_key()

    # append 5-10 bytes before and after the plaintext
    pad_before = get_random_bytes(random.randint(5, 10))
    pad_after = get_random_bytes(random.randint(5, 10))
    plaintext = pad_before + plaintext + pad_after
    plaintext = pkcs7_pad(plaintext, AES_BLOCK_SIZE)

    if random.random() < 0.5:
        # encrypt with ECB mode
        cipher_obj = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher_obj.encrypt(plaintext)
        return ciphertext, 'ECB'

    else:
        # encrypt with CBC mode
        nonce = get_random_bytes(AES_BLOCK_SIZE)
        ciphertext = aes_cbc_encrypt(plaintext, key, nonce)
        return ciphertext, 'CBC'


def detect_encryption_mode(cipher: bytes):
    # split cipher to blocks
    blocks = [cipher[i:i + AES_BLOCK_SIZE] for i in range(0, len(cipher), AES_BLOCK_SIZE)]

    # evaluate number of repeating blocks
    repetitions = len(blocks) - len(set(blocks))

    if repetitions > 0:
        return 'ECB'
    else:
        return 'CBC'


def test_prediction():
    plaintext = bytes(AES_BLOCK_SIZE) * 5
    cipher, real_mode = encryption_oracle(plaintext)
    predicted_mode = detect_encryption_mode(cipher)
    return real_mode == predicted_mode


def main():
    for i in range(1000):
        if not test_prediction():
            print('Test Failed!')

    print('Test Passed!')


if __name__ == '__main__':
    main()
