import base64
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# globals
AES_BLOCK_SIZE = 16


# challenge 9 tests
def test_padding():
    from challenge_9 import pkcs7_pad
    for i in range(2000):
        block_size = random.randint(4, 30)
        plaintext = random.randbytes(random.randint(1, 30))

        my_padding = pkcs7_pad(plaintext, block_size)
        target_padding = pad(plaintext, block_size)
        assert my_padding == target_padding


def test_unpadding():
    from challenge_9 import pkcs7_pad, pkcs7_unpad
    for i in range(2000):
        block_size = random.randint(4, 30)
        plaintext = random.randbytes(random.randint(1, 30))
        my_padding = pkcs7_pad(plaintext, block_size)

        my_unpadding = pkcs7_unpad(my_padding, block_size)
        target_unpadding = unpad(my_padding, block_size)
        assert my_unpadding == target_unpadding


# challenge 12 tests
def test_challenge_12():
    from challenge_12 import decrypt_ecb
    target = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                              "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                              "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                              "YnkK")
    for _ in range(100):
        res = decrypt_ecb()
        assert res == target


# challenge 14 tests
def test_challenge_14():
    from challenge_14 import decrypt_ecb
    target = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                              "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                              "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                              "YnkK")
    for _ in range(200):
        res = decrypt_ecb()
        assert res == target
