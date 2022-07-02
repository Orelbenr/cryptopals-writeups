
import random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


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