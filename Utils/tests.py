import unittest
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class AesTests(unittest.TestCase):
    def test_cbc(self):
        from Utils.AES import aes_cbc_encrypt, aes_cbc_decrypt
        for i in range(5000):
            key = get_random_bytes(AES.block_size)
            nonce = get_random_bytes(AES.block_size)

            data = random.randbytes(random.randint(1, 1000))
            my_cipher = aes_cbc_encrypt(data, key, nonce)

            cipher_obj = AES.new(key, AES.MODE_CBC, iv=nonce)
            target_cipher = cipher_obj.encrypt(pad(data, AES.block_size))

            self.assertEqual(my_cipher, target_cipher, 'encryption differ')

            my_decryption = aes_cbc_decrypt(my_cipher, key, nonce, remove_padding=True)
            cipher_obj = AES.new(key, AES.MODE_CBC, iv=nonce)
            target_decryption = unpad(cipher_obj.decrypt(my_cipher), AES.block_size)

            self.assertEqual(my_decryption, data, 'decryption unsuccessful')
            self.assertEqual(my_decryption, target_decryption, 'decryption differ')

    def test_ctr(self):
        from Utils.AES import AesCtr
        for i in range(5000):
            key = get_random_bytes(AES.block_size)
            nonce = get_random_bytes(AES.block_size//2)
            aes_ctr = AesCtr(key=key, nonce=nonce, byteorder='big')

            data = random.randbytes(random.randint(1, 1000))
            my_cipher = aes_ctr.encrypt(data)

            cipher_obj = AES.new(key, AES.MODE_CTR, nonce=nonce)
            target_cipher = cipher_obj.encrypt(data)

            self.assertEqual(my_cipher, target_cipher, 'encryption differ')

            cipher_obj = AES.new(key, AES.MODE_CTR, nonce=nonce)
            my_decryption = aes_ctr.decrypt(my_cipher)
            target_decryption = cipher_obj.decrypt(my_cipher)

            self.assertEqual(my_decryption, data, 'decryption unsuccessful')
            self.assertEqual(my_decryption, target_decryption, 'decryption differ')


if __name__ == '__main__':
    unittest.main()
