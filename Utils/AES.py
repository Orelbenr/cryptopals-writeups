
from Crypto.Cipher import AES

from Utils.Padding import pkcs7_pad, pkcs7_unpad


def aes_ecb_encrypt(plaintext: bytes, key: bytes, add_padding=True) -> bytes:
    if add_padding:
        plaintext = pkcs7_pad(plaintext, block_size=AES.block_size)
    cipher_obj = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher_obj.encrypt(plaintext)
    return ciphertext


def aes_ecb_decrypt(ciphertext: bytes, key: bytes, remove_padding=False) -> bytes:
    cipher_obj = AES.new(key, AES.MODE_ECB)
    plaintext = cipher_obj.decrypt(ciphertext)
    if remove_padding:
        plaintext = pkcs7_unpad(plaintext, AES.block_size)
    return plaintext
