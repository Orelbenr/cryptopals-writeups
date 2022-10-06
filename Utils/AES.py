
import math
import random
from typing import Literal
from Crypto.Cipher import AES

from Utils.Padding import pkcs7_pad, pkcs7_unpad
from Utils.bytes_logic import xor_bytes


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


def aes_cbc_encrypt(plaintext: bytes, key: bytes, nonce: bytes = bytes(AES.block_size), add_padding=True) -> bytes:
    # pad if needed
    if add_padding:
        plaintext = pkcs7_pad(plaintext, block_size=AES.block_size)

    # verify input
    if len(nonce) != AES.block_size:
        raise ValueError(f"Nonce must be of size {AES.block_size}")
    if len(plaintext) % AES.block_size != 0:
        raise ValueError(f"plaintext length must be a multiply of the block size")

    # create AES ECB mode object
    cipher_obj = AES.new(key, AES.MODE_ECB)

    # loop blocks to generate cipher
    prev_iv = nonce
    cipher = bytes()
    for i in range(0, len(plaintext), AES.block_size):
        # extract block and XOR with last ciphertext block
        extracted_block = plaintext[i:i+AES.block_size]
        extracted_block = xor_bytes((extracted_block, prev_iv))
        encrypted_block = cipher_obj.encrypt(extracted_block)
        cipher += encrypted_block

        # update prev block
        prev_iv = encrypted_block

    return cipher


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, nonce: bytes = bytes(AES.block_size), remove_padding=False) -> bytes:
    # verify input
    if len(nonce) != AES.block_size:
        raise ValueError(f"Nonce must be of size {AES.block_size}")
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError(f"ciphertext must have length multiple of the block size")

    # create AES ECB mode object
    cipher_obj = AES.new(key, AES.MODE_ECB)

    # loop blocks to generate cipher
    prev_iv = nonce
    plaintext = bytes()
    for i in range(0, len(ciphertext), AES.block_size):
        # extract block, decrypt and XOR with last plaintext block
        extracted_block = ciphertext[i:i+AES.block_size]
        plaintext_block = cipher_obj.decrypt(extracted_block)
        plaintext_block = xor_bytes((plaintext_block, prev_iv))
        plaintext += plaintext_block

        # update prev block
        prev_iv = extracted_block

    # remove pad if needed
    if remove_padding:
        plaintext = pkcs7_unpad(plaintext, AES.block_size)

    return plaintext


class AesCtr:
    def __init__(self, key: bytes, nonce: bytes = None, byteorder: Literal["little", "big"] = "little"):
        # verify input
        if byteorder not in ["big", "little"]:
            raise ValueError('byteorder must be "big" or "little"')

        if nonce is None:
            self.nonce = random.randbytes(8)
        elif len(nonce) != AES.block_size // 2:
            raise ValueError(f'nonce length must equal {AES.block_size // 2}!')
        else:
            self.nonce = nonce

        # init vals
        self.key = key
        self.byteorder = byteorder
        self.cipher_obj = AES.new(self.key, AES.MODE_ECB)

    def generate_key_stream(self, input_len: int, counter_init: int = 0) -> bytes:
        key_stream = bytes()
        counter = counter_init
        for _ in range(math.ceil(input_len / AES.block_size)):
            # create and encrypt counter block
            counter_block = self.nonce + counter.to_bytes(AES.block_size // 2, byteorder=self.byteorder)
            key_stream += self.cipher_obj.encrypt(counter_block)

            # update counter
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
