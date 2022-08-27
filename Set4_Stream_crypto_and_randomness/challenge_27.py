"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/27

Recover the key from CBC with IV=Key
Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the sender and the receiver
have to know the key already, and can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in flight
can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string.
Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values).
Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext
(this happens all the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:
AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

Modify the message (you are now the attacker):
C_1, C_2, C_3 -> C_1, 0, C_1

Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
As the attacker, recovering the plaintext from the error, extract the key:
P'_1 XOR P'_3
"""
import string

from Crypto.Random import get_random_bytes

from Utils.bytes_logic import xor_bytes
from Utils.AES import aes_cbc_decrypt, aes_cbc_encrypt

# globals
AES_BLOCK_SIZE = 16


class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.nonce = self.key

    def encode(self, plaintext: bytes) -> bytes:
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

        # quote out ";" and "="
        plaintext = plaintext.replace(b";", b"").replace(b"=", b"")
        plaintext = prefix + plaintext + suffix

        # encrypt and return
        ciphertext = aes_cbc_encrypt(plaintext, key=self.key, nonce=self.nonce, add_padding=True)
        return ciphertext

    def parse(self, ciphertext: bytes) -> bool:
        decrypted = aes_cbc_decrypt(ciphertext, key=self.key, nonce=self.nonce, remove_padding=True)

        # verify each byte of the plaintext for ASCII compliance
        try:
            decoded = decrypted.decode('ascii')
        except UnicodeDecodeError:
            raise ValueError('Ciphertext contain illegal characters!', decrypted)

        return ';admin=true;' in decoded


def detect_key(oracle: Oracle):
    # some ciphertext with at least 3 blocks
    ciphertext = oracle.encode(b'A' * 3 * AES_BLOCK_SIZE)
    ciphertext = bytearray(ciphertext)

    # modify ciphertext: C_1, C_2, C_3 -> C_1, 0, C_1
    ciphertext[AES_BLOCK_SIZE:2*AES_BLOCK_SIZE] = bytes([0]*AES_BLOCK_SIZE)
    ciphertext[2*AES_BLOCK_SIZE:3*AES_BLOCK_SIZE] = ciphertext[:AES_BLOCK_SIZE]

    # send modified ciphertext to oracle
    try:
        oracle.parse(ciphertext)
        raise Exception('detect_key failed')
    except ValueError as e:
        decrypted = e.args[1]

    # parse key: P'_1 XOR P'_3
    key = xor_bytes((decrypted[:AES_BLOCK_SIZE], decrypted[2*AES_BLOCK_SIZE:3*AES_BLOCK_SIZE]))
    return key


def main():
    oracle = Oracle()
    key = detect_key(oracle)

    ciphertext = oracle.encode(b'cryptopals')
    plaintext = aes_cbc_decrypt(ciphertext=ciphertext, key=key, nonce=key, remove_padding=True)
    print(plaintext)


if __name__ == '__main__':
    main()
