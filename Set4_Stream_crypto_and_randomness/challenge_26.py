"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/26

There are people in the world that believe that CTR resists bit flipping attacks
of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode.
Inject an "admin=true" token.
"""

from Crypto.Random import get_random_bytes

from Utils.BytesLogic import xor_bytes
from Utils.AES import AesCtr

# globals
AES_BLOCK_SIZE = 16


class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.ctr_obj = AesCtr(self.key)

    def encode(self, plaintext: bytes) -> bytes:
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

        # quote out ";" and "="
        plaintext = plaintext.replace(b";", b"").replace(b"=", b"")
        plaintext = prefix + plaintext + suffix

        # encrypt and return
        ciphertext = self.ctr_obj.encrypt(plaintext)
        return ciphertext

    def parse(self, ciphertext: bytes) -> bool:
        decrypted = self.ctr_obj.decrypt(ciphertext)
        return b';admin=true;' in decrypted


def detect_prefix_length(oracle: Oracle) -> int:
    c1 = oracle.encode(b'A' * 5)
    c2 = oracle.encode(b'B' * 5)

    for i in range(len(c1)):
        if c1[i] != c2[i]:
            return i

    raise Exception('detect_prefix_length failed')


def generate_attack_sequence(oracle: Oracle, prefix_len: int):
    # target and corresponding target=c1+c2
    target = b';admin=true;'
    c1 = b'F' * len(target)
    c2 = xor_bytes((target, c1))

    # get ciphertext and build modification
    ciphertext = oracle.encode(c1)
    c2_padded = bytes([0] * prefix_len) + c2
    c2_padded += bytes([0] * (len(ciphertext) - len(c2_padded)))
    modified_ciphertext = xor_bytes((ciphertext, c2_padded))
    return modified_ciphertext


def main():
    oracle = Oracle()
    prefix_len = detect_prefix_length(oracle)
    print(f'{prefix_len=}')

    attack_sequence = generate_attack_sequence(oracle, prefix_len)
    is_admin = oracle.parse(attack_sequence)
    print(f'{is_admin=}')


if __name__ == '__main__':
    main()
