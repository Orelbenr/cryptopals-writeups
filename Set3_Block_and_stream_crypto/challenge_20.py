"""
Orel Ben-Reuven
https://cryptopals.com/sets/3/challenges/20

Break fixed-nonce CTR statistically
In this file find a similar set of Base64'd plaintext.
Do with them exactly what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext,
treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR,
but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length
(the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR,
with a key size of the length of the ciphertext you XOR'd.
"""

import base64
from Crypto.Random import get_random_bytes

from Set1_Basics.challenge_6 import decode_single_byte_xor_cypher, transpose_blocks
from challenge_18 import AesCtr
from Utils.BytesLogic import xor_bytes

# globals
AES_BLOCK_SIZE = 16


def break_fixed_nonce_ctr_statistically(streams: list[bytes]) -> bytes:
    # transform into repeating xor cipher
    min_len = min(map(len, streams))
    ciphertext = b''.join([stream[:min_len] for stream in streams])

    # divide and transpose blocks
    block_list = transpose_blocks(ciphertext, min_len)

    # reconstruct key stream
    key_stream = bytes(map(decode_single_byte_xor_cypher, block_list))
    return key_stream


def main():
    # load file and base64 decode
    with open('20.txt', 'r') as fh:
        lines = fh.readlines()
    strings = list(map(base64.b64decode, lines))

    # encrypt all the lines with the same nonce
    key = get_random_bytes(AES_BLOCK_SIZE)
    aes_ctr = AesCtr(key=key, nonce=bytes(8), byteorder='little')
    strings_enc = list(map(aes_ctr.encrypt, strings))

    # detect key stream
    key_stream = break_fixed_nonce_ctr_statistically(strings_enc)

    # decrypt the strings
    for stream in strings_enc:
        stream = stream[:len(key_stream)]
        decrypted_string = xor_bytes((stream, key_stream))
        print(decrypted_string)


if __name__ == '__main__':
    main()
