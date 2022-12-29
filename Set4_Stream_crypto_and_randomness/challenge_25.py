"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/25

Break "random access read/write" AES CTR
Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key
(for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext.
Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key
or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.

Food for thought.
A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext;
to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream.
Imagine if you'd relied on that advice to, say, encrypt a disk.
"""

import base64
from Crypto.Random import get_random_bytes

from Utils.BytesLogic import xor_bytes
from Utils.AES import aes_ecb_decrypt, AesCtr

# globals
AES_BLOCK_SIZE = 16


class EditOracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.ctr_obj = AesCtr(self.key)

    def get_cipher(self):
        # load cipher and decode base64 to bytes
        with open('25.txt', 'r') as fh:
            source = base64.b64decode(fh.read())

        key = b"YELLOW SUBMARINE"
        plaintext = aes_ecb_decrypt(ciphertext=source, key=key, remove_padding=True)

        # encrypt under CTR mode
        ciphertext = self.ctr_obj.encrypt(plaintext)
        return ciphertext

    def edit(self, ciphertext: bytes, offset: int, new_text: bytes):
        key_stream = self.ctr_obj.generate_key_stream(len(ciphertext))
        key_stream = key_stream[offset: offset + len(new_text)]

        new_cipher = xor_bytes((key_stream, new_text))
        out = ciphertext[:offset] + new_cipher + ciphertext[offset+len(new_cipher):]
        return out


def main():
    oracle = EditOracle()
    ciphertext = oracle.get_cipher()

    # attack
    recovered_plaintext = oracle.edit(ciphertext=ciphertext, offset=0, new_text=ciphertext)
    print(recovered_plaintext)


if __name__ == '__main__':
    main()
