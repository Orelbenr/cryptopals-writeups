"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/50

Hashing with CBC-MAC

Sometimes people try to use CBC-MAC as a hash function.

This is a bad idea. Matt Green explains:
To make a long story short: cryptographic hash functions are public functions (i.e., no secret key)
that have the property of collision-resistance (it's hard to find two messages with the same hash).
MACs are keyed functions that (typically) provide message unforgeability -- a very different property.
Moreover, they guarantee this only when the key is secret.

Let's try a simple exercise.

Hash functions are often used for code verification. This snippet of JavaScript (with newline):
    alert('MZA who was that?');

Hashes to 296b8d7cb78a243dda4d0a61d33bbdd1 under CBC-MAC with a key of "YELLOW SUBMARINE" and a 0 IV.

Forge a valid snippet of JavaScript that alerts "Ayo, the Wu is back!" and hashes to the same value.
Ensure that it runs in a browser.

Extra Credit
Write JavaScript code that downloads your file, checks its CBC-MAC,
and inserts it into the DOM iff it matches the expected hash.
"""
import random

from challenge_49 import CbcMac

from Utils.bytes_logic import xor_bytes
from Utils.AES import aes_cbc_encrypt

AES_BLOCK_SIZE = 16


def forge_msg(new_msg: bytes, original_msg: bytes, key: bytes) -> bytes:
    while True:
        suffix = bytes([random.randint(32, 126) for _ in range(AES_BLOCK_SIZE)])
        tmp_iv = aes_cbc_encrypt(new_msg + suffix, key=key, add_padding=False)[-AES_BLOCK_SIZE:]
        overlap_block = xor_bytes((tmp_iv, original_msg[:AES_BLOCK_SIZE]))
        try:

            overlap_block.decode('ascii')
            break
        except UnicodeDecodeError:
            continue

    final_msg = new_msg + suffix + overlap_block + original_msg[AES_BLOCK_SIZE:]
    return final_msg


def main():
    # original message
    key = b'YELLOW SUBMARINE'
    msg = b"alert('MZA who was that?');\n"
    mac = CbcMac.sign(msg, key=key, iv=bytes(AES_BLOCK_SIZE))
    assert mac.hex() == '296b8d7cb78a243dda4d0a61d33bbdd1'

    # forged mac
    new_msg = b"alert('Ayo, the Wu is back!');" + b'//'
    final_msg = forge_msg(new_msg, msg, key)
    assert CbcMac.verify(final_msg, sig=mac, key=key, iv=bytes(AES_BLOCK_SIZE))

    print(final_msg.decode('ascii'))


if __name__ == '__main__':
    main()
