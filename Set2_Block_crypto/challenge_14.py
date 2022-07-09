"""
Orel Ben-Reuven
https://cryptopals.com/sets/2/challenges/14

Byte-at-a-time ECB decryption (Harder)
Take your oracle function from #12.
Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle?
The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
"""

import base64
import random
from Crypto.Random import get_random_bytes

from Utils.AES import aes_ecb_encrypt

# globals
AES_BLOCK_SIZE = 16


class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.prefix = get_random_bytes(random.randint(1, 100))
        self.unknown_string = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                               "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                               "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                               "YnkK")

    def encrypt(self, plaintext: bytes) -> bytes:
        full_plaintext = self.prefix + plaintext + self.unknown_string
        ciphertext = aes_ecb_encrypt(full_plaintext, key=self.key, add_padding=True)
        return ciphertext


def detect_block_size(oracle: Oracle, max_block_size=100) -> int:
    """ The block size will match the first gap of cipher output lengths """
    base_len = len(oracle.encrypt(b''))
    # Increment the input length by one at a time,
    # and wait for a jump in output length.
    for i in range(1, max_block_size):
        plaintext = b'A' * i
        new_len = len(oracle.encrypt(plaintext))
        if new_len != base_len:
            return new_len - base_len

    raise ValueError('Max block size exceeded')


def detect_msg_length(oracle, block_size: int) -> int:
    # check how much we can pad before the output length jump
    base_len = len(oracle.encrypt(b''))
    for i in range(1, block_size+1):
        tmp_len = len(oracle.encrypt(b'A'*i))
        if tmp_len > base_len:
            # the padding we added indicates the padding of base_len
            return base_len - i


def count_repetitions(cipher: bytes) -> int:
    # split cipher to blocks
    blocks = [cipher[i:i + AES_BLOCK_SIZE] for i in range(0, len(cipher), AES_BLOCK_SIZE)]

    # evaluate number of repeating blocks
    return len(blocks) - len(set(blocks))


def detect_alignment(oracle: Oracle, block_size: int) -> int:
    """
    Evaluate the padding length required to extend the prefix,
    into an integer number of [block_size] lengths.
    """
    base_repetitions = count_repetitions(oracle.encrypt(b''))

    # repeat [num_attempts] to avoid random correct alignment
    num_attempts = 5
    for i in range(num_attempts):
        repetitions = []
        for pad_len in range(block_size):
            stream = b'A' * pad_len + 2 * bytes(range(i, block_size+i))
            num_repetitions = count_repetitions(oracle.encrypt(stream))
            repetitions.append(num_repetitions)

        # if only one padding align, we know it is correct
        rep_max_val = max(repetitions)
        if repetitions.count(rep_max_val) == 1:
            return repetitions.index(rep_max_val)

    raise ValueError('Cipher mode is probably not ECB')


def detect_attacker_index(oracle: Oracle, block_size: int, alignment_pad: int) -> int:
    """
    Detect the starting location of our plaintext in the output ciphertext.
    The function assumes the cipher is ECB-AES, and searches for the output block
    that changes as a result of a change in the input.
    """
    command1 = b'A' * alignment_pad + b'1' * block_size
    response1 = oracle.encrypt(command1)
    command2 = b'A' * alignment_pad + b'2' * block_size
    response2 = oracle.encrypt(command2)

    for i in range(0, len(response1), block_size):
        block1 = response1[i:i+block_size]
        block2 = response2[i:i + block_size]

        if block1 != block2:
            return i

    raise ValueError('detect_attacker_index failed')


class AttackerOracle:
    def __init__(self, oracle: Oracle):
        self.oracle = oracle
        self.block_size = detect_block_size(self.oracle)
        self.alignment_pad = detect_alignment(self.oracle, self.block_size)
        self.attacker_idx = detect_attacker_index(self.oracle, self.block_size, self.alignment_pad)

    def encrypt(self, plaintext):
        ext_plaintext = self.alignment_pad * b'A' + plaintext
        ciphertext = self.oracle.encrypt(ext_plaintext)
        ciphertext = ciphertext[self.attacker_idx:]
        return ciphertext


def detect_single_byte(oracle, ref_block: bytes, padding: bytes, block_size: int) -> int:
    # verify inputs
    if len(ref_block) % block_size != 0:
        raise ValueError('ref_block length error')
    if (len(padding) + 1) % block_size != 0:
        raise ValueError('padding length error')

    # look for correct single byte
    for i in range(2 ** 8):
        guess_block = padding + bytes([i])
        res = oracle.encrypt(guess_block)
        res = res[:block_size]

        if res == ref_block:
            return i

    raise StopIteration('None of the bytes matched')


def decrypt_ecb():
    oracle = Oracle()
    attacker_oracle = AttackerOracle(oracle)

    block_size = attacker_oracle.block_size
    msg_len = detect_msg_length(attacker_oracle, block_size)

    # decrypt hidden cipher
    plaintext = b'A' * (block_size - 1)

    for i in range(msg_len):
        # create reference block
        pad_len = (block_size - i - 1) % block_size
        ref_block = attacker_oracle.encrypt(b'A' * pad_len)
        ref_block_idx = i - (i % block_size)
        ref_block = ref_block[ref_block_idx: ref_block_idx + block_size]

        # detect single byte
        padding = plaintext[-block_size+1:]
        new_byte = detect_single_byte(attacker_oracle, ref_block, padding, block_size)
        plaintext += bytes([new_byte])

    # remove initial padding and return
    return plaintext[block_size-1:]


if __name__ == '__main__':
    decrypted_target = decrypt_ecb()
    print(decrypted_target)
