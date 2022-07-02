"""
Orel Ben-Reuven
https://cryptopals.com/sets/2/challenges/12

Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key
(for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it.
Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now, is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1) Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.

2) Detect that the function is using ECB. You already know, but do this step anyway.

3) Knowing the block size, craft an input block that is exactly 1 byte short
(for instance, if the block size is 8 bytes, make "AAAAAAA").
Think about what the oracle function is going to put in that last byte position.

4) Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA",
"AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

5) Match the output of the one-byte-short input to one of the entries in your dictionary.
You've now discovered the first byte of unknown-string.

6) Repeat for the next byte.

Congratulations.
This is the first challenge we've given you whose solution will break real crypto.
Lots of people know that when you encrypt something in ECB mode, you can see penguins through it.
Not so many of them can decrypt the contents of those ciphertexts, and now you can.
If our experience is any guideline, this attack will get you code execution in security tests about once a year.
"""

import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from challenge_9 import pkcs7_pad
from challenge_11 import detect_encryption_mode

# globals
AES_BLOCK_SIZE = 16
KEY = get_random_bytes(AES_BLOCK_SIZE)


def encryption_oracle(plaintext: bytes) -> bytes:
    unknown_string = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                      "YnkK")
    plaintext = plaintext + unknown_string
    plaintext = pkcs7_pad(plaintext, AES_BLOCK_SIZE)

    # encrypt with ECB mode
    cipher_obj = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher_obj.encrypt(plaintext)
    return ciphertext


def detect_msg_length(block_size: int) -> int:
    # check how much we can pad before the output length jump
    base_len = len(encryption_oracle(b''))
    for i in range(block_size+1):
        tmp_len = len(encryption_oracle(b'A'*i))
        if tmp_len > base_len:
            # the padding we added indicates the padding of base_len
            return base_len - i + 1


def detect_block_size() -> int:
    """ The block size will match the first gap of cipher output lengths """
    max_block_size = 100
    base_len = len(encryption_oracle(b''))
    # Increment the input length by one at a time,
    # and wait for a jump in output length.
    for i in range(1, max_block_size):
        plaintext = b'A' * i
        new_len = len(encryption_oracle(plaintext))
        if new_len != base_len:
            return new_len - base_len

    raise StopIteration('Max block size exceeded')


def split_to_blocks(stream: bytes, block_size: int) -> list[bytes]:
    if len(stream) % block_size != 0:
        raise ValueError('stream length must divide by block_size!')

    blocks = [stream[i:i + block_size] for i in range(0, len(stream), block_size)]
    return blocks


def detect_single_byte(cipher_block: bytes, ref_block: bytes, block_size: int) -> int:
    # verify inputs
    if len(cipher_block) % block_size != 0:
        raise ValueError('cipher_block length error')
    if (len(ref_block) + 1) % block_size != 0:
        raise ValueError('ref_block length error')

    # look for correct single byte
    for i in range(2 ** 8):
        full_ref_block = ref_block + bytes([i])
        res = encryption_oracle(full_ref_block)
        res = split_to_blocks(res, block_size)[0]

        if res == cipher_block:
            return i

    raise StopIteration('None of the bytes matched')


def decrypt_ecb():
    # detect basic params
    block_size = detect_block_size()
    msg_len = detect_msg_length(block_size)
    mode = detect_encryption_mode(encryption_oracle(b'1' * 50))
    print(f"{mode} detected.")

    # decrypt hidden cipher
    plaintext = b''

    # decrypt each block in a loop
    num_blocks = len(encryption_oracle(b'')) // block_size
    for block_idx in range(num_blocks):
        # decrypt single block
        for i in range(block_size):
            # extract cipher block
            buffer = b'A' * (block_size - 1 - i)
            tmp_cipher = encryption_oracle(buffer)
            cipher_block = split_to_blocks(tmp_cipher, block_size)[block_idx]

            # build history
            last_bytes = plaintext[-(block_size - 1):]
            pad = block_size - 1 - len(last_bytes)
            ref_block = b'A' * pad + last_bytes

            # detect byte
            detected_byte = detect_single_byte(cipher_block, ref_block, block_size)
            plaintext += bytes([detected_byte])

            # check for terminal condition
            if len(plaintext) == msg_len:
                return plaintext


def main():
    plaintext = decrypt_ecb()
    print(plaintext)


if __name__ == '__main__':
    main()
