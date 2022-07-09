"""
Orel Ben-Reuven
https://cryptopals.com/sets/2/challenges/16

CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string: "comment1=cooking%20MCs;userdata=" ...
and append the string: ";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;"
(or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples,
and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it
that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
- Completely scrambles the block the error occurs in
- Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.
Before you implement this attack, answer this question: why does CBC mode have this property?
"""

from Crypto.Random import get_random_bytes

from Utils.AES import aes_cbc_decrypt, aes_cbc_encrypt
from Utils.bytes_logic import xor_bytes

# globals
AES_BLOCK_SIZE = 16


class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.nonce = get_random_bytes(AES_BLOCK_SIZE)

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
        return b';admin=true;' in decrypted


def detect_prefix_length(oracle: Oracle, block_size: int) -> int:
    # detect how many complete block_size fit into the prefix
    full_block_len = 0
    c1 = oracle.encode(b'')
    c2 = oracle.encode(b'A')
    for i in range(0, len(c2), block_size):
        if c1[i:i+block_size] != c2[i:i+block_size]:
            full_block_len = i
            break

    # detect the prefix length in its final block
    block_idx = slice(full_block_len, full_block_len+block_size)
    prev_block = c1[block_idx]
    pad_len = 0
    for i in range(1, block_size+2):
        new_block = oracle.encode(b'A'*i)[block_idx]
        if new_block == prev_block:
            pad_len = i - 1
            break
        prev_block = new_block

    # combine the length in blocks and the padding length
    prefix_len = full_block_len + block_size - pad_len
    return prefix_len


def generate_attack_sequence(oracle: Oracle, prefix_len: int):
    # align our input to new block
    if prefix_len % AES_BLOCK_SIZE != 0:
        pad_len = AES_BLOCK_SIZE - (prefix_len % AES_BLOCK_SIZE)
    else:
        pad_len = 0

    prev_blocks_len = prefix_len + pad_len

    # encode two blocks of repeating 'A'
    known_plaintext = b'B' * pad_len + b'A' * 2 * AES_BLOCK_SIZE
    ciphertext = oracle.encode(known_plaintext)

    # create target block
    target = b';admin=true'
    target = b'A' * (AES_BLOCK_SIZE - len(target)) + target

    # modify c_1 to inject [target] into p_2
    c1_original = ciphertext[prev_blocks_len: prev_blocks_len + AES_BLOCK_SIZE]
    p2_original = b'A' * AES_BLOCK_SIZE
    c1_modified = xor_bytes((c1_original, p2_original, target))

    # build attack sequence
    attack_sequence = ciphertext[:prev_blocks_len]
    attack_sequence += c1_modified
    attack_sequence += ciphertext[prev_blocks_len + AES_BLOCK_SIZE:]

    return attack_sequence


def main():
    oracle = Oracle()
    prefix_len = detect_prefix_length(oracle, AES_BLOCK_SIZE)
    print(f'{prefix_len=}')
    attack_sequence = generate_attack_sequence(oracle, prefix_len=prefix_len)
    is_admin = oracle.parse(attack_sequence)
    print(f'{is_admin=}')


if __name__ == '__main__':
    main()
