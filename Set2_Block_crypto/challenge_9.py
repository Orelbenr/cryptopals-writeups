"""
Orel Ben-Reuven
https://cryptopals.com/sets/2/challenges/9

Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext.
But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding,
creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.
For instance, "YELLOW SUBMARINE" ... padded to 20 bytes would be: "YELLOW SUBMARINE\x04\x04\x04\x04"
"""


def pkcs7_pad(stream: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(stream) % block_size)
    return stream + bytes([pad_len] * pad_len)


def pkcs7_unpad(stream: bytes, block_size: int) -> bytes:
    if len(stream) % block_size != 0:
        raise ValueError('steam length must be a multiply of block_size')

    for i in range(block_size, 0, -1):
        guessed_padding = stream[-i:]
        # check if the guess is valid
        padding_vals = set(guessed_padding)
        if len(padding_vals) == 1 and padding_vals.pop() == i:
            return stream[:-i]

    # no padding was found
    raise ValueError('No padding was found!')


if __name__ == '__main__':
    src = b"YELLOW SUBMARINE"
    target = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    result = pkcs7_pad(src, 20)
    print(result == target)
