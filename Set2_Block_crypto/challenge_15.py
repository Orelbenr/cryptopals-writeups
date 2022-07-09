"""
Orel Ben-Reuven
https://cryptopals.com/sets/2/challenges/15

PKCS#7 padding validation
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string: "ICE ICE BABY\x04\x04\x04\x04" ... has valid padding, and produces the result "ICE ICE BABY".

The string: "ICE ICE BABY\x05\x05\x05\x05" ... does not have valid padding, nor does:
"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby,
make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
"""

# globals
AES_BLOCK_SIZE = 16


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
    raise AssertionError('No padding was found!')


if __name__ == '__main__':
    assert b'ICE ICE BABY' == pkcs7_unpad(b'ICE ICE BABY\x04\x04\x04\x04', AES_BLOCK_SIZE)

    try:
        pkcs7_unpad(b'ICE ICE BABY\x05\x05\x05\x05', AES_BLOCK_SIZE)
    except AssertionError:
        print('No padding was found')
    else:
        assert False

    try:
        pkcs7_unpad(b'ICE ICE BABY\x01\x02\x03\x04', AES_BLOCK_SIZE)
    except AssertionError:
        print('No padding was found')
    else:
        assert False
