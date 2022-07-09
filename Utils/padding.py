
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
