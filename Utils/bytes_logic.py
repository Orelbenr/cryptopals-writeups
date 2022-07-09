import sys
from functools import reduce


def xor_bytes(input_bytes: tuple[bytes, ...]) -> bytes:
    """
    Xor together series of bytes of the same length
    :param input_bytes: tuple of arbitrary size with [bytes]
    :return: [bytes] - the resulting xor
    """
    if len(set(map(len, input_bytes))) != 1:
        raise ValueError('All of the bytes sequences must have the same length!')

    int_rep = map(lambda x: int.from_bytes(x, 'big'), input_bytes)
    xor_int = reduce(lambda x, y: x ^ y, int_rep)
    return xor_int.to_bytes(len(input_bytes[0]), 'big')


if __name__ == '__main__':
    res = xor_bytes((bytes([5, 2, 1, 4]), bytes([1, 2, 3, 6])))
    print(res)
