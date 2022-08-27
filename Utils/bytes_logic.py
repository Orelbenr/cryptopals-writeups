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


def bitlist_2_int(bit_list: list[int]) -> int:
    out = 0
    for bit in bit_list:
        out = (out << 1) | bit
    return out


def int_2_bitlist(num: int) -> list[int]:
    return [1 if digit == '1' else 0 for digit in format(num, '032b')]


def circular_left_shit(num: int, shift: int, bit_size: int = 32):
    shifted = (num << shift) & (2**bit_size - 1)
    reminder = num >> (bit_size - shift)
    return shifted | reminder


if __name__ == '__main__':
    res = xor_bytes((bytes([5, 2, 1, 4]), bytes([1, 2, 3, 6])))
    print(res)

    res = circular_left_shit(num=9, shift=1, bit_size=4)
    print(res)
