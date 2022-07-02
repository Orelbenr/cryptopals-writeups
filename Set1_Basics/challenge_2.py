"""
Orel Ben-Reuven
https://cryptopals.com/sets/1/challenges/2

Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:
1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:
686974207468652062756c6c277320657965

... should produce:
746865206b696420646f6e277420706c6179
"""


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])


if __name__ == '__main__':
    src = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    mask = bytes.fromhex('686974207468652062756c6c277320657965')
    result = xor_bytes(src, mask)
    result_hex = result.hex()
    # result = b"the kid don't play"

    # checking result
    out = '746865206b696420646f6e277420706c6179'
    print(result_hex == out)
