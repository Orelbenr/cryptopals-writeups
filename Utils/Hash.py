import struct

from Utils.bytes_logic import circular_left_shit


def SHA1(msg: bytes) -> bytes:
    # Initialize variables
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # message length in bits
    ml = len(msg) * 8

    # Pre-processing:
    # append the bit '1' to the message
    msg += bytes([0x80])

    # append bits '0' to match len of 448 (mod 512)
    pad_len = (448 // 8) - (len(msg) % (512 // 8))
    pad_len = (512 // 8) + pad_len if pad_len < 0 else pad_len
    msg += bytes(pad_len)

    # append ml, the original message length in bits, as a 64-bit big-endian integer.
    msg += ml.to_bytes(64 // 8, byteorder='big')

    # the total length is a multiple of 512 bits.
    assert (len(msg) % 64 == 0)

    # break message into 512-bit chunks
    for chunk_idx in range(0, len(msg), 64):
        chunk = msg[chunk_idx:chunk_idx + 64]

        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = [int.from_bytes(chunk[i:i + 4], 'big') for i in range(0, len(chunk), 4)]

        # extend the sixteen 32-bit words into eighty 32-bit words
        for i in range(16, 80):
            tmp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            tmp_shifted = circular_left_shit(num=tmp, shift=1)
            w.append(tmp_shifted)

        assert (len(w) == 80)

        # Initialize hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (circular_left_shit(num=a, shift=5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = circular_left_shit(num=b, shift=30)
            b = a
            a = temp

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian) as a 160-bit number
    hh = (struct.pack('>I', i) for i in [h0, h1, h2, h3, h4])
    hh = b''.join(hh)
    return hh


if __name__ == '__main__':
    res = SHA1(b"The quick brown fox jumps over the lazy dog")
    print(res.hex() == '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')
