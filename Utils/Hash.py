import struct

from Utils.bytes_logic import circular_left_shit


def SHA1(msg: bytes, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE,
         h3=0x10325476, h4=0xC3D2E1F0, force_len: int = None) -> bytes:

    # message length in bits
    if force_len is None:
        ml = len(msg) * 8
    else:
        ml = force_len * 8

    # Pre-processing:
    # append the bit '1' to the message
    msg += bytes([0x80])

    # append bits '0' to match len of 448 (mod 512) bits
    pad_len = (448 // 8) - (len(msg) % (512 // 8))
    pad_len = (512 // 8) + pad_len if pad_len < 0 else pad_len
    msg += bytes(pad_len)

    # append ml, the original message length in bits, as a 64-bit big-endian integer.
    msg += ml.to_bytes(64 // 8, byteorder='big')

    # the total length is a multiple of 512 bits (64 bytes)
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


class MD4:
    """
    An implementation of the MD4 hash algorithm.
    Taken from https://gist.github.com/kangtastic/c3349fc4f9d659ee362b12d7d8c639b6
    """

    width = 32
    mask = 0xFFFFFFFF

    @staticmethod
    def process(msg, h=None, force_len=None) -> bytes:
        if h is None:
            h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

        # message length in bits
        if force_len is None:
            ml = len(msg) * 8
        else:
            ml = force_len * 8

        # Pre-processing: Total length is a multiple of 512 bits.
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)

        # Process the message in successive 512-bit chunks.
        chunks = [msg[i: i + 64] for i in range(0, len(msg), 64)]
        for chunk in chunks:
            X, h_tmp = list(struct.unpack("<16I", chunk)), h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h_tmp[i] + MD4.F(h_tmp[j], h_tmp[k], h_tmp[l]) + X[K]
                h_tmp[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h_tmp[i] + MD4.G(h_tmp[j], h_tmp[k], h_tmp[l]) + X[K] + 0x5A827999
                h_tmp[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h_tmp[i] + MD4.H(h_tmp[j], h_tmp[k], h_tmp[l]) + X[K] + 0x6ED9EBA1
                h_tmp[i] = MD4.lrot(hn & MD4.mask, S)

            h = [((v + n) & MD4.mask) for v, n in zip(h, h_tmp)]

        return struct.pack("<4L", *h)

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


if __name__ == '__main__':
    res = SHA1(b"The quick brown fox jumps over the lazy dog")
    print(res.hex() == '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')

    res2 = MD4.process(b"The quick brown fox jumps over the lazy cog")
    print(res2.hex() == 'b86e130ce7028da59e672d56ad0113df')
