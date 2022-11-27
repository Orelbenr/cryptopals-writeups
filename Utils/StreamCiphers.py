from Utils.bytes_logic import xor_bytes


class RC4:
    @staticmethod
    def process(stream: bytes, key: bytes) -> bytes:
        key_stream = RC4.generate_stream(len(stream), key)
        output = xor_bytes((stream, key_stream))
        return output

    @staticmethod
    def generate_stream(stream_len: int, key: bytes) -> bytes:
        key_len = len(key)
        if not 1 <= key_len <= 256:
            raise ValueError('key length error')

        # Key-scheduling algorithm
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % key_len]) % 256
            S[i], S[j] = S[j], S[i]

        # Pseudo-random generation algorithm
        i, j = 0, 0
        k = [0 for _ in range(stream_len)]
        for k_idx in range(stream_len):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k[k_idx] = S[(S[i] + S[j]) % 256]

        return bytes(k)


if __name__ == '__main__':
    key = b'Very long and confidential key'
    res = RC4.generate_stream(stream_len=10, key=key)
    print(res)
