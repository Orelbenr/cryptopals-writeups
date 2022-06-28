"""
Orel Ben-Reuven
https://cryptopals.com/sets/1/challenges/8

Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""

AES_BLOCK_SIZE = 16


def score_ecb_mode(cipher: bytes) -> float:
    """ evaluate repetition of blocks """
    blocks = []
    for i in range(0, len(cipher), AES_BLOCK_SIZE):
        blocks.append(cipher[i:i+AES_BLOCK_SIZE])

    # evaluate number of distinct blocks relative to the total number of blocks
    return len(set(blocks)) / len(blocks)


def main():
    # load cypher and decode hex to bytes
    with open('8.txt', 'r') as fh:
        lines = fh.readlines()
        ciphertext_list = list(map(bytes.fromhex, lines))

    min_count = float('inf')
    best_cipher = 0
    for idx, ciphertext in enumerate(ciphertext_list):
        count = score_ecb_mode(ciphertext)
        if count < min_count:
            min_count = count
            best_cipher = idx

    print(f'{best_cipher=}')
    # best_cipher=132


if __name__ == '__main__':
    main()
