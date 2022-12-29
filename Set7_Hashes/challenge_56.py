"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/56

RC4 Single-Byte Biases

RC4 is popular stream cipher notable for its usage in protocols like TLS, WPA, RDP, &c.

It's also susceptible to significant single-byte biases, especially early in the keystream. What does this mean?

Simply: for a given position in the keystream, certain bytes are more (or less) likely to pop up than others.
Given enough encryptions of a given plaintext, an attacker can use these biases to recover the entire plaintext.

Now, search online for "On the Security of RC4 in TLS and WPA". This site is your one-stop shop for RC4 information.

Click through to "RC4 biases" on the right.

These are graphs of each single-byte bias (one per page). Notice in particular the monster spikes on z16, z32, z48, etc.
(Note: these are one-indexed, so z16 = keystream[15].)

How useful are these biases?

Click through to the research paper and scroll down to the simulation results.
(Incidentally, the whole paper is a good read if you have some spare time.)
We start out with clear spikes at 2^26 iterations,
but our chances for recovering each of the first 256 bytes approaches 1 as we get up towards 2^32.

There are two ways to take advantage of these biases. The first method is really simple:
1. Gain exhaustive knowledge of the keystream biases.
2. Encrypt the unknown plaintext 2^30+ times under different keys.
3. Compare the ciphertext biases against the keystream biases.

Doing this requires deep knowledge of the biases for each byte of the keystream.
But it turns out we can do pretty well with just a few useful biases - if we have some control over the plaintext.

How? By using knowledge of a single bias as a peephole into the plaintext.

Decode this secret:
    QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F

And call it a cookie. No peeking!

Now use it to build this encryption oracle:
    RC4(your-request || cookie, random-key)

Use a fresh 128-bit key on every invocation.

Picture this scenario: you want to steal a user's secure cookie. You can spawn arbitrary requests
(from a malicious plugin or somesuch) and monitor network traffic.
(Ok, this is unrealistic - the cookie wouldn't be right at the beginning of the request like that -
this is just an example!)

You can control the position of the cookie by requesting "/", "/A", "/AA", and so on.

Build bias maps for a couple chosen indices (z16 and z32 are good) and decrypt the cookie.
"""

import base64
import random

import numpy as np
import matplotlib.pyplot as plt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ARC4
from tqdm import tqdm

from Utils.Helpers import timeit

# Consts
KEY_SIZE = 128 // 8


class RC4Oracle:
    cookie = base64.b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')

    @classmethod
    def monitor(cls, request: bytes):
        key = get_random_bytes(KEY_SIZE)
        data = request + cls.cookie

        cipher = ARC4.new(key)
        msg = cipher.encrypt(data)
        return msg


def build_bias_maps(r_list: list[int], num_repetitions: int) -> np.ndarray:
    """
    Estimate distribution of RC4 key stream bytes Zr
    :param num_repetitions: number of independent keys for the statistics
    :param r_list: list of r, such that r in (1, 256) r-th byte of key stream output by RC4
    :return: np.ndarray of dists.
    """
    if not all(map(lambda r: 1 <= r <= 256, r_list)):
        raise ValueError('r should be in range 1-256')

    # store distribution of Zr for all r
    hist = np.zeros((len(r_list), 256))

    # eval distribution
    max_r = max(r_list)
    r_list_len = len(r_list)
    for _ in tqdm(range(num_repetitions), miniters=1e5):
        key = random.randbytes(KEY_SIZE)
        cipher = ARC4.new(key)
        key_stream = cipher.encrypt(bytes(max_r))

        for j in range(r_list_len):
            hist[j, key_stream[r_list[j]-1]] += 1

    # normalize dist
    hist = hist / num_repetitions
    return hist


@timeit
def estimate_byte(cipher_seq, p_rk: np.ndarray) -> int:
    """
    Single-byte bias attack
    :param cipher_seq: C(j,r); 1≤j≤S - S independent encryption's of fixed plaintext P at byte r
    :param p_rk: p(r,k) - list of probabilities of the distribution at position r
    :return: estimate for plaintext byte Pr
    """
    # distribution of C(j,r)
    c_dist = np.zeros(256, dtype=np.uint32)
    for c_val in cipher_seq:
        c_dist[c_val] += 1

    # eval mu using MLE (as discussed in the README)
    k_vec = np.arange(256)
    mu_hat = np.argmax([np.sum(c_dist[k_vec ^ mu] * np.log10(p_rk)) for mu in range(256)])
    return mu_hat


def bias_attack(bias_maps: np.ndarray, num_rep: int):
    oracle = RC4Oracle

    cookie_evaluation = []
    # Eval bytes 0-15 using Z16
    for byte_idx in range(16):
        pad_len = 15-byte_idx
        req = b'A' * pad_len

        cipher_seq = (oracle.monitor(req)[15] for _ in range(num_rep))  # generate Cj,16
        byte_estimate = estimate_byte(cipher_seq, bias_maps[0])  # bias_maps of r=16
        cookie_evaluation.append(byte_estimate)

    # Eval bytes 16-30 using Z32
    for byte_idx in range(14):
        pad_len = 15 - byte_idx
        req = b'A' * pad_len

        cipher_seq = (oracle.monitor(req)[31] for _ in range(num_rep))  # generate Cj,32
        byte_estimate = estimate_byte(cipher_seq, bias_maps[1])  # bias_maps of r=32
        cookie_evaluation.append(byte_estimate)

    return bytes(cookie_evaluation)


def main(debug_plot=False):
    # build bias maps
    r_list = [16, 32]

    try:
        hist = np.load('challenge_56_dists.npy')
    except FileNotFoundError:
        hist = build_bias_maps(r_list, num_repetitions=int(2**30))
        np.save('challenge_56_dists.npy', hist)

    # plot distributions
    if debug_plot:
        for idx, r in enumerate(r_list):
            plt.figure()
            plt.plot(hist[idx])
            plt.title(f'Keystream distribution at position {r}')
            plt.xlabel('Byte value [0...255]')
            plt.ylabel('Probability')

        plt.show()

    # run single-byte bias attack
    cookie = bias_attack(hist, num_rep=int(2**24))
    print(f'{cookie=}')


if __name__ == '__main__':
    main()

    # import cProfile
    # cProfile.run('main()')
