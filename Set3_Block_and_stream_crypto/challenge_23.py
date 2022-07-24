"""
Orel Ben-Reuven
https://cryptopals.com/sets/3/challenges/23

Clone an MT19937 RNG from its output
The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state.
By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped,
an element of its internal state is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output
and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order.
There are two kinds of operations in the temper transform each applied twice;
one is an XOR against a right-shifted value,
and the other is an XOR against a left-shifted value AND'd with a magic number.
So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator,
tap it for 624 outputs, untemper each of them to recreate the state of the generator,
and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.

Stop and think for a second.
How would you modify MT19937 to make this attack hard?
What would happen if you subjected each tempered output to a cryptographic hash?
"""

import random

from challenge_21 import MT19937
from Utils.bytes_logic import bitlist_2_int, int_2_bitlist

# Globals
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18


def temper(y: int) -> int:
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)
    return y


def untempter(y: int) -> int:
    """
    Takes an MT19937 output,
    and transforms it back into the corresponding element of the MT19937 state array.
    """
    y = invert_right(y, l)
    y = invert_left_mask(y, t, c)
    y = invert_left_mask(y, s, b)
    y = invert_right(y, u)
    return y


def invert_right(x: int, shift: int) -> int:
    out = int_2_bitlist(x)
    for idx in range(shift, 32):
        out[idx] = out[idx] ^ out[idx - shift]

    return bitlist_2_int(out)


def invert_left_mask(x: int, shift: int, mask: int) -> int:
    mask = int_2_bitlist(mask)
    out = int_2_bitlist(x)
    for idx in range(32-shift-1, -1, -1):
        out[idx] = out[idx] ^ (out[idx+shift] & mask[idx])

    return bitlist_2_int(out)


def clone_mt19937(rng):
    # determine state
    state = []
    for i in range(n):
        state.append(untempter(next(rng)))

    # clone MT19937 using state
    return MT19937().init_from_state(state)


def main():
    seed = random.randint(0, 2**32-1)
    rng = iter(MT19937(seed))
    cloned_rng = iter(clone_mt19937(rng))

    for _ in range(1000000):
        assert next(cloned_rng) == next(rng)


if __name__ == '__main__':
    main()
