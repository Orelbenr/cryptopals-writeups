"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/55

MD4 Collisions

MD4 is a 128-bit cryptographic hash function, meaning it should take a work factor of roughly 2^64 to find collisions.

It turns out we can do much better.

The paper "Cryptanalysis of the Hash Functions MD4 and RIPEMD"
by Wang et al details a cryptanalytic attack that lets us find collisions in 2^8 or less.

Given a message block M, Wang outlines a strategy for finding a sister message block M', differing only in a few bits,
that will collide with it. Just so long as a short set of conditions holds true for M.

What sort of conditions? Simple bitwise equalities within the intermediate hash function state, e.g. a[1][6] = b[0][6].
This should be read as: "the sixth bit (zero-indexed) of a[1] (i.e. the first update to 'a')
should equal the sixth bit of b[0] (i.e. the initial value of 'b')".

It turns out that a lot of these conditions are trivial to enforce.
To see why, take a look at the first (of three) rounds in the MD4 compression function.
In this round, we iterate over each word in the message block sequentially and mix it into the state.
So we can make sure all our first-round conditions hold by doing this:

# calculate the new value for a[1] in the normal fashion
a[1] = (a[0] + f(b[0], c[0], d[0]) + m[0]).lrot(3)

# correct the erroneous bit
a[1] ^= ((a[1][6] ^ b[0][6]) << 6)

# use algebra to correct the first message block
m[0] = a[1].rrot(3) - a[0] - f(b[0], c[0], d[0])

Simply ensuring all the first round conditions puts us well within the range to generate collisions,
but we can do better by correcting some additional conditions in the second round.
This is a bit trickier, as we need to take care not to stomp on any of the first-round conditions.

Once you've adequately massaged M, you can simply generate M' by flipping a few bits and test for a collision.
A collision is not guaranteed as we didn't ensure every condition.
But hopefully we got enough that we can find a suitable (M, M') pair without too much effort.

Implement Wang's attack.
"""

import random
from dataclasses import dataclass
from typing import Literal

from Utils.bytes_logic import lrot, rrot
from Crypto.Hash import MD4


# helper functions
def f(x, y, z): return x & y | ~x & z
def g(x, y, z): return x & y | x & z | y & z
def h(x, y, z): return x ^ y ^ z


def phi1(a, b, c, d, m, s): return lrot(a + f(b, c, d) + m, s)
def phi1_inv(a, b, c, d, next_a, s): return rrot(next_a, s) - a - f(b, c, d)
def phi2(a, b, c, d, m, s): return lrot(a + g(b, c, d) + m + 0x5a827999, s)
def phi3(a, b, c, d, m, s): return lrot(a + h(b, c, d) + m + 0x6ed9eba1, s)


@dataclass
class Constraint:
    type: Literal['eq', 'zero', 'one']
    src_bit: int


def phi1_constrained(a, b, c, d, m, m_idx, s, constraints: list[Constraint]):
    # eval next a
    next_a = phi1(a, b, c, d, m[m_idx], s)

    # loop constraints
    for con in constraints:
        if con.type == 'eq':
            next_a ^= (next_a & (1 << con.src_bit)) ^ (b & (1 << con.src_bit))
        elif con.type == 'zero':
            next_a ^= (next_a & (1 << con.src_bit)) ^ 0
        elif con.type == 'one':
            next_a ^= (next_a & (1 << con.src_bit)) ^ (1 << con.src_bit)
        else:
            raise Exception

    # fix message block
    m[m_idx] = phi1_inv(a, b, c, d, next_a, s)
    return next_a


def generate_weak_message():
    # initial state
    a, b, c, d = h0, h1, h2, h3 = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    # Generate a random one-block message
    m = random.randbytes(64)
    m = [int.from_bytes(m[idx:idx+4], byteorder='little') for idx in range(0, 64, 4)]

    # --- Round 1 conditions ---
    # step 1: a1,7 = b0,7
    constraints = [Constraint(type='eq', src_bit=6)]
    a = phi1_constrained(a, b, c, d, m, 0, 3, constraints)

    # step 2: d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
    constraints = [Constraint(type='zero', src_bit=6),
                   Constraint(type='eq', src_bit=7),
                   Constraint(type='eq', src_bit=10)]
    d = phi1_constrained(d, a, b, c, m, 1, 7, constraints)

    # step 3: c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
    constraints = [Constraint(type='one', src_bit=6),
                   Constraint(type='one', src_bit=7),
                   Constraint(type='zero', src_bit=10),
                   Constraint(type='eq', src_bit=25)]
    c = phi1_constrained(c, d, a, b, m, 2, 11, constraints)

    # step 4: b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
    constraints = [Constraint(type='one', src_bit=6),
                   Constraint(type='zero', src_bit=7),
                   Constraint(type='zero', src_bit=10),
                   Constraint(type='zero', src_bit=25)]
    b = phi1_constrained(b, c, d, a, m, 3, 19, constraints)

    # step 5: a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
    constraints = [Constraint(type='one', src_bit=0),
                   Constraint(type='one', src_bit=10),
                   Constraint(type='zero', src_bit=25),
                   Constraint(type='eq', src_bit=13)]
    a = phi1_constrained(a, b, c, d, m, 4, 3, constraints)

    # step 6: d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
    constraints = [Constraint(type='zero', src_bit=13),
                   Constraint(type='eq', src_bit=18),
                   Constraint(type='eq', src_bit=19),
                   Constraint(type='eq', src_bit=20),
                   Constraint(type='eq', src_bit=21),
                   Constraint(type='one', src_bit=25)]
    d = phi1_constrained(d, a, b, c, m, 5, 7, constraints)

    # step 7: c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
    constraints = [Constraint(type='eq', src_bit=12),
                   Constraint(type='zero', src_bit=13),
                   Constraint(type='eq', src_bit=14),
                   Constraint(type='zero', src_bit=18),
                   Constraint(type='zero', src_bit=19),
                   Constraint(type='one', src_bit=20),
                   Constraint(type='zero', src_bit=21)]
    c = phi1_constrained(c, d, a, b, m, 6, 11, constraints)

    # step 8: b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
    constraints = [Constraint(type='one', src_bit=12),
                   Constraint(type='one', src_bit=13),
                   Constraint(type='zero', src_bit=14),
                   Constraint(type='eq', src_bit=16),
                   Constraint(type='zero', src_bit=18),
                   Constraint(type='zero', src_bit=19),
                   Constraint(type='zero', src_bit=20),
                   Constraint(type='zero', src_bit=21)]
    b = phi1_constrained(b, c, d, a, m, 7, 19, constraints)

    # step 9: a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0, a3,20 = 0, a3,21 = 0,
    # a3,23 = b2,23, a3,22 = 1, a3,26 = b2,26
    constraints = [Constraint(type='one', src_bit=12),
                   Constraint(type='one', src_bit=13),
                   Constraint(type='one', src_bit=14),
                   Constraint(type='zero', src_bit=16),
                   Constraint(type='zero', src_bit=18),
                   Constraint(type='zero', src_bit=19),
                   Constraint(type='zero', src_bit=20),
                   Constraint(type='eq', src_bit=22),
                   Constraint(type='one', src_bit=21),
                   Constraint(type='eq', src_bit=25)]
    a = phi1_constrained(a, b, c, d, m, 8, 3, constraints)

    # step 10: d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0,
    # d3,26 = 1, d3,30 = a3,30
    constraints = [Constraint(type='one', src_bit=12),
                   Constraint(type='one', src_bit=13),
                   Constraint(type='one', src_bit=14),
                   Constraint(type='zero', src_bit=16),
                   Constraint(type='zero', src_bit=19),
                   Constraint(type='one', src_bit=20),
                   Constraint(type='one', src_bit=21),
                   Constraint(type='zero', src_bit=22),
                   Constraint(type='one', src_bit=25),
                   Constraint(type='eq', src_bit=29)]
    d = phi1_constrained(d, a, b, c, m, 9, 7, constraints)

    # step 11: c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
    constraints = [Constraint(type='one', src_bit=16),
                   Constraint(type='zero', src_bit=19),
                   Constraint(type='zero', src_bit=20),
                   Constraint(type='zero', src_bit=21),
                   Constraint(type='zero', src_bit=22),
                   Constraint(type='zero', src_bit=25),
                   Constraint(type='one', src_bit=29),
                   Constraint(type='eq', src_bit=31)]
    c = phi1_constrained(c, d, a, b, m, 10, 11, constraints)

    # step 12: b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
    constraints = [Constraint(type='zero', src_bit=19),
                   Constraint(type='one', src_bit=20),
                   Constraint(type='one', src_bit=21),
                   Constraint(type='eq', src_bit=22),
                   Constraint(type='one', src_bit=25),
                   Constraint(type='zero', src_bit=29),
                   Constraint(type='zero', src_bit=31)]
    b = phi1_constrained(b, c, d, a, m, 11, 19, constraints)

    # step 13: a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
    constraints = [Constraint(type='zero', src_bit=22),
                   Constraint(type='zero', src_bit=25),
                   Constraint(type='eq', src_bit=26),
                   Constraint(type='eq', src_bit=28),
                   Constraint(type='one', src_bit=29),
                   Constraint(type='zero', src_bit=31)]
    a = phi1_constrained(a, b, c, d, m, 12, 3, constraints)

    # step 14: d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
    constraints = [Constraint(type='zero', src_bit=22),
                   Constraint(type='zero', src_bit=25),
                   Constraint(type='one', src_bit=26),
                   Constraint(type='one', src_bit=28),
                   Constraint(type='zero', src_bit=29),
                   Constraint(type='one', src_bit=31)]
    d = phi1_constrained(d, a, b, c, m, 13, 7, constraints)

    # step 15: c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
    constraints = [Constraint(type='eq', src_bit=18),
                   Constraint(type='one', src_bit=22),
                   Constraint(type='one', src_bit=25),
                   Constraint(type='zero', src_bit=26),
                   Constraint(type='zero', src_bit=28),
                   Constraint(type='zero', src_bit=29)]
    c = phi1_constrained(c, d, a, b, m, 14, 11, constraints)

    # step 16: b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
    constraints = [Constraint(type='zero', src_bit=18),
                   Constraint(type='eq', src_bit=25),
                   Constraint(type='one', src_bit=26),
                   Constraint(type='one', src_bit=28),
                   Constraint(type='zero', src_bit=29)]
    b = phi1_constrained(b, c, d, a, m, 15, 19, constraints)





def main():
    generate_weak_message()


if __name__ == '__main__':
    main()
