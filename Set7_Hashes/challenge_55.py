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
import struct
from dataclasses import dataclass
from typing import Literal

from Utils.BytesLogic import lrot, rrot
from Utils.Helpers import timeit

from Crypto.Hash import MD4


# helper functions
def f(x, y, z): return x & y | ~x & z
def g(x, y, z): return x & y | x & z | y & z
def h(x, y, z): return x ^ y ^ z


def phi1(a, b, c, d, m, s): return lrot(a + f(b, c, d) + m, s)
def phi2(a, b, c, d, m, s): return lrot(a + g(b, c, d) + m + 0x5a827999, s)
def phi3(a, b, c, d, m, s): return lrot(a + h(b, c, d) + m + 0x6ed9eba1, s)


def phi1_inv(a, b, c, d, next_a, s): return (rrot(next_a, s) - a - f(b, c, d)) & 0xFFFFFFFF
def phi2_inv(a, b, c, d, next_a, s): return (rrot(next_a, s) - a - g(b, c, d) - 0x5a827999) & 0xFFFFFFFF


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
    m[m_idx] = phi1_inv(a, b, c, d, next_a, s) & 0xFFFFFFFF
    return next_a


def generate_weak_message():
    # initial state
    a, b, c, d = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    a_vec, b_vec, c_vec, d_vec = [a], [b], [c], [d]

    # Generate a random one-block message
    m = random.randbytes(64)
    m = list(struct.unpack("<16I", m))

    # --- Round 1 conditions ---
    # step 1: a1,7 = b0,7
    constraints = [Constraint(type='eq', src_bit=6)]
    a = phi1_constrained(a, b, c, d, m, 0, 3, constraints)
    a_vec.append(a)

    # step 2: d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
    constraints = [Constraint(type='zero', src_bit=6),
                   Constraint(type='eq', src_bit=7),
                   Constraint(type='eq', src_bit=10)]
    d = phi1_constrained(d, a, b, c, m, 1, 7, constraints)
    d_vec.append(d)

    # step 3: c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
    constraints = [Constraint(type='one', src_bit=6),
                   Constraint(type='one', src_bit=7),
                   Constraint(type='zero', src_bit=10),
                   Constraint(type='eq', src_bit=25)]
    c = phi1_constrained(c, d, a, b, m, 2, 11, constraints)
    c_vec.append(c)

    # step 4: b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
    constraints = [Constraint(type='one', src_bit=6),
                   Constraint(type='zero', src_bit=7),
                   Constraint(type='zero', src_bit=10),
                   Constraint(type='zero', src_bit=25)]
    b = phi1_constrained(b, c, d, a, m, 3, 19, constraints)
    b_vec.append(b)

    # step 5: a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
    constraints = [Constraint(type='one', src_bit=7),
                   Constraint(type='one', src_bit=10),
                   Constraint(type='zero', src_bit=25),
                   Constraint(type='eq', src_bit=13)]
    a = phi1_constrained(a, b, c, d, m, 4, 3, constraints)
    a_vec.append(a)

    # step 6: d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
    constraints = [Constraint(type='zero', src_bit=13),
                   Constraint(type='eq', src_bit=18),
                   Constraint(type='eq', src_bit=19),
                   Constraint(type='eq', src_bit=20),
                   Constraint(type='eq', src_bit=21),
                   Constraint(type='one', src_bit=25)]
    d = phi1_constrained(d, a, b, c, m, 5, 7, constraints)
    d_vec.append(d)

    # step 7: c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
    constraints = [Constraint(type='eq', src_bit=12),
                   Constraint(type='zero', src_bit=13),
                   Constraint(type='eq', src_bit=14),
                   Constraint(type='zero', src_bit=18),
                   Constraint(type='zero', src_bit=19),
                   Constraint(type='one', src_bit=20),
                   Constraint(type='zero', src_bit=21)]
    c = phi1_constrained(c, d, a, b, m, 6, 11, constraints)
    c_vec.append(c)

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
    b_vec.append(b)

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
    a_vec.append(a)

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
    d_vec.append(d)

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
    c_vec.append(c)

    # step 12: b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
    constraints = [Constraint(type='zero', src_bit=19),
                   Constraint(type='one', src_bit=20),
                   Constraint(type='one', src_bit=21),
                   Constraint(type='eq', src_bit=22),
                   Constraint(type='one', src_bit=25),
                   Constraint(type='zero', src_bit=29),
                   Constraint(type='zero', src_bit=31)]
    b = phi1_constrained(b, c, d, a, m, 11, 19, constraints)
    b_vec.append(b)

    # step 13: a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
    constraints = [Constraint(type='zero', src_bit=22),
                   Constraint(type='zero', src_bit=25),
                   Constraint(type='eq', src_bit=26),
                   Constraint(type='eq', src_bit=28),
                   Constraint(type='one', src_bit=29),
                   Constraint(type='zero', src_bit=31)]
    a = phi1_constrained(a, b, c, d, m, 12, 3, constraints)
    a_vec.append(a)

    # step 14: d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
    constraints = [Constraint(type='zero', src_bit=22),
                   Constraint(type='zero', src_bit=25),
                   Constraint(type='one', src_bit=26),
                   Constraint(type='one', src_bit=28),
                   Constraint(type='zero', src_bit=29),
                   Constraint(type='one', src_bit=31)]
    d = phi1_constrained(d, a, b, c, m, 13, 7, constraints)
    d_vec.append(d)

    # step 15: c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
    constraints = [Constraint(type='eq', src_bit=18),
                   Constraint(type='one', src_bit=22),
                   Constraint(type='one', src_bit=25),
                   Constraint(type='zero', src_bit=26),
                   Constraint(type='zero', src_bit=28),
                   Constraint(type='zero', src_bit=29)]
    c = phi1_constrained(c, d, a, b, m, 14, 11, constraints)
    c_vec.append(c)

    # step 16: b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
    constraints = [Constraint(type='zero', src_bit=18),
                   Constraint(type='eq', src_bit=25),
                   Constraint(type='one', src_bit=26),
                   Constraint(type='one', src_bit=28),
                   Constraint(type='zero', src_bit=29),
                   Constraint(type='eq', src_bit=31)]
    b = phi1_constrained(b, c, d, a, m, 15, 19, constraints)
    b_vec.append(b)

    # --- Round 2 conditions ---
    # a5 constraints
    a5 = phi2(a, b, c, d, m[0], 3)
    a5 ^= (a5 & (1 << 18)) ^ (c & (1 << 18))  # a5,19 = c4,19
    a5 ^= (a5 & (1 << 25)) ^ (1 << 25)  # a5,26 = 1
    a5 ^= (a5 & (1 << 26)) ^ 0  # a5,27 = 0
    a5 ^= (a5 & (1 << 28)) ^ (1 << 28)  # a5,29 = 1
    a5 ^= (a5 & (1 << 31)) ^ (1 << 31)  # a5,32 = 1

    # fix message block
    m[0] = phi2_inv(a, b, c, d, a5, 3)
    a_vec[1] = phi1(a_vec[0], b_vec[0], c_vec[0], d_vec[0], m[0], 3)

    # update message according to the new state
    m[1] = phi1_inv(d_vec[0], a_vec[1], b_vec[0], c_vec[0], d_vec[1], 7)
    m[2] = phi1_inv(c_vec[0], d_vec[1], a_vec[1], b_vec[0], c_vec[1], 11)
    m[3] = phi1_inv(b_vec[0], c_vec[1], d_vec[1], a_vec[1], b_vec[1], 19)
    m[4] = phi1_inv(a_vec[1], b_vec[1], c_vec[1], d_vec[1], a_vec[2], 3)

    # update a
    a = a5
    a_vec.append(a)

    # d5 constraints
    d5 = phi2(d, a, b, c, m[4], 5)
    d5 ^= (d5 & (1 << 18)) ^ (a & (1 << 18))  # d5,19 = a5,19
    d5 ^= (d5 & (1 << 25)) ^ (b & (1 << 25))  # d5,26 = b4,26
    d5 ^= (d5 & (1 << 26)) ^ (b & (1 << 26))  # d5,27 = b4,27
    d5 ^= (d5 & (1 << 28)) ^ (b & (1 << 28))  # d5,29 = b4,29
    d5 ^= (d5 & (1 << 31)) ^ (b & (1 << 31))  # d5,32 = b4,32

    # fix message block
    m[4] = phi2_inv(d, a, b, c, d5, 5)
    a_vec[2] = phi1(a_vec[1], b_vec[1], c_vec[1], d_vec[1], m[4], 3)

    # update message according to the new state
    m[5] = phi1_inv(d_vec[1], a_vec[2], b_vec[1], c_vec[1], d_vec[2], 7)
    m[6] = phi1_inv(c_vec[1], d_vec[2], a_vec[2], b_vec[1], c_vec[2], 11)
    m[7] = phi1_inv(b_vec[1], c_vec[2], d_vec[2], a_vec[2], b_vec[2], 19)
    m[8] = phi1_inv(a_vec[2], b_vec[2], c_vec[2], d_vec[2], a_vec[3], 3)

    # update d
    d = d5
    d_vec.append(d)

    # c5 constraints
    c5 = phi2(c, d, a, b, m[8], 9)
    c5 ^= (c5 & (1 << 25)) ^ (d & (1 << 25))  # c5,26 = d5,26
    c5 ^= (c5 & (1 << 26)) ^ (d & (1 << 26))  # c5,27 = d5,27
    c5 ^= (c5 & (1 << 28)) ^ (d & (1 << 28))  # c5,29 = d5,29
    c5 ^= (c5 & (1 << 29)) ^ (d & (1 << 29))  # c5,30 = d5,30
    c5 ^= (c5 & (1 << 31)) ^ (d & (1 << 31))  # c5,32 = d5,32

    # fix message block
    m[8] = phi2_inv(c, d, a, b, c5, 9)
    a_vec[3] = phi1(a_vec[2], b_vec[2], c_vec[2], d_vec[2], m[8], 3)

    # update message according to the new state
    m[9] = phi1_inv(d_vec[2], a_vec[3], b_vec[2], c_vec[2], d_vec[3], 7)
    m[10] = phi1_inv(c_vec[2], d_vec[3], a_vec[3], b_vec[2], c_vec[3], 11)
    m[11] = phi1_inv(b_vec[2], c_vec[3], d_vec[3], a_vec[3], b_vec[3], 19)
    m[12] = phi1_inv(a_vec[3], b_vec[3], c_vec[3], d_vec[3], a_vec[4], 3)

    # update c
    c = c5
    c_vec.append(c)

    # --- Ending ---
    # pack m to bytes
    m = struct.pack("<16I", *m)
    return m


@timeit
def find_collision():
    while True:
        # generate weak message
        src = generate_weak_message()
        src_unpack = list(struct.unpack("<16I", src))

        # create collision message
        new_msg = src_unpack.copy()
        new_msg[1] = (new_msg[1] + (2 ** 31)) & 0xFFFFFFFF
        new_msg[2] = (new_msg[2] + (2 ** 31) - (2 ** 28)) & 0xFFFFFFFF
        new_msg[12] = (new_msg[12] - (2 ** 16)) & 0xFFFFFFFF
        new_msg = struct.pack("<16I", *new_msg)

        # check for collision
        hash1 = MD4.new(src).digest()
        hash2 = MD4.new(new_msg).digest()

        if hash1 == hash2:
            return src, new_msg, hash1


def main():
    m1, m2, hash_collision = find_collision()
    print(f'{m1.hex()=}')
    print(f'{m2.hex()=}')
    print(f'{hash_collision.hex()=}')


if __name__ == '__main__':
    main()
