"""
Orel Ben-Reuven
https://cryptopals.com/sets/3/challenges/22

Crack an MT19937 seed
Make sure your MT19937 accepts an integer seed value.
Test it (verify that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:
- Wait a random number of seconds between, I don't know, 40 and 1000.
- Seeds the RNG with the current Unix timestamp
- Waits a random number of seconds again.
- Returns the first 32 bit output of the RNG.

You get the idea. Go get coffee while it runs. Or just simulate the passage of time,
although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.
"""

import time
import random

from challenge_21 import MT19937


def generate_rand() -> tuple[int, int]:
    # sleep a random seconds between 40 and 1000.
    time.sleep(random.randint(40, 1000))
    seed = round(time.time())

    # generate rng
    rng = iter(MT19937(seed=seed))
    time.sleep(random.randint(10, 40))

    # return first 32 bit
    return next(rng), seed


def crack_mt19937_seed(rand_val: int) -> int:
    # initial value
    seed_value = round(time.time())
    while True:
        res = next(iter(MT19937(seed_value)))
        if res == rand_val:
            return seed_value
        seed_value = (seed_value - 1) % (2 ** 32)


def main():
    rand_val, true_seed = generate_rand()
    detected_seed = crack_mt19937_seed(rand_val)
    print(f'{detected_seed=}')
    print(detected_seed == true_seed)


if __name__ == '__main__':
    main()
