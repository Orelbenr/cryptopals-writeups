"""
Orel Ben-Reuven
https://cryptopals.com/sets/3/challenges/21

Implement the MT19937 Mersenne Twister RNG
You can get the pseudocode for this from Wikipedia.

If you're writing in Python, Ruby, or (gah) PHP,
your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
"""


class MT19937:
    # The coefficients of MT19937
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    # Create masks
    w_bit_mask = (1 << w) - 1
    lower_mask = (1 << r) - 1
    upper_mask = w_bit_mask & ~lower_mask

    def __init__(self, seed: int = 5489, length: int = None):
        self.MT = self.seed_mt(seed)
        self.index = self.n
        self.length = length

    def init_from_state(self, state):
        self.MT = state
        self.index = self.n
        return self

    def __iter__(self):
        """ Extract a tempered value based on MT[index] """
        idx = 0
        while True:
            # stop condition
            idx += 1
            if self.length is not None and self.length < idx:
                break

            # calling twist() every n numbers
            if self.index == self.n:
                self.twist()

            # calc next value
            y = self.MT[self.index]
            y = y ^ ((y >> self.u) & self.d)
            y = y ^ ((y << self.s) & self.b)
            y = y ^ ((y << self.t) & self.c)
            y = y ^ (y >> self.l)

            self.index += 1
            yield self.w_bit_mask & y

    @classmethod
    def seed_mt(cls, seed: int) -> list[int]:
        """ Initialize the generator from a seed """
        # MT[0] := seed
        MT = [seed]
        for i in range(1, cls.n):
            # MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
            MT.append(cls.w_bit_mask & (cls.f * (MT[i-1] ^ (MT[i-1] >> (cls.w-2))) + i))

        return MT

    def twist(self):
        """ Generate the next n values from the series x_i """
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:  # lowest bit of x is 1
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA

        self.index = 0


def main():
    # rng = iter(MT19937(seed=424512))
    # print(next(rng))
    # print(next(rng))
    # print(next(rng))

    for i in MT19937(seed=129292, length=3):
        print(i)


if __name__ == '__main__':
    main()
