import random


# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]


def miller_rabin_test(n: int, iterations: int) -> bool:
    """
    Input #1: n > 3, an odd integer to be tested for primality
    Input #2: k, the number of rounds of testing to perform
    Output: False - “composite” if n is found to be composite,
            True - “probably prime” otherwise
    """

    # write n as 2s·d + 1 with d odd (by factoring out powers of 2 from n − 1)
    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert (2 ** s * d == n - 1)

    # WitnessLoop: repeat k times
    for _ in range(iterations):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == (n - 1):
            # a^{d} = 1 mod {n}
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                # a^{2^{r} * d} = -1 mod {n}
                continue
        return False
    return True


def probable_prime_test(candidate: int) -> bool:
    """
     Output: False - “composite” if candidate is found to be composite,
             True - “probably prime” otherwise
    """
    # First, check trial division by the smallest primes
    if candidate in first_primes_list:
        return True
    for divisor in first_primes_list:
        if candidate % divisor == 0:
            return False

    # These are the number of Miller-Rabin iterations s.t. p(k, t) < 1E-30,
    # with p(k, t) being the probability that a randomly chosen k-bit number
    # is composite but still survives t MR iterations.
    mr_ranges = ((220, 30), (280, 20), (390, 15), (512, 10),
                 (620, 7), (740, 6), (890, 5), (1200, 4),
                 (1700, 3), (3700, 2))

    bit_size = candidate.bit_length()
    try:
        mr_iterations = list(filter(lambda x: bit_size < x[0],
                                    mr_ranges))[0][1]
    except IndexError:
        mr_iterations = 1

    # perform miller rabin test
    return miller_rabin_test(candidate, mr_iterations)


def generate_probable_prime(num_bits):
    result = False
    while not result:
        candidate = random.randrange(2 ** (num_bits - 1) + 1, 2 ** num_bits - 1)
        result = probable_prime_test(candidate)
    return candidate


if __name__ == '__main__':
    pass
