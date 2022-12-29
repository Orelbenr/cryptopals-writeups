from functools import reduce
from typing import Iterator


def power_mod(b, e, m):
    """
    Modular exponentiation.
    Right-to-left binary method (https://en.wikipedia.org/wiki/Modular_exponentiation)
    """
    res = 1
    while e > 0:
        b, e, res = (
            b * b % m,
            e >> 2,
            b * res % m if e % 2 else res
        )

    return res


def extended_gcd(a: int, b: int) -> tuple[int, tuple[int, int]]:
    """
    Extended Euclidean algorithm
    :return: ( 'gcd' - the resulting gcd,
               'coeffs' - Bézout coefficients )
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, (old_s, old_t)


def invmod(a: int, m: int):
    """
    Modular multiplicative inverse
    ax = 1 (mod m)
    :return: integer x such that the product ax is congruent to 1 with respect to the modulus m
    """
    gcd, coeffs = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f'The modular multiplicative inverse of {a} (mod {m}) does not exist.')

    return coeffs[0] % m


def invpow_integer(x, n):
    """
    Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    https://stackoverflow.com/questions/55436001/cube-root-of-a-very-large-number-using-only-math-library
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1


def integer_division_ceil(a: int, b: int) -> int:
    """ Return ceil(a/b) without losing precision of floating points numbers """
    return (a + b - 1) // b


def trial_division(n: int) -> Iterator[int]:
    """
    Basic Integer Factorization Algorithm.
    https://en.wikipedia.org/wiki/Trial_division
    """
    while n % 2 == 0:
        yield 2
        n //= 2

    f = 3
    while f * f <= n:
        if n % f == 0:
            yield f
            n //= f
        else:
            f += 2

    if n != 1:
        yield n


def chinese_remainder(n_list: list[int], a_list: list[int]) -> int:
    """
    Solution of the system:
    x = a1 (mod n1)
    x = a2 (mod n2)
    ...
    x = ak (mod k)

    Such that 0 <= x < N,
    where N = n1 * n2 * ... * nk

    https://en.wikipedia.org/wiki/Chinese_remainder_theorem#Existence_(direct_construction)
    """
    x = 0
    N = reduce(lambda a, b: a * b, n_list)
    for ni, ai in zip(n_list, a_list):
        Ni = N // ni
        _, (Mi, _) = extended_gcd(Ni, ni)
        x += ai*Mi*Ni

    return x % N


if __name__ == '__main__':
    x = chinese_remainder([2, 3, 5, 7, 13], [1, 2, 1, 5, 10])
    print(x)
