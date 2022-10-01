
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


def extended_gcd(a: int, b: int) -> tuple:
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


if __name__ == '__main__':
    # gcd, coeffs = extended_gcd(240, 46)
    # print(gcd, coeffs)
    #
    # inv = invmod(17, 3120)
    # print(inv)

    res = invpow_integer(65, 3)
    print(res)
