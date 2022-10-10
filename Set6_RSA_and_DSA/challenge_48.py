"""
Orel Ben-Reuven
https://cryptopals.com/sets/6/challenges/48

Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

Cryptanalytic MVP award
This is an extraordinarily useful attack.
PKCS#1v15 padding, despite being totally insecure, is the default padding used by RSA implementations.
The OAEP standard that replaces it is not widely implemented. This attack routinely breaks SSL/TLS.

This is a continuation of challenge #47; it implements the complete BB'98 attack.

Set yourself up the way you did in #47, but this time generate a 768 bit modulus.

To make the attack work with a realistic RSA keypair, you need to reproduce step 2b from the paper,
and your implementation of Step 3 needs to handle multiple ranges.

The full Bleichenbacher attack works basically like this:
- Starting from the smallest 's' that could possibly produce a plaintext bigger than 2B,
  iteratively search for an 's' that produces a conformant plaintext.
- For our known 's1' and 'n', solve m1=m0s1-rn (again: just a definition of modular multiplication) for 'r',
  the number of times we've wrapped the modulus.
- 'm0' and 'm1' are unknowns, but we know both are conformant PKCS#1v1.5 plaintexts, and so are between [2B,3B].
- We substitute the known bounds for both, leaving only 'r' free, and solve for a range of possible 'r' values.
  This range should be small!
- Solve m1=m0s1-rn again but this time for 'm0', plugging in each value of 'r' we generated in the last step.
  This gives us new intervals to work with. Rule out any interval that is outside 2B,3B.
- Repeat the process for successively higher values of 's'.
  Eventually, this process will get us down to just one interval, whereupon we're back to exercise #47.

What happens when we get down to one interval is, we stop blindly incrementing 's';
instead, we start rapidly growing 'r' and backing it out to 's' values
by solving m1=m0s1-rn for 's' instead of 'r' or 'm0'.
So much algebra! Make your teenage son do it for you! *Note: does not work well in practice*
"""

from challenge_47 import RSA_PKCS1_Type2_Oracle
from Utils.Number import invmod, integer_division_ceil


def bleichenbacher98_attack(oracle: RSA_PKCS1_Type2_Oracle, c: int):
    # Set consts
    e, n = oracle.e, oracle.n
    B = 2 ** (8 * (oracle.k-2))

    # Initialize variables
    i = 1
    M_prev = [(2*B, 3*B - 1)]
    s_prev = None

    # Step 1: Blinding.
    # (In our case, c in already PKCS conforming)
    s0 = 1
    c0 = (c * pow(s0, e, n)) % n

    while True:
        print(f'Iteration number {i} ...')

        # Step 2: Searching for PKCS conforming messages.
        # Step 2.a: find the smallest positive integer s1 >= n/3B
        if i == 1:
            s = integer_division_ceil(n, (3*B))
            while not oracle.validate_msg((c0 * pow(s, e, n)) % n):
                s += 1

        # Step 2.b: Searching with more than one interval left.
        elif len(M_prev) > 1:
            s = s_prev + 1
            while not oracle.validate_msg((c0 * pow(s, e, n)) % n):
                s += 1

        # Step 2.c: Searching with one interval left.
        else:
            a, b = M_prev[0]
            r = integer_division_ceil(2 * (b * s_prev - 2 * B), n)
            s = integer_division_ceil((2 * B + r * n), b)

            while True:
                if oracle.validate_msg((c0 * pow(s, e, n)) % n):
                    break

                if s < (3 * B + r * n) // a:
                    s += 1

                else:
                    r += 1
                    s = integer_division_ceil((2 * B + r * n), b)

        # verify step 2 result
        assert oracle.validate_msg((c0 * pow(s, e, n)) % n)

        # Step 3: Narrowing the set of solutions.
        M_tmp = []
        for a, b in M_prev:
            r_up = (b*s - 2*B) // n
            r_dwn = integer_division_ceil((a*s - 3*B + 1), n)

            for r in range(r_dwn, r_up + 1):
                dwn = max(a, integer_division_ceil((2*B + r*n), s))
                up = min(b, (3*B - 1 + r*n) // s)
                M_tmp.append((dwn, up))

        if len(M_tmp) > 1:
            M = calc_set_union(M_tmp)
        else:
            M = M_tmp

        # Step 4: Computing the solution.
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = (M[0][0] * invmod(s0, n)) % n
            return m

        # Update prev variables
        s_prev = s
        M_prev = M
        i += 1


def calc_set_union(interval_set: list) -> list:
    """
    Calc the union of given intervals
    :param interval_set: list of intervals of the form (start, end)
    :return: list of intervals corresponding to the union
    """
    interval_set.sort(key=lambda interval: interval[0])
    y = [interval_set[0]]
    for x in interval_set[1:]:
        if y[-1][1] < x[0]:
            y.append(x)
        else:
            y[-1] = y[-1][0],  max(y[-1][1], x[1])

    return y


def main():
    oracle = RSA_PKCS1_Type2_Oracle(key_len=768)
    msg = b'kick it, CC'

    cipher = oracle.encrypt(msg)
    print(f'{cipher=}')

    assert oracle.validate_msg(cipher)
    assert not oracle.validate_msg(cipher + 1)

    decryption = bleichenbacher98_attack(oracle, cipher)
    decryption = oracle.integer_to_bytes_padded(decryption)
    decryption = oracle.pkcs_unpadding(decryption)
    assert decryption == msg
    print(f'{decryption=}')


if __name__ == '__main__':
    main()
