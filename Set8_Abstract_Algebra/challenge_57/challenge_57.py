"""
Orel Ben-Reuven
https://cryptopals.com/sets/8/challenges/57.txt
"""

import math
import random
import hmac

from Utils.Number import trial_division, chinese_remainder


# Diffie-Hellman Consts
p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
q = 236234353446506858198510045061214171961
j = 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570


class BobOracle:
    """
    Alice computes u=g^a, and sends u to Bob.
    Bob computes v=g^b and sends v to Alice.
    The secret shared by Alice and Bob is w = g^(a*b).
    """

    # class consts
    shared_secret_len = math.ceil(math.log2(p) / 8)

    def __init__(self):
        # initiate random private key
        self._b = random.randint(1, q-1)

    @classmethod
    def generate_shared_secret(cls, u: int, b: int) -> bytes:
        shared_secret = pow(u, b, p)
        shared_secret = shared_secret.to_bytes(cls.shared_secret_len, byteorder='big')
        return shared_secret

    def get_response(self, u: int) -> tuple[bytes, bytes]:
        shared_secret = self.generate_shared_secret(u, self._b)
        m = b"crazy flamboyant for the rap enjoyment"
        digest = hmac.digest(key=shared_secret, msg=m, digest='sha256')
        return m, digest


def find_element_of_order(order: int, p: int) -> int:
    """
    return element h of order r.
    h := rand(1, p)^((p-1)/r) mod p
    """
    if (p-1) % order != 0:
        raise ValueError('r must divide p-1')

    while True:
        h = pow(random.randint(1, p-1), (p-1)//order, p)
        if h != 1:
            return h


def brute_force_search_private_key(response, h, r) -> int:
    for i in range(r):
        shared_secret = BobOracle.generate_shared_secret(h, i)
        digest = hmac.digest(key=shared_secret, msg=response[0], digest='sha256')
        if digest == response[1]:
            return i

    raise Exception('should not reach here')


def attack(oracle: BobOracle) -> int:
    # find xi = a (mod ri),  i=1,...,n
    # until r1*...*rn > q
    r_list = []
    x_list = []

    total_size = 1
    factor_gen = trial_division(j)
    while total_size <= q:
        # find next factor of j
        r = next(factor_gen)
        if r in r_list:
            continue

        # update max number counting
        total_size *= r

        # find element h of order r
        h = find_element_of_order(r, p)

        # acquire Bob response
        response = oracle.get_response(h)

        # search for correct private key (mod r)
        a_r = brute_force_search_private_key(response, h, r)

        # store results
        r_list.append(r)
        x_list.append(a_r)

    # use CRT to reconstruct a (Bob private key)
    a = chinese_remainder(r_list, x_list)
    return a


def main():
    bob = BobOracle()
    bob_secret_key = attack(bob)

    print(f'{bob_secret_key=}')
    print(f'{bob._b=}')
    assert bob_secret_key == bob._b


if __name__ == '__main__':
    main()
