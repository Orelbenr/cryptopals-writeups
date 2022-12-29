## Challenge 57 - Diffie-Hellman Revisited: Small Subgroup Confinement

> Challenge: https://cryptopals.com/sets/8/challenges/57.txt

### Let's start with a short recap on Diffie-Hellman Protocol:

The protocol consist 2 large primes; $p$ and $q$, such that $q$ divides $(p-1)$. 

Since $q$ divides $(p−1)$, the group $Z^{*}_{p}= \lbrace 1,...,p-1 \rbrace$ has an element $g$ of order $q$.  

This means that $g^{q} = 1 \pmod p$, and the group 

$$ G \coloneqq \lbrace g^{a} : a = 0,..., q − 1 \rbrace $$ 

is a subset of $Z^{*}_{p}$ and has $q$ distict elements; all of them with order $q$.

Bob and Alice pick $a,b \in Z^{*}_{p}$ and compute:

$$ g^{a} , g^{b} \pmod p$$

(Each one of them got one element of $G$ out of $q$ possible outcomes.)

Then, they compute the shared secret:

$$ g^{a \cdot b} \pmod p $$

and they both agree on another element from the group $G$.


### The Attack

We factorize $(p-1)$ to find small divisors; call them $r_{1},r_{2},r_{3},...,r_{n}$.

Each divisor $r_{i}$ form a group with order $r_{i}$ and has corresponding $h_{i} \in Z^{*}_{p}$ such that:

$$ h^{r_{i}}_{i}=1 \pmod p $$

Eve, as the attacker, sends Bob $h_{i}$.

Bob in his turn computes:

$$ K = h^{a}_{i} \pmod p $$

where $a$ is Bob's secret key.

As we noted, $h_{i}$ has order $r_{i}$, and thus $h^{a}_{i}$ has only $r_{i}$ possible values. 

We find the correct value using brute-force search (that's why we picked small $r_{i}$'s), and obtain:

$$ x_{i} = a \mod r_{i} $$

$$ i=1,2,3,...,n $$

Once $(r1 \cdot r2 \dotsm rn) > q$, we can use the *Chinese Remainder Theorem* to reconstruct $a$ (Bob's secret key).

### The Implementation

We build the following Oracle to represent Bob's side of *Diffie-Hellman key agreement*:
```python
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
```

For the factorization part, we use the simple *Trial division Algorithm*:
```python
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
```

Using Bob's response, we use brute-force searching to find the value of `a (mod r)`
```python
def brute_force_search_private_key(response, h, r) -> int:
    for i in range(r):
        shared_secret = BobOracle.generate_shared_secret(h, i)
        digest = hmac.digest(key=shared_secret, msg=response[0], digest='sha256')
        if digest == response[1]:
            return i

    raise Exception('should not reach here')
```

The CRT (Chinese Remainder Theorem) algorithm to retrieve Bob's secret key:
```python
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
```

Finally, the whole attack:
```python
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

        # search for the correct private key (mod r)
        a_r = brute_force_search_private_key(response, h, r)

        # store results
        r_list.append(r)
        x_list.append(a_r)

    # use CRT to reconstruct a (Bob private key)
    a = chinese_remainder(r_list, x_list)
    return a
```

And we can verify it finds the correct key:
```python
bob = BobOracle()
bob_secret_key = attack(bob)

print(f'{bob_secret_key=}')  # bob_secret_key=179569166138842856879519552572563281908
print(f'{bob._b=}')  # bob._b=179569166138842856879519552572563281908
assert bob_secret_key == bob._b
```
