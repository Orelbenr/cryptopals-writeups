
# Set 5: Diffie-Hellman and friends

## Table of contents
33. [Challenge 33 - Implement Diffie-Hellman](#challenge-33---implement-diffie-hellman)
34. [Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](#challenge-34---implement-a-mitm-key-fixing-attack-on-diffie-hellman-with-parameter-injection)






## Challenge 33 - Implement Diffie-Hellman

> Challenge: https://cryptopals.com/sets/5/challenges/33

We start with a simple example.

The Diffie-Hellman constants are:
```python
p, g = 37, 5
```

Each user generate a private key:
```python
a = random.randint(1, 37)
b = random.randint(1, 37)
```

And calcualte the public key:
```python
A = (g ** a) % p
B = (g ** b) % p
```

The session keys are then calculated and should be identical:
```python
s1 = (A ** b) % p
s2 = (B ** a) % p
assert s1 == s2
```

Now, we move to *bignums like in the real world*.

The computer is too slow to find the entire value of (g ** a) for example. 
Instead, we need to use a fast algorithm for modular exponentiation.

We use the [Right-to-left binary method](https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method):
```python
def power_mod(b, e, m):
    res = 1
    while e > 0:
        b, e, res = (
            b * b % m,
            e >> 2,
            b * res % m if e % 2 else res
        )
    
    return res
```

And generate the keys:
```python
# bignums example
p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80d'
        'c1cd129024e088a67cc74020bbea63b139b22514a08'
        '798e3404ddef9519b3cd3a431b302b0a6df25f14374'
        'fe1356d6d51c245e485b576625e7ec6f44c42e9a637'
        'ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f241'
        '17c4b1fe649286651ece45b3dc2007cb8a163bf0598'
        'da48361c55d39a69163fa8fd24cf5f83655d23dca3a'
        'd961c62f356208552bb9ed529077096966d670c354e'
        '4abc9804f1746c08ca237327ffffffffffffffff ', 16)

g = 2

# secret
a = random.randint(1, p)
b = random.randint(1, p)

# public keys
A = power_mod(g, a, p)
B = power_mod(g, b, p)

# session key
s1 = power_mod(A, b, p)
s2 = power_mod(B, a, p)
assert s1 == s2
```



## Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

> Challenge: https://cryptopals.com/sets/5/challenges/34

Let's examine the proposed MITM attack:
1. **ALICE -> MIDDLE**: Send "p", "g", "A"
2. **MIDDLE -> BOB**: Send "p", "g", "p"

    After step 2, *BOB* will calculate the session key as:

    $$ s = (A^{b}) \mod p = p^{b} \mod p = 0 $$

3. **BOB -> MIDDLE**: Send "B"
4. **MIDDLE -> ALICE**: Send "p"

    After step 4, *ALICE* will calculate the session key as:

    $$ s = (B^{a}) \mod p = p^{a} \mod p = 0 $$

As it turns out, both parties will agree on the same key, and the MITM will be able to decrypt all the traffic.



We'll use **socket programing** for the server and client as described [here](https://realpython.com/python-sockets/).

We start with the "echo" bot:
```python

```

