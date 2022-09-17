"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/36

Implement Secure Remote Password (SRP)

To understand SRP, look at how you generate an AES key from DH;
now, just observe you can do the "opposite" operation and generate a numeric parameter from a hash.
Then:
Replace A and B with C and S (client & server)

C & S:
Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)

S:
1. Generate salt as random integer
2. Generate string xH=SHA256(salt|password)
3. Convert xH to integer x somehow (put 0x on hexdigest)
4. Generate v=g**x % N
5. Save everything but x, xH

C->S:
Send I, A=g**a % N (a la Diffie Hellman)

S->C:
Send salt, B=kv + g**b % N

S, C:
Compute string uH = SHA256(A|B), u = integer of uH

C:
1. Generate string xH=SHA256(salt|password)
2. Convert xH to integer x somehow (put 0x on hexdigest)
3. Generate S = (B - k * g**x)**(a + u * x) % N
4. Generate K = SHA256(S)

S:
1. Generate S = (A * v**u) ** b % N
2. Generate K = SHA256(S)

C->S:
Send HMAC-SHA256(K, salt)

S->C:
Send "OK" if HMAC-SHA256(K, salt) validates

You're going to want to do this at a REPL of some sort; it may take a couple tries.

It doesn't matter how you go from integer to string or string to integer (where things are going in or out of SHA256)
as long as you do it consistently. I tested by using the ASCII decimal representation of integers as input to SHA256,
and by converting the hexdigest to an integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password into the public keys.
The server also takes an extra step to avoid storing an easily crackable password-equivalent.
"""

import hashlib
import hmac
import secrets

from Crypto.Util.number import long_to_bytes


def H(*args) -> int:
    """A one-way hash function."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)


def main():
    """ SRP demo """
    # BOTH: Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    N = """00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
           4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
           c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
           97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
           c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
           c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
           16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
           9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:"""

    N = int("".join(N.split()).replace(":", ""), 16)
    g, k = 2, 3

    I = 'Unbreakable@key.com'
    P = 'StrongPassword'

    # SERVER:
    salt = secrets.randbits(64)  # Salt for the user
    x = H(salt, P)  # Private key
    v = pow(g, x, N)  # Password verifier
    print("\nServer stores (I, s, v) in its password database")
    print(f'{I = }\n{P = }\n{salt = }\n{x = }\n{v = }')

    # CLIENT to SERVER: Send I, A=g**a % N
    print("\nClient sends username I and public ephemeral value A to the server")
    a = secrets.randbits(1024)
    A = pow(g, a, N)
    print(f"{I = }\n{A = }")

    # SERVER to CLIENT: Send salt, B=kv + g**b % N
    print("\nServer sends user's salt s and public ephemeral value B to client")
    b = secrets.randbits(1024)
    B = (k * v + pow(g, b, N)) % N
    print(f"{salt = }\n{B = }")

    # BOTH: Compute string uH = SHA256(A|B), u = integer of uH
    print("\nClient and server calculate the random scrambling parameter")
    u = H(A, B)
    print(f"{u = }")

    # CLIENT:
    print("\nClient computes session key")
    x = H(salt, P)
    S_c = pow(B - k * pow(g, x, N), a + u * x, N)
    K_c = H(S_c)
    print(f"{S_c = }\n{K_c = }")

    # SERVER:
    print("\nServer computes session key")
    S_s = pow(A * pow(v, u, N), b, N)
    K_s = H(S_s)
    print(f"{S_s = }\n{K_s = }")

    assert K_s == K_c

    # SERVER verify CLIENT:
    client_verification = hmac.digest(key=long_to_bytes(K_c), msg=long_to_bytes(salt), digest='sha256')
    if hmac.digest(key=long_to_bytes(K_s), msg=long_to_bytes(salt), digest='sha256') != client_verification:
        print('Client verification failed')


if __name__ == '__main__':
    main()
