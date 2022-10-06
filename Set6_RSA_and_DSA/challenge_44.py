"""
Orel Ben-Reuven
https://cryptopals.com/sets/6/challenges/44

DSA nonce recovery from repeated nonce

Cryptanalytic MVP award.
This attack (in an elliptic curve group) broke the PS3. It is a great, great attack.

In this file find a collection of DSA-signed messages. (NB: each msg has a trailing space.)

These were signed under the following pubkey:

y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
    13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
    5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
    f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
    f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
    2971c3de5084cce04a2e147821

(using the same domain parameters as the previous exercise)

It should not be hard to find the messages for which we have accidentally used a repeated "k".
Given a pair of such messages, you can discover the "k" we used with the following formula:

         (m1 - m2)
     k = --------- mod q
         (s1 - s2)

9th Grade Math: Study It!
If you want to demystify this, work out that equation from the original DSA equations.

Basic cyclic group math operations want to screw you
Remember all this math is mod q; s2 may be larger than s1,
for instance, which isn't a problem if you're doing the subtraction mod q.
If you're like me, you'll definitely lose an hour to forgetting a paren or a mod q.
(And don't forget that modular inverse function!)

What's my private key? Its SHA-1 (from hex) is:
   ca8f6f7c66fa362d40760d135b763eb8527d3d52
"""

from Set6_RSA_and_DSA.challenge_43 import DSA
from Utils.Number import invmod


def eval_k(msg1: bytes, s1: int, msg2: bytes, s2: int) -> int:
    # domain parameters
    q = DSA.q

    # equation parts
    hm1_minus_hm2 = (DSA.H(msg1) - DSA.H(msg2)) % q
    s1_minus_s2 = (s1 - s2) % q
    s1_minus_s2_inv = invmod(s1_minus_s2, q)

    # calc k
    k = (hm1_minus_hm2 * s1_minus_s2_inv) % q
    return k


def estimate_x_given_k(k: int, msg: bytes, r: int, s: int):
    # domain parameters
    q, H = DSA.q, DSA.H

    r_inv = invmod(r, q)
    x_est = (r_inv * (s * k - H(msg))) % q
    return x_est


def main():
    msg1 = b'Listen for me, you better listen for me now. '
    r1 = 1105520928110492191417703162650245113664610474875
    s1 = 1267396447369736888040262262183731677867615804316

    msg2 = b'Pure black people mon is all I mon know. '
    r2 = 1105520928110492191417703162650245113664610474875
    s2 = 1021643638653719618255840562522049391608552714967

    # eval k
    k = eval_k(msg1=msg1, s1=s1, msg2=msg2, s2=s2)
    print(f'{k=}')

    # eval x
    x = estimate_x_given_k(k=k, msg=msg1, r=r1, s=s1)
    print(f'{x=}')

    # check for matching signatures
    x_fingerprint = DSA.H(hex(x)[2:].encode())
    print(x_fingerprint == int('ca8f6f7c66fa362d40760d135b763eb8527d3d52', 16))


if __name__ == '__main__':
    main()
