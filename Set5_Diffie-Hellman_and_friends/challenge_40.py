"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/40

Implement an E=3 RSA Broadcast attack

Assume you're a Javascript programmer. That is, you're using a naive handrolled RSA to encrypt without padding.

Assume you can be coerced into encrypting the same plaintext three times, under three different public keys.
You can; it's happened.

Then an attacker can trivially decrypt your message, by:
1. Capturing any 3 of the ciphertexts and their corresponding pubkeys
2. Using the CRT to solve for the number represented by the three ciphertexts
   (which are residues mod their respective pubkeys)
3. Taking the cube root of the resulting number

The CRT says you can take any number and represent it as the combination of a series of residues mod a series of moduli.
In the three-residue case, you have:
result =
  (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
  (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
  (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012

where:
 c_0, c_1, c_2 are the three respective residues mod
 n_0, n_1, n_2

 m_s_n (for n in 0, 1, 2) are the product of the moduli
 EXCEPT n_n --- ie, m_s_1 is n_0 * n_2

 N_012 is the product of all three moduli

To decrypt RSA using a simple cube root, leave off the final modulus operation;
just take the raw accumulated result and cube-root it.
"""

from challenge_39 import RSA
from Utils.Number import invmod, invpow_integer


def main():
    # get encryption of m under 3 different keys
    rsa_0 = RSA(key_len=1024)
    rsa_1 = RSA(key_len=1024)
    rsa_2 = RSA(key_len=1024)

    m = b'CRT is FUN!!!'
    c0, n0 = rsa_0.encrypt(m), rsa_0.n
    c1, n1 = rsa_1.encrypt(m), rsa_1.n
    c2, n2 = rsa_2.encrypt(m), rsa_2.n

    # use CRT to determine m ^ 3
    m_s_0, m_s_1, m_s_2 = n1 * n2, n0 * n2, n0 * n1
    m3 = (c0 * m_s_0 * invmod(m_s_0, n0) +
          c1 * m_s_1 * invmod(m_s_1, n1) +
          c2 * m_s_2 * invmod(m_s_2, n2)) % (n0 * n1 * n2)

    m_rec = invpow_integer(m3, 3)

    # convert num to bytes
    m_rec = RSA.num_to_bytes(m_rec)
    print(m)
    print(m_rec)


if __name__ == '__main__':
    main()
