"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/28

Implement a SHA-1 keyed MAC
Find a SHA-1 implementation in the language you code in.

Don't cheat. It won't work.
Do not use the SHA-1 implementation your language already provides
(for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).

Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
SHA1(key || message)

Verify that you cannot tamper with the message without breaking the MAC you've produced,
and that you can't produce a new MAC without knowing the secret key.
"""

from Utils.Hash import SHA1

from Crypto.Random import get_random_bytes


def sha1_mac(msg: bytes, key: bytes):
    return SHA1(key + msg)


def main():
    key = get_random_bytes(16)
    msg = b"Don't cheat. It won't work."
    digestion = sha1_mac(msg=msg, key=key)
    print(digestion)


if __name__ == '__main__':
    main()
