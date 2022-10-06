"""
Orel Ben-Reuven
https://cryptopals.com/sets/6/challenges/41

Implement unpadded message recovery oracle

Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring". Here's why.

Imagine a web application, again with the Javascript encryption,
taking RSA-encrypted messages which (again: Javascript) aren't padded before encryption at all.

You can submit an arbitrary RSA blob and the server will return plaintext.
But you can't submit the same message twice: let's say the server keeps hashes of previous messages for some
liveness interval, and that the message has an embedded timestamp:
{
  time: 1356304276,
  social: '555-55-5555',
}
You'd like to capture other people's messages and use the server to decrypt them.
But when you try, the server takes the hash of the ciphertext and uses it to reject the request.
Any bit you flip in the ciphertext irrevocably scrambles the decryption.

This turns out to be trivially breakable:
- Capture the ciphertext C
- Let N and E be the public modulus and exponent respectively
- Let S be a random number > 1 mod N. Doesn't matter what.
- Now:
    C' = ((S**E mod N) C) mod N
- Submit C', which appears totally different from C, to the server, recovering P',
  which appears totally different from P
- Now:
          P'
    P = -----  mod N
          S

Oops!

Implement that attack.

Careful about division in cyclic groups.
Remember: you don't simply divide mod N; you multiply by the multiplicative inverse mod N.
So you'll need a modinv() function.
"""

import random
import time
from hashlib import sha256

from Crypto.Util.number import long_to_bytes

from Utils.PublicKey import RSA
from Utils.Number import invmod


class Server:
    def __init__(self):
        self.rsa_obj = RSA(512)
        self.prev_msg = []
        self.timestamps = []

    def encrypt(self, msg: bytes) -> int:
        return self.rsa_obj.encrypt(msg)

    def decrypt(self, ciphertext: int) -> bytes:
        # check for older decryption
        msg_hash = sha256(long_to_bytes(ciphertext)).digest()
        if msg_hash in self.prev_msg:
            raise PermissionError('The message has already been decrypted.')

        # update history
        self.prev_msg.append(msg_hash)
        self.timestamps.append(time.time())

        # decrypt the message
        plaintext = self.rsa_obj.decrypt(ciphertext)
        return plaintext


def attack(server: Server, ciphertext: int) -> bytes:
    # some consts
    N = server.rsa_obj.n
    e = server.rsa_obj.e

    s = random.randint(2, N - 1)
    s_inv = invmod(s, N)

    # create fake ciphertext
    fake_ciphertext = (pow(s, e, N) * ciphertext) % N

    # decrypt
    p_fake = RSA.bytes_to_integer(server.decrypt(fake_ciphertext))
    p = (s_inv * p_fake) % N
    p = server.rsa_obj.integer_to_bytes(p)

    return p


def main():
    server = Server()

    # encrypt message
    msg = b'Implement unpadded message recovery oracle'
    c = server.encrypt(msg)

    # first decryption
    p = server.decrypt(c)
    print(f'{p=}')

    # second decryption
    try:
        server.decrypt(c)
    except PermissionError:
        print('Second attempt failed successfully :)')

    # attack
    rec_p = attack(server, c)
    print(f'{rec_p=}')


if __name__ == '__main__':
    main()
