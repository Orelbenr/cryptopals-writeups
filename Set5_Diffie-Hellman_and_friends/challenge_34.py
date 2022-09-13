"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/34

Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

Use the code you just worked out to build a protocol and an "echo" bot.
You don't actually have to do the network part of this if you don't want; just simulate that. The protocol is:

A->B
Send "p", "g", "A"
B->A
Send "B"
A->B
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

(In other words, derive an AES key from DH with SHA1, use it in both directions,
and do CBC with random IVs appended or prepended to the message).

Now implement the following MITM attack:

A->M
Send "p", "g", "A"
M->B
Send "p", "g", "p"
B->M
Send "B"
M->A
Send "p"
A->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
M->B
Relay that to B
B->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
M->A
Relay that to A

M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys,
over the wire --- have been swapped out with "p".
Do the DH math on this quickly to see what that does to the predictability of the key.

Decrypt the messages from M's vantage point as they go by.

Note that you don't actually have to inject bogus parameters to make this attack work;
you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack.
But do the parameter injection attack; it's going to come up again.
"""

import json
import math
import random
import socket

from Utils.Hash import SHA1
from Utils.AES import aes_cbc_encrypt, aes_cbc_decrypt

# Consts
BUFFER_SIZE = 1024
AES_BLOCK_SIZE = 16


class Client:
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

    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        self.session_key = self.generate_session()

    def __del__(self):
        self.sock.close()

    def generate_session(self) -> bytes:
        # create DH session
        a = random.randint(1, self.p)
        A = pow(self.g, a, self.p)

        # pack params
        params = {'p': self.p, 'g': self.g, 'A': A}
        params = json.dumps(params).encode('utf-8')
        self.sock.sendall(params)

        # Receive DH session
        data = json.loads(self.sock.recv(BUFFER_SIZE).decode('utf-8'))
        B = data['B']

        # generate key
        s = pow(B, a, self.p)
        max_len = math.ceil(math.log2(self.p) / 8)
        s_bytes = s.to_bytes(max_len, 'big')
        session_key = SHA1(s_bytes)[:16]
        print(f'{session_key=}')
        return session_key

    def send_msg(self, msg: bytes):
        # encrypt the message and send to server
        client_nonce = random.randbytes(AES_BLOCK_SIZE)
        encrypted = aes_cbc_encrypt(msg, self.session_key, client_nonce)
        data = encrypted + client_nonce
        self.sock.sendall(data)

        # receive the server responses
        data = self.sock.recv(BUFFER_SIZE)
        code = data[:-AES_BLOCK_SIZE]
        server_nonce = data[-AES_BLOCK_SIZE:]

        # decrypt message
        echo_msg = aes_cbc_decrypt(code, self.session_key, server_nonce, remove_padding=True)
        print(f'{msg=}')
        print(f'{echo_msg=}')


def main():
    Client("localhost", 65432).send_msg(b'cryptopals')


if __name__ == '__main__':
    main()
