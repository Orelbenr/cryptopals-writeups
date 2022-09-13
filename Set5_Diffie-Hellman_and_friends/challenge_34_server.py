"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/34
"""

import json
import math
import random
import socketserver

from Utils.Hash import SHA1
from Utils.AES import aes_cbc_decrypt, aes_cbc_encrypt

# Consts
BUFFER_SIZE = 1024
AES_BLOCK_SIZE = 16


class EchoHandler(socketserver.BaseRequestHandler):
    def generate_session(self) -> bytes:
        # parse open request
        data = self.request.recv(BUFFER_SIZE)
        try:
            data = json.loads(data.decode('utf-8'))
            p, g, A = data['p'], data['g'], data['A']
        except (json.decoder.JSONDecodeError, AttributeError, KeyError):
            self.request.sendall(b'Illegal Message!')
            raise ConnectionError('Invalid request')

        # create DH session
        b = random.randint(1, p)
        B = pow(g, b, p)
        s = pow(A, b, p)

        # generate key
        max_len = math.ceil(math.log2(p) / 8)
        s_bytes = s.to_bytes(max_len, 'big')
        session_key = SHA1(s_bytes)[:16]
        print(f'{session_key=}')

        # send response
        resp = json.dumps({'B': B}).encode('utf-8')
        self.request.sendall(resp)

        return session_key

    def handle(self):
        print(f"Serving client {self.client_address} ...")

        # start session
        try:
            session_key = self.generate_session()
        except ConnectionError:
            return

        # parse encrypted message
        data = self.request.recv(BUFFER_SIZE)
        code = data[:-AES_BLOCK_SIZE]
        client_nonce = data[-AES_BLOCK_SIZE:]

        # decrypt message
        try:
            msg = aes_cbc_decrypt(code, session_key, client_nonce, remove_padding=True)
            print(f'{msg=}')
        except ValueError:
            self.request.sendall(b'Wrong session key!')
            return

        # transmit message
        server_nonce = random.randbytes(AES_BLOCK_SIZE)
        encrypted = aes_cbc_encrypt(msg, session_key, server_nonce)
        data = encrypted + server_nonce
        self.request.sendall(data)


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    with socketserver.TCPServer((HOST, PORT), EchoHandler) as server:
        server.serve_forever()
