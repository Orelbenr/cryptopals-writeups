"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/34
"""

import json
import math
import socket
import socketserver

from Utils.Hash import SHA1
from Utils.AES import aes_cbc_decrypt

# Consts
BUFFER_SIZE = 1024
AES_BLOCK_SIZE = 16


class MitmHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"Caught client {self.client_address} ...")

        # open connection with Bob
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_socket:
            bob_socket.connect(('localhost', 9999))

            # parse Alice open request, modify A to p, and send to Bob
            params = self.request.recv(BUFFER_SIZE)
            params = json.loads(params.decode('utf-8'))
            p = params['p']
            params['A'] = p
            params = json.dumps(params).encode('utf-8')
            bob_socket.sendall(params)

            # listen for Bob response
            bob_socket.recv(BUFFER_SIZE)

            # send modified B to Alice
            modified_resp = json.dumps({'B': p}).encode('utf-8')
            self.request.sendall(modified_resp)

            # pass Alice message to Bob
            alice_msg = self.request.recv(BUFFER_SIZE)
            bob_socket.sendall(alice_msg)

            # pass Bob message to Alice
            bob_msg = bob_socket.recv(BUFFER_SIZE)
            self.request.sendall(bob_msg)

        # eval session key
        s = 0
        max_len = math.ceil(math.log2(p) / 8)
        s_bytes = s.to_bytes(max_len, 'big')
        session_key = SHA1(s_bytes)[:16]
        print(f'{session_key=}')

        # parse and decrypt Bob and Alice Messages
        alice_code = alice_msg[:-AES_BLOCK_SIZE]
        alice_nonce = alice_msg[-AES_BLOCK_SIZE:]
        alice_msg_decrypted = aes_cbc_decrypt(alice_code, session_key, alice_nonce, remove_padding=True)
        print(f'{alice_msg_decrypted=}')

        bob_code = bob_msg[:-AES_BLOCK_SIZE]
        bob_nonce = bob_msg[-AES_BLOCK_SIZE:]
        bob_msg_decrypted = aes_cbc_decrypt(bob_code, session_key, bob_nonce, remove_padding=True)
        print(f'{bob_msg_decrypted=}')


if __name__ == "__main__":
    HOST, PORT = "localhost", 65432
    with socketserver.TCPServer((HOST, PORT), MitmHandler) as server:
        server.serve_forever()
