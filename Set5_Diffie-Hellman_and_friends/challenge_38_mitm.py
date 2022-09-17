"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/38
"""

import hmac
import json
import secrets
import socket
import string
from itertools import product
from multiprocessing import Pool
from typing import Callable

from tqdm import tqdm
from Crypto.Util.number import long_to_bytes

from challenge_37 import H

# connection
HOST = "localhost"
PORT = 9999

# Consts
BUFFER_SIZE = 1024

# Server and Client consts
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


def simplified_srp_handshake(conn: socket) -> Callable:
    # generate salt
    salt = secrets.randbits(64)  # Salt for the user

    # receive I and A from the client
    data = json.loads(conn.recv(BUFFER_SIZE).decode('utf-8'))
    I, A = data['I'], data['A']

    # SERVER to CLIENT: salt, B = g**b % n, u = 128 bit random number
    u = secrets.randbits(128)
    B = g
    conn.sendall(json.dumps({'salt': salt, 'B': B, 'u': u}).encode('utf-8'))

    # receive client verification
    client_verification = conn.recv(BUFFER_SIZE)

    def validate_password(password: str) -> bool:
        x = H(salt, password)
        S_c = (A * pow(g, u * x, N)) % N
        K_c = H(S_c)
        calc_verification = hmac.digest(key=long_to_bytes(K_c), msg=long_to_bytes(salt), digest='sha256')
        return calc_verification == client_verification

    return validate_password


def crack_password(validate_func: Callable):
    vals = string.digits
    for pass_len in tqdm(range(1, 20)):
        for attempt in product(vals, repeat=pass_len):
            password = ''.join(attempt)
            if validate_func(password):
                return password

    raise Exception('Password not found')


def simplified_srp_mitm() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            validate_func = simplified_srp_handshake(conn)
            password = crack_password(validate_func)
            return password


if __name__ == '__main__':
    recovered_password = simplified_srp_mitm()
    print(f'{recovered_password=}')
