"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/38
"""

import hmac
import json
import secrets
import socket

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

I_GLOBAL = 'Unbreakable@key.com'
P_GLOBAL = 'StrongPassword'


def simplified_srp_handshake(conn: socket) -> bool:
    # generate the password verifier
    salt = secrets.randbits(64)  # Salt for the user
    x = H(salt, P_GLOBAL)  # Private key
    v = pow(g, x, N)  # Password verifier
    del x

    # receive I and A from the client
    data = json.loads(conn.recv(BUFFER_SIZE).decode('utf-8'))
    I, A = data['I'], data['A']

    # SERVER to CLIENT: salt, B = g**b % n, u = 128 bit random number
    b = secrets.randbits(1024)
    u = secrets.randbits(128)
    B = pow(g, b, N)
    conn.sendall(json.dumps({'salt': salt, 'B': B, 'u': u}).encode('utf-8'))

    # calc shared key
    S_s = pow(A * pow(v, u, N), b, N)
    K_s = H(S_s)
    print(f"{S_s = }\n{K_s = }")

    # receive client verification
    client_verification = conn.recv(BUFFER_SIZE)

    # verify client
    res = hmac.digest(key=long_to_bytes(K_s), msg=long_to_bytes(salt), digest='sha256')
    if res == client_verification:
        conn.sendall(b'User authenticated.')
        return True
    else:
        conn.sendall(b'Password is not correct!')
        return False


def simplified_srp_server() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            res = simplified_srp_handshake(conn)
            return res


if __name__ == '__main__':
    authenticated = simplified_srp_server()
    print(f'{authenticated=}')
