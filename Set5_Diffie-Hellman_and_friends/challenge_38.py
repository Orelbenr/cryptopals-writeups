"""
Orel Ben-Reuven
https://cryptopals.com/sets/5/challenges/38

Offline dictionary attack on simplified SRP
S:
    x = SHA256(salt|password)
    v = g**x % n

C->S:
    I, A = g**a % n

S->C:
    salt, B = g**b % n, u = 128 bit random number

C:
    x = SHA256(salt|password)
    S = B**(a + ux) % n
    K = SHA256(S)
S:
    S = (A * v ** u)**b % n
    K = SHA256(S)

C->S:
    Send HMAC-SHA256(K, salt)

S->C:
    Send "OK" if HMAC-SHA256(K, salt) validates

Note that in this protocol, the server's "B" parameter doesn't depend on the password
(it's just a Diffie Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B, u, and salt.

Crack the password from A's HMAC-SHA256(K, salt).
"""

import hmac
import socket
import secrets
import json

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
P_GLOBAL = '54321'


def simplified_srp_client() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # CLIENT to SERVER: Send I, A=g**a % N
        print("\nSend username I and public ephemeral value A to the server")
        a = secrets.randbits(1024)
        A = pow(g, a, N)
        s.sendall(json.dumps({'I': I_GLOBAL, 'A': A}).encode('utf-8'))
        print(f"{I_GLOBAL = }\n{A = }")

        # receive salt, B = g**b % n, u = 128 bit random number
        data = json.loads(s.recv(BUFFER_SIZE).decode('utf-8'))
        salt, B, u = data['salt'], data['B'], data['u']

        # calc shared key
        x = H(salt, P_GLOBAL)
        S_c = pow(B, (a + u*x), N)
        K_c = H(S_c)
        print(f"{S_c = }\n{K_c = }")

        # send verification to server
        client_verification = hmac.digest(key=long_to_bytes(K_c), msg=long_to_bytes(salt), digest='sha256')
        s.sendall(client_verification)

        # receive server response
        verification_response = s.recv(BUFFER_SIZE)
        if verification_response == b'User authenticated.':
            return True
        else:
            return False


if __name__ == '__main__':
    authenticated = simplified_srp_client()
    print(f'{authenticated=}')
