
# Set 5: Diffie-Hellman and friends

## Table of contents
33. [Challenge 33 - Implement Diffie-Hellman](#challenge-33---implement-diffie-hellman)
34. [Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](#challenge-34---implement-a-mitm-key-fixing-attack-on-diffie-hellman-with-parameter-injection)
35. [Challenge 35 - Implement DH with negotiated groups, and break with malicious "g" parameters](#challenge-35---implement-dh-with-negotiated-groups-and-break-with-malicious-g-parameters)
36. [Challenge 36 - Implement Secure Remote Password (SRP)](#challenge-36---implement-secure-remote-password-srp)
37. [Challenge 37 - Break SRP with a zero key](#challenge-37---break-srp-with-a-zero-key)
38. [Challenge 38 - Offline dictionary attack on simplified SRP](#challenge-38---offline-dictionary-attack-on-simplified-srp)
39. [Challenge 39 - Implement RSA](#challenge-39---implement-rsa)





## Challenge 33 - Implement Diffie-Hellman

> Challenge: https://cryptopals.com/sets/5/challenges/33

We start with a simple example.

The Diffie-Hellman constants are:
```python
p, g = 37, 5
```

Each user generate a private key:
```python
a = random.randint(1, 37)
b = random.randint(1, 37)
```

And calcualte the public key:
```python
A = (g ** a) % p
B = (g ** b) % p
```

The session keys are then calculated and should be identical:
```python
s1 = (A ** b) % p
s2 = (B ** a) % p
assert s1 == s2
```

Now, we move to *bignums like in the real world*.

The computer is too slow to find the entire value of (g ** a) for example. 
Instead, we need to use a fast algorithm for modular exponentiation.

We use the [Right-to-left binary method](https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method):
```python
def power_mod(b, e, m):
    res = 1
    while e > 0:
        b, e, res = (
            b * b % m,
            e >> 2,
            b * res % m if e % 2 else res
        )
    
    return res
```

And generate the keys:
```python
# bignums example
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

# secret
a = random.randint(1, p)
b = random.randint(1, p)

# public keys
A = power_mod(g, a, p)
B = power_mod(g, b, p)

# session key
s1 = power_mod(A, b, p)
s2 = power_mod(B, a, p)
assert s1 == s2
```


## Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

> Challenge: https://cryptopals.com/sets/5/challenges/34

Let's examine the proposed MITM attack:
1. **ALICE -> MIDDLE**: Send "p", "g", "A"
2. **MIDDLE -> BOB**: Send "p", "g", "p"

    After step 2, *BOB* will calculate the session key as:

    $$ s = (A^{b}) \mod p = p^{b} \mod p = 0 $$

3. **BOB -> MIDDLE**: Send "B"
4. **MIDDLE -> ALICE**: Send "p"

    After step 4, *ALICE* will calculate the session key as:

    $$ s = (B^{a}) \mod p = p^{a} \mod p = 0 $$

As it turns out, both parties will agree on the same key, and the MITM will be able to decrypt all the traffic.

We'll use **socket programing** for the server and client as described [here](https://realpython.com/python-sockets/).

We start with the "echo" bot. 
The server manage DH handshake for new connections, then continue to "echo" the message:
```python
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
```

Next, we implement the client.

The client generate DH session when created, and procceed to send secure messages to the server.
```python
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
```

Lastly, we implement the MITM which modify the traffic as described:
```python
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
```

When we run all the mentioned parties, we get:

Client prints:
```python
session_key=b'\xd7i\x93\x08\xc3\x8c\xd0N\xebs%w\xa8-1\xd0'
msg=b'cryptopals'
echo_msg=b'cryptopals'
```

Server prints:
```python
Serving client ('127.0.0.1', 49260) ...
session_key=b'\xd7i\x93\x08\xc3\x8c\xd0N\xebs%w\xa8-1\xd0'
msg=b'cryptopals'
```

MITM prints:
```python
Caught client ('127.0.0.1', 49259) ...
session_key=b'\xd7i\x93\x08\xc3\x8c\xd0N\xebs%w\xa8-1\xd0'
alice_msg_decrypted=b'cryptopals'
bob_msg_decrypted=b'cryptopals'
```

We can see that all the parties agree on the same session key.

Moreover, the MITM is able to decrypt all the traffic.



## Challenge 35 - Implement DH with negotiated groups, and break with malicious "g" parameters

> Challenge: https://cryptopals.com/sets/5/challenges/35

Let's examine the DH session with each of the possible malicious "g" parameters.

In case `g = 1`:

$$ A = g ^ {a} \mod p = 1 ^ {a} \mod p = 1 $$

$$ B = g ^ {b} \mod p = 1 ^ {b} \mod p = 1 $$

$$ s = A ^ {b} \mod p = B ^ {a} \mod p = 1 $$

In case `g = p`:

$$ A = g ^ {a} \mod p = p ^ {a} \mod p = 0 $$

$$ B = g ^ {b} \mod p = p ^ {b} \mod p = 0 $$

$$ s = A ^ {b} \mod p = B ^ {a} \mod p = 0 $$

In case `g = p - 1`:

$$ A = g ^ {a} \mod p = (p-1) ^ {a} \mod p = (-1) ^ {a} \mod p $$

$$ B = g ^ {b} \mod p = (p-1) ^ {b} \mod p = (-1) ^ {b} \mod p $$

$$ s = A ^ {b} \mod p = B ^ {a} \mod p = (-1) ^ {a \cdot b} \mod p $$

$$ s = 1 / p-1 $$

Validate with real key exchange:
```python
# possible g and s
g_list = [1, p, p-1]
res = [(1,), (0,), (1, p-1)]

# validate match
for idx, g in enumerate(g_list):
    # secret
    a = random.randint(1, p)
    b = random.randint(1, p)

    # public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    # session key
    s1 = pow(A, b, p)
    s2 = pow(B, a, p)
    assert reduce(lambda x, y: x or y, [s1 == s2 == res[idx][i] for i in range(len(res[idx]))])
```



## Challenge 36 - Implement Secure Remote Password (SRP)

> Challenge: https://cryptopals.com/sets/5/challenges/36

In SRP authentication, one party (the "client" or "user") demonstrates to another party (the "server") that they know the password, without sending the password itself nor any other information from which the password can be derived. The password never leaves the client and is unknown to the server. (https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)

The basic demo implementation:
```python
""" SRP demo """
# BOTH: Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
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

I = 'Unbreakable@key.com'
P = 'StrongPassword'

# SERVER:
salt = secrets.randbits(64)  # Salt for the user
x = H(salt, P)  # Private key
v = pow(g, x, N)  # Password verifier
print("\nServer stores (I, s, v) in its password database")
print(f'{I = }\n{P = }\n{salt = }\n{x = }\n{v = }')

# CLIENT to SERVER: Send I, A=g**a % N
print("\nClient sends username I and public ephemeral value A to the server")
a = secrets.randbits(1024)
A = pow(g, a, N)
print(f"{I = }\n{A = }")

# SERVER to CLIENT: Send salt, B=kv + g**b % N
print("\nServer sends user's salt s and public ephemeral value B to client")
b = secrets.randbits(1024)
B = (k * v + pow(g, b, N)) % N
print(f"{salt = }\n{B = }")

# BOTH: Compute string uH = SHA256(A|B), u = integer of uH
print("\nClient and server calculate the random scrambling parameter")
u = H(A, B)
print(f"{u = }")

# CLIENT:
print("\nClient computes session key")
x = H(salt, P)
S_c = pow(B - k * pow(g, x, N), a + u * x, N)
K_c = H(S_c)
print(f"{S_c = }\n{K_c = }")

# SERVER:
print("\nServer computes session key")
S_s = pow(A * pow(v, u, N), b, N)
K_s = H(S_s)
print(f"{S_s = }\n{K_s = }")

assert K_s == K_c

# SERVER verify CLIENT:
client_verification = hmac.digest(key=long_to_bytes(K_c), msg=long_to_bytes(salt), digest='sha256')
if hmac.digest(key=long_to_bytes(K_s), msg=long_to_bytes(salt), digest='sha256') != client_verification:
    print('Client verification failed')
```



## Challenge 37 - Break SRP with a zero key

> Challenge: https://cryptopals.com/sets/5/challenges/37

We create the SRP server like we did in challenge 34:
```python
class SRPHandler(socketserver.BaseRequestHandler):
    def srp_handshake(self) -> bool:
        # generate the password verifier
        salt = secrets.randbits(64)  # Salt for the user
        x = H(salt, P_GLOBAL)  # Private key
        v = pow(g, x, N)  # Password verifier
        del x

        # receive I and A from the client
        try:
            data = json.loads(self.request.recv(BUFFER_SIZE).decode('utf-8'))
            I, A = data['I'], data['A']
        except (json.decoder.JSONDecodeError, AttributeError, KeyError):
            self.request.sendall(b'Illegal Message!')
            raise ConnectionError('Invalid request')

        # verify I in server list
        if I != I_GLOBAL:
            raise ConnectionError('Wrong I!')

        # SERVER to CLIENT: Send salt, B=kv + g**b % N
        print("\nSends user's salt s and public ephemeral value B to client")
        b = secrets.randbits(1024)
        B = (k * v + pow(g, b, N)) % N
        self.request.sendall(json.dumps({'salt': salt, 'B': B}).encode('utf-8'))
        print(f"{salt = }\n{B = }")

        # BOTH: Compute string uH = SHA256(A|B), u = integer of uH
        print("\nClient and server calculate the random scrambling parameter")
        u = H(A, B)
        print(f"{u = }")

        # SERVER:
        print("\nServer computes session key")
        S_s = pow(A * pow(v, u, N), b, N)
        K_s = H(S_s)
        print(f"{S_s = }\n{K_s = }")

        # receive client verification
        client_verification = self.request.recv(BUFFER_SIZE)

        # verify client
        res = hmac.digest(key=long_to_bytes(K_s), msg=long_to_bytes(salt), digest='sha256')
        if res == client_verification:
            return True
        else:
            return False

    def handle(self):
        print(f"Serving client {self.client_address} ...")

        # start session
        try:
            user_valid = self.srp_handshake()
        except ConnectionError:
            return

        if user_valid:
            self.request.sendall(b'User authenticated.')
            print('User authenticated.')
        else:
            self.request.sendall(b'Password is not correct!')
            print('Password is not correct!')
```

Now, if the client send $0$ as its $A$ value, the server will calcualte $S$ as:

$$ S = (A \cdot v^{u} \mod N) ^ {b} \mod N =  (0 \cdot v^{u} \mod N) ^ {b} \mod N = 0 $$

Let's see it in action:
```python
def attack_1() -> bool:
    """ Log in without password using 0 as the A value """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # CLIENT to SERVER: Send I, A=g**a % N
        print("\nSend username I and public ephemeral value A to the server")
        A = 0
        s.sendall(json.dumps({'I': I, 'A': A}).encode('utf-8'))
        print(f"{I = }\n{A = }")

        # Receive salt and B from server
        data = json.loads(s.recv(BUFFER_SIZE).decode('utf-8'))
        salt, B = data['salt'], data['B']

        # BOTH: Compute string uH = SHA256(A|B), u = integer of uH
        print("\nClient and server calculate the random scrambling parameter")
        u = H(A, B)
        print(f"{u = }")

        # CLIENT:
        print("\nClient computes session key")
        S_c = 0
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
```

The server output:
```python
# Serving client ('127.0.0.1', 63901) ...

# Sends user's salt s and public ephemeral value B to client
# salt = 16466168904433963395
# B = 8530424648836581302040321632065848592185366523581751834105547833024276795266985154373679779950984497456033634982335116958905424560021615828086942500896619007297242790600291547633275714006201815146322396208843878496567715031642210407126221279879837496519104628490080006526263187792592954

# Client and server calculate the random scrambling parameter
# u = 101175302053737051081529405308915063173392309664199002128228189853346821001312

# Server computes session key
# S_s = 0
# K_s = 43388321209941149759420236104888244958223766953174235657296806338137402595305
# User authenticated.
```

Likewise, if the client send $k \cdot N$ as its $A$ value (k is integer), the server will calcualte $S$ as:

$$ S = (A \cdot v^{u} \mod N) ^ {b} \mod N =  (kN \cdot v^{u} \mod N) ^ {b} \mod N = 0 $$

The server evaluate $S$ like in the previus attack, and the client can exploit it to gain access.



## Challenge 38 - Offline dictionary attack on simplified SRP

> Challenge: https://cryptopals.com/sets/5/challenges/38


Let's examine this simplified SRP version.

The client will calculte $S$ as:

$$ Sc = B ^ {a + ux} = g ^ {b \cdot (a + ux)} $$

The server will calculte $S$ as:

$$ Ss = (A \cdot v ^ {u}) ^ {b} = (g^{a} \cdot g ^ {ux}) ^ {b} = g ^ {b \cdot (a + ux)} $$

$$ Sc = Ss $$


We note that in this protocol, the server's "B" parameter doesn't depend on the password.

The server and client implementation:
```python
def simplified_srp_server() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            res = simplified_srp_handshake(conn)
            return res


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
```

```python
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
```

Now, we need to perform offline dictionary attack using MITM on the client.

We, as the MITM can choose the the following values as our own choice: b, B, u, and salt.

If we set $ B = g $, the client will calc $Sc$ as follows:

$$ Sc = B ^ {a + ux} = g ^ {a + ux} = g^{a} \cdot g^{ux} = A \cdot g^{ux} $$ 

As the MITM we know all the values in the equation but $x$, which means we can write a function: 

$$ F(password) = HMAC-SHA256(K, salt) = $$

$$ = HMAC-SHA256(SHA256(S), salt) = $$ 

$$ = HMAC-SHA256(SHA256(A \cdot g^{ux}), salt) = $$

$$ = HMAC-SHA256(SHA256(A \cdot g^{u \cdot (SHA256(salt|password))}), salt) $$

Using the above function, we can iterate the possible values of the weak password.

The MITM implementation:
```python
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
```

In this example we limit the search to digits only, but it can be expanded at a cost of computational time.
```python
Connected by ('127.0.0.1', 64490)
 21%|██        | 4/19 [01:11<04:29, 17.94s/it]
recovered_password='54321'
```



## Challenge 39 - Implement RSA

> Challenge: https://cryptopals.com/sets/5/challenges/39

