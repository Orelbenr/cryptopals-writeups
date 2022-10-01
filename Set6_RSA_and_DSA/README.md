# Set 6: RSA and DSA

## Table of contents
41. [Challenge 41 - Implement unpadded message recovery oracle](#challenge-41---implement-unpadded-message-recovery-oracle)
42. [Challenge 42 - Bleichenbacher's e=3 RSA Attack](#challenge-42---bleichenbachers-e3-rsa-attack)





## Challenge 41 - Implement unpadded message recovery oracle

> Challenge: https://cryptopals.com/sets/6/challenges/41

In this challenge we have a server that is able to decrypt a message only on it's first arrival.

We, as the attacker, want to find a way to decrypt a message that has already been decrypted by the server. Our attack is based on the following property:

*RSA has the property that the product of two ciphertexts is equal to the encryption of the product of the respective plaintexts. That is, $m_{1}^{e} \cdot m_{2}^{e} = (m_{1} \cdot m_{2})^{e} \mod n$.*

So, in order to decrypt a ciphertext $C$ , we create a new ciphertext $C'$ (where $s$ is a random number):

$$ C' = (s^{e} \mod N) \cdot C \mod N $$

The decryption of $C'$ (based on the presented properly) will be:

$$ P' = s \cdot P \mod N $$

And then we can recover $P$ using the cyclic invmod operation:

$$ P = invmod(s, N) \cdot P' $$

We start with implementing the server:
```python
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
```

And testing its exception for repeated messages:
```python
server = Server()

# encrypt message
msg = b'Implement unpadded message recovery oracle'
c = server.encrypt(msg)

# first decryption
p = server.decrypt(c)
print(f'{p=}')  # p=b'Implement unpadded message recovery oracle'

# second decryption
try:
    server.decrypt(c)
except PermissionError:
    print('Second attempt failed successfully :)')  # Second attempt failed successfully :)
```

Then, we implement the attack as described above:
```python
def attack(server: Server, ciphertext: int) -> bytes:
    # some consts
    N = server.rsa_obj.n
    e = server.rsa_obj.e

    s = random.randint(2, N - 1)
    s_inv = invmod(s, N)

    # create fake ciphertext
    fake_ciphertext = (pow(s, e, N) * ciphertext) % N

    # decrypt
    p_fake = RSA.bytes_to_num(server.decrypt(fake_ciphertext))
    p = (s_inv * p_fake) % N
    p = RSA.num_to_bytes(p)

    return p
```

And decrypting the message:
```python
# attack
rec_p = attack(server, c)
print(f'{rec_p=}')  # rec_p=b'Implement unpadded message recovery oracle'
```



## Challenge 42 - Bleichenbacher's e=3 RSA Attack

> Challenge: https://cryptopals.com/sets/6/challenges/42

We start by implementing RSA PCKS #1 version 1.5 standard.

*The standard provides the basic definitions of and recommendations for implementing the RSA algorithm for public-key cryptography. It defines the mathematical properties of public and private keys, primitive operations for encryption and signatures, secure cryptographic schemes, and related ASN.1 syntax representations.*

```python
class RSA_SIG_PKCS1:
    """
    Implementation of RSA.
    Based on the standard PKCS #1 Version 1.5
    Using MD5 digest.
    """
    ASN1_MD5 = b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'

    def __init__(self):
        self.rsa_obj = RSA()

    def sign(self, msg: bytes) -> int:
        # digest the message
        msg_hash = hashlib.md5(msg).digest()
        msg_hash = self.ASN1_MD5 + msg_hash

        # encode the data
        prefix = b'\x00\x01'
        padding = b'\xFF' * (self.rsa_obj.k - 3 - len(msg_hash))
        suffix = b'\x00'

        # EB = 00 || BT || PS || 00 || D
        msg_encoded = prefix + padding + suffix + msg_hash
        assert len(msg_encoded) == self.rsa_obj.k

        # convert to int and sign
        sig = self.rsa_obj.sign(msg_encoded)

        return sig

    def verify(self, msg: bytes, sig: int) -> bool:
        # decrypt sig and convert to bytes
        sig = self.rsa_obj.verify_sign(sig)

        # find the signature  marker
        if sig[0:2] != b'\x00\x01':
            return False

        # find the 00 separator between the padding and the payload
        try:
            sep_idx = sig.index(b'\x00', 2)
            sep_idx += 1
        except ValueError:
            return False

        # parse ASN1
        if not sig[sep_idx:].startswith(self.ASN1_MD5):
            return False

        # parse hash
        msg_hash = sig[sep_idx+len(self.ASN1_MD5):sep_idx+len(self.ASN1_MD5)+16]
        real_msg_hash = hashlib.md5(msg).digest()

        # check message integrity
        return msg_hash == real_msg_hash
```

Note that the verifier isn't checking all the padding!

Consequently, there is the possibility that instead of hundreds of ffh bytes, we only have a few, which means there could be lot of possible numbers that could produce a valid-looking signature.

So, in order to forge a signature for a message m, we need to find a number that when cubed:
- doesn't wrap the modulus (thus bypassing the key entirely)
- produces a block that start with "00h 01h ffh ... 00h ASN.1 HASH".

One possible approche for finding such a number: 

Formating the message block we want to forge, leaving sufficient trailing zeros at the end to fill with garbage, then taking the cube-root of that block (The cube root is implemented using binary search for large integers):

```python
def forge_sig(msg: bytes, sig_len: int):
    # create ASN1 | HASH
    msg_hash = hashlib.md5(msg).digest()
    msg_hash = RSA_SIG_PKCS1.ASN1_MD5 + msg_hash

    # format the message block
    msg_encoded = b'\x00\x01\xFF\xFF\xFF\xFF\x00'
    msg_encoded += msg_hash
    msg_encoded += b'\x00' * (sig_len - len(msg_encoded))

    # transform to integer
    msg_encoded = RSA.bytes_to_integer(msg_encoded)

    # cube root the result (floor)
    sig = invpow_integer(msg_encoded, 3)

    return sig + 1
```

And checking the results:
```python
# create signature object
rsa_sig = RSA_SIG_PKCS1()

# the message we choose
msg = b'hi mom'

# real signature
real_sig = rsa_sig.sign(msg)

# forged signature
sig_len = math.ceil(math.log2(rsa_sig.rsa_obj.n) / 8)
forged_sig = forge_sig(msg, sig_len)

# verify signature
real_sig_res = rsa_sig.verify(msg, real_sig)
print(f'{real_sig_res=}')  # real_sig_res=True
forged_sig_res = rsa_sig.verify(msg, forged_sig)
print(f'{forged_sig_res=}')  # forged_sig_res=True
```
