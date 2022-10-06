# Set 6: RSA and DSA

## Table of contents
41. [Challenge 41 - Implement unpadded message recovery oracle](#challenge-41---implement-unpadded-message-recovery-oracle)
42. [Challenge 42 - Bleichenbacher's e=3 RSA Attack](#challenge-42---bleichenbachers-e3-rsa-attack)
43. [Challenge 43 - DSA key recovery from nonce](#challenge-43---dsa-key-recovery-from-nonce)
44. [Challenge 44 - DSA nonce recovery from repeated nonce](#challenge-44---dsa-nonce-recovery-from-repeated-nonce)
45. [Challenge 45 - DSA parameter tampering](#challenge-45---dsa-parameter-tampering)
46. [Challenge 46 - RSA parity oracle](#challenge-46---rsa-parity-oracle)





## Challenge 41 - Implement unpadded message recovery oracle

> Challenge: https://cryptopals.com/sets/6/challenges/41

In this challenge we have a server that is able to decrypt a message only on it's first arrival.

We, as the attacker, want to find a way to decrypt a message that has already been decrypted by the server. Our attack is based on the following property:

RSA has the property that the product of two ciphertexts is equal to the encryption of the product of the respective plaintexts. That is: 

$$ m_{1}^{e} \cdot m_{2}^{e} = (m_{1} \cdot m_{2})^{e} \mod n $$

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



## Challenge 43 - DSA key recovery from nonce

> Challenge: https://cryptopals.com/sets/6/challenges/43

We start with implementing DSA:
```python
class DSA:
    p = int('800000000000000089e1855218a0e7dac38136ffafa72eda7'
            '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
            '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
            'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
            'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
            '1a584471bb1', 16)

    q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

    g = int('5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
            '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
            '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
            '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
            '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
            '9fc95302291', 16)

    def __init__(self):
        # Per-user keys
        self.x = random.randint(1, self.q - 1)  # private key
        self.y = pow(self.g, self.x, self.p)  # public key

    @staticmethod
    def H(x):
        return int(hashlib.sha1(x).hexdigest(), 16)

    def sign(self, msg: bytes) -> (int, int):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue

            k_inv = invmod(k, self.q)
            s = (k_inv * (self.H(msg) + self.x * r)) % self.q
            if s != 0:
                break

        return r, s

    def verify(self, msg: bytes, sig: (int, int)) -> bool:
        # unpack sig
        r, s = sig

        # check signature bounds
        if not (0 < r < self.q and 0 < s < self.q):
            return False

        w = invmod(s, self.q)
        u1 = (self.H(msg) * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q

        return v == r
```

In this challenge, we have the message and the signature, and we need to determine the private key.

The "bug" in the used DSA implementation is that *k* is chosen from the range [0, 2^16]. The small space of *k* values allow us to brute-force the result.

We start by recovering the private key *x* given the subkey *k*:
```python
def estimate_x_given_k(self, k: int):
    r_inv = invmod(self.r, self.q)
    x_est = (r_inv * (self.s * k - self.hash_func(self.msg))) % self.q
    return x_est
```

Then, we brute-force the possible values of *k* until we find a *k* that produces the given signature:
```python
def detect_k(self, k_max_val: int):
    """ Find the value of k using brute-force approach """
    for k in range(1, k_max_val):
        # calc r based on k
        tmp_r = pow(self.g, k, self.p) % self.q
        if tmp_r == self.r:
            return k
```

Finally, we can determine the private key of the given message:
```python
# given params
y = int('84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
        'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
        'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
        '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
        'bb283e6633451e535c45513b2d33c99ea17', 16)

msg = b'For those that envy a MC it can be hazardous to your health\n' \
    b'So be friendly, a matter of life and death, just like a etch-a-sketch\n'

r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940

# evaluate private key
x, k = Attack(msg=msg, r=r, s=s, q=DSA.q, p=DSA.p, g=DSA.g, hash_func=DSA.H, pub_key=y).detect_private_key()
print(f'{x=}\n{k=}')
# x=125489817134406768603130881762531825565433175625
# k=16575

# test signature using x
r_est = pow(DSA.g, k, DSA.p) % DSA.q
assert r_est == r

k_inv = invmod(k, DSA.q)
s_est = (k_inv * (DSA.H(msg) + x * r)) % DSA.q
assert s_est == s

# check for matching signatures
x_fingerprint = DSA.H(hex(x)[2:].encode())
print(x_fingerprint == int('0954edd5e0afe5542a4adf012611a91912a3ec16', 16))
# True
```



## Challenge 44 - DSA nonce recovery from repeated nonce

> Challenge: https://cryptopals.com/sets/6/challenges/44

We have two messages that were signed using the same *k* value.

We can find *k* from the messages and signatures using following way:

The equation for s is:

$$ s = k^{-1}(H(m) + x \cdot r) \mod q $$

Now, we look at two messages m1, m2 that were signed with the same k:

$$ s1 = k^{-1}(H(m1) + x \cdot r1) \mod q $$

$$ s2 = k^{-1}(H(m2) + x \cdot r2) \mod q $$

(Note that r1 = r2 is the same for both messages, since it depends only on k)

We get:

$$ s1 - s2 = k^{-1}[(H(m1) + x \cdot r1) - (H(m2) + x \cdot r2)] $$

$$ = k^{-1}[(H(m1) - H(m2)] $$

And conclude that:

$$ k = \dfrac{H(m1) - H(m2)}{s1 - s2} \mod q $$

```python
def eval_k(msg1: bytes, s1: int, msg2: bytes, s2: int) -> int:
    # domain parameters
    q = DSA.q

    # equation parts
    hm1_minus_hm2 = (DSA.H(msg1) - DSA.H(msg2)) % q
    s1_minus_s2 = (s1 - s2) % q
    s1_minus_s2_inv = invmod(s1_minus_s2, q)

    # calc k
    k = (hm1_minus_hm2 * s1_minus_s2_inv) % q
    return k
```

In order to find two messages with the same *k*, we can look for two messages with the same *r* (since *r* depends only on *k* and the domain parameters).

We can search the collection and find the following two messages:
```python
msg1 = b'Listen for me, you better listen for me now. '
r1 = 1105520928110492191417703162650245113664610474875
s1 = 1267396447369736888040262262183731677867615804316

msg2 = b'Pure black people mon is all I mon know. '
r2 = 1105520928110492191417703162650245113664610474875
s2 = 1021643638653719618255840562522049391608552714967
```

We use the described equation to evaluate k:
```python
# eval k
k = eval_k(msg1=msg1, s1=s1, msg2=msg2, s2=s2)
print(f'{k=}')  # k=108994997653034620063305500641348549625
```

And the method from last challenge to evaluate x:
```python
# eval x
x = estimate_x_given_k(k=k, msg=msg1, r=r1, s=s1)
print(f'{x=}')  # x=1379952329417023174824742221952501647027600451162

# check for matching signatures
x_fingerprint = DSA.H(hex(x)[2:].encode())
print(x_fingerprint == int('ca8f6f7c66fa362d40760d135b763eb8527d3d52', 16))  # True
```



## Challenge 45 - DSA parameter tampering

> Challenge: https://cryptopals.com/sets/6/challenges/45

Case 1:

If we substitute 0 for *g*, *r* will be 0, and the signature will not depend on *x*:

$$ r = g^{k} \mod p \mod q $$

When we try to verify a message with a signature containing r=0, we get: 

$$ v = (g^{u1} * y^{u2}) \mod p \mod q $$

$$ = (0^{u1} * y^{0}) \mod p \mod q $$

$$ = (0 * 1) \mod p \mod q = 0 $$

And the message pass verification.

```python
dsa = DSA(override_g=0)
msg = b'Whats Wrong??'

sig = dsa.sign(msg)
print(sig)  # (0, 1237736788808797058494844893968319670917570967501)

print(dsa.verify(msg, sig))  # True
print(dsa.verify(b'what is going on in here', (0, 85478656467)))  # True
```

Case 2:

If we substitute *p+1* for *g* and choose the magic (r,s) we get:

$$ g^{u1} \mod p = (p+1)^{u1} \mod p = 1 $$

$$ u2 = r_{magic} \cdot w \mod q = r_{magic} \cdot s_{magic}^{-1} \mod q = r_{magic} \cdot r_{magic}^{-1} \cdot z \mod q = z $$

$$ y^{u2} \mod p = y^{z} \mod p $$

$$ v = (g^{u1} * y^{u2}) \mod p \mod q = (1 * y^{z}) \mod p \mod q = r_{magic} $$

So, each message will be authenticated:

```python
dsa = DSA(override_g=DSA.p+1)

z = 4
z_inv = invmod(z, dsa.q)
r = pow(dsa.y, z, dsa.p) % dsa.q
s = (z_inv * r) % dsa.q
magic_sig = (r, s)

print(dsa.verify(b'Whattttt ???????', magic_sig))  # True
```



## Challenge 46 - RSA parity oracle

> Challenge: https://cryptopals.com/sets/6/challenges/46

