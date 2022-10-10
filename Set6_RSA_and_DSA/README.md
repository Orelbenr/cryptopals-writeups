# Set 6: RSA and DSA

## Table of contents
41. [Challenge 41 - Implement unpadded message recovery oracle](#challenge-41---implement-unpadded-message-recovery-oracle)
42. [Challenge 42 - Bleichenbacher's e=3 RSA Attack](#challenge-42---bleichenbachers-e3-rsa-attack)
43. [Challenge 43 - DSA key recovery from nonce](#challenge-43---dsa-key-recovery-from-nonce)
44. [Challenge 44 - DSA nonce recovery from repeated nonce](#challenge-44---dsa-nonce-recovery-from-repeated-nonce)
45. [Challenge 45 - DSA parameter tampering](#challenge-45---dsa-parameter-tampering)
46. [Challenge 46 - RSA parity oracle](#challenge-46---rsa-parity-oracle)
47. [Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](#challenge-47---bleichenbachers-pkcs-15-padding-oracle-simple-case)
48. [Challenge 48 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](#challenge-48---bleichenbachers-pkcs-15-padding-oracle-complete-case)




## Challenge 41 - Implement unpadded message recovery oracle

> Challenge: https://cryptopals.com/sets/6/challenges/41

In this challenge, we have a server that can decrypt a message only on its first arrival.

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

Consequently, there is the possibility that instead of hundreds of ffh bytes, we only have a few, which means there could be a lot of possible numbers that could produce a valid-looking signature.

So, to forge a signature for a message m, we need to find a number that when cubed:
- doesn't wrap the modulus (thus bypassing the key entirely)
- produces a block that starts with "00h 01h ffh ... 00h ASN.1 HASH".

One possible approach for finding such a number: 

Formating the message block we want to forge, leaving sufficient trailing zeros at the end to fill with garbage, then taking the cube root of that block (The cube root is implemented using binary search for large integers):

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

The "bug" in the used DSA implementation is that *k* is chosen from the range [0, 2^16]. The small space of *k* values allows us to brute-force the result.

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
print(x_fingerprint == int('0954edd5e0afe5542a4adf012611a91912a3ec16', 16))  # True
```



## Challenge 44 - DSA nonce recovery from repeated nonce

> Challenge: https://cryptopals.com/sets/6/challenges/44

We have two messages that were signed using the same *k* value.

We can find *k* from the messages and signatures using the following way:

The equation for s is:

$$ s = k^{-1}(H(m) + x \cdot r) \mod q $$

Now, we look at two messages m1, m2 that were signed with the same k:

$$ s1 = k^{-1}(H(m1) + x \cdot r1) \mod q $$

$$ s2 = k^{-1}(H(m2) + x \cdot r2) \mod q $$

(Note that r1 = r2 is the same for both messages since it depends only on k)

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

To find two messages with the same *k*, we can look for two messages with the same *r* (since *r* depends only on *k* and the domain parameters).

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

And the method from the last challenge to evaluate x:
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

$$ v = (g^{u1} \cdot y^{u2}) \mod p \mod q $$

$$ = (0^{u1} \cdot y^{0}) \mod p \mod q $$

$$ = (0 \cdot 1) \mod p \mod q = 0 $$

And the message passes verification.

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

We write an Oracle that checks if the plaintext of a given message is even or odd:
```python
class Oracle:
    def __init__(self):
        self.rsa = RSA(1024)

    def validate_msg(self, cipher: int) -> bool:
        """ Return True if the parity bit is zero """
        msg = self.rsa.decrypt(cipher, output_bytes=False)
        return not msg & 1
```

Now, using this oracle, we should be able to decrypt any ciphertext we want!

Using the following identity of RSA:

$$ m_{1}^{e} \cdot m_{2}^{e} = (m_{1} \cdot m_{2})^{e} \mod n $$

we can control the message the oracle decrypts.

If we use the Oracle to test the parity bit of the following message:

$$ 2 \cdot m \mod n $$

there are two possibilities:

1) In case that: 

    $$ 2 \cdot m < n $$

    $$ m < \dfrac{n}{2} $$

    the message won't wrap the modulus, and the parity bit will indicate *even*.

2) In case that:

    $$ 2 \cdot m > n $$

    $$ m > \dfrac{n}{2} $$

    the message will wrap the modulus, and the parity bit will indicate *odd* (since n is a prime number).

Using $\log_{2}{n}$ iterations of this approach, we can narrow down the possible values of *m* to one:

```python
def decrypt_attack(oracle, cipher: int):
    n = oracle.rsa.n
    low_frac, high_frac = Fraction(0), Fraction(1)  # fraction out of n
    low, high = 0, n

    num_repetitions = n.bit_length()
    for i in range(num_repetitions):
        # double the message
        cipher = (cipher * oracle.rsa.encrypt(2, input_bytes=False)) % n
        
        # check parity bit
        res = oracle.validate_msg(cipher)

        # the plaintext is less than half the modulus
        if res:
            high_frac = (high_frac - low_frac) / 2 + low_frac
            high = n * high_frac

        # the plaintext is more than half the modulus
        else:
            low_frac = (high_frac - low_frac) / 2 + low_frac
            low = n * low_frac

        msg = long_to_bytes(math.floor(high))
        print(f'Iteration {i}: {msg}')

    return msg
```

Finally, we can decrypt the given message:
```python
oracle = Oracle()

# given message
msg = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
msg = base64.b64decode(msg)

# encrypt with public key
cipher = oracle.rsa.encrypt(msg)

# decrypt the cipher
recovered_message = decrypt_attack(oracle, cipher)
print(f'{recovered_message=}')
```

And the "hollywood style" decryption:
```python
Iteration 0: b']l\xdb\xb6#\x84V\x08\xf9\x1b\xbd\xc7\xa2u%:\xdeg\xff\xbe\x02\x9cN:\xf1\x85\xc4"\x97\x05\x81Mmx\xea\xb5(\xf6\x9f\x12\xec9\x01\xd1\x00\x93\xcb\xf7\x840\x86]\xba5-S\xc08g\xb7\xeb|\xca\xbeCO\x823\xcf\xdes\xe0\xb0I9<\xfeM\xd7c\x0fgS\x0c\x1b\xc1\xb9\x9d:\xd4\x8b\x84(\x03\xe9\x82\xd3\xff\xe1\x99\xc4P\x192\xb4\x9c\xbd=\xef\xcc\x95\x88kkZ\x15\xcc\x9e\x03q\x05\x93Y\xe0\xf7\x11\x0b\xbcq\xb3\x08\xb4Kq\x9e\xc4\x01\x98\x97\x94\xc3\xf2(\x0f\xa18\xc8\xa7\xa6dx\xe5\x87\x0c\x9b\xfaP\xf6$\xffS\ro\x92TM\xc2\xeb\xcagK\xea\xf1\xb0U\x9f\x91\xb7\xf9\x9d\xad\xd1\xba\xc0\x81\x17\xbep\xe5%&\xb6B\x91O\xa6\xe2\x17Y\x95ZU\xfbF~\x91\xbc:z\nW\x18\xb9\xa3\xbe\x89\xbeXy\x8b7\x05\x01\xa7\xdb\xc3\xd6\xa3\xee\x86\x89\x89\xe8\xc7\xff\xa2\x9f\x088\xf5\x14\xfc\x06\xd6\xab\x89\xed\x0c\x9f\xf7\xb9\xe0"\xf8}r'
Iteration 1: b".\xb6m\xdb\x11\xc2+\x04|\x8d\xde\xe3\xd1:\x92\x9do3\xff\xdf\x01N'\x1dx\xc2\xe2\x11K\x82\xc0\xa6\xb6\xbcuZ\x94{O\x89v\x1c\x80\xe8\x80I\xe5\xfb\xc2\x18C.\xdd\x1a\x96\xa9\xe0\x1c3\xdb\xf5\xbee_!\xa7\xc1\x19\xe7\xef9\xf0X$\x9c\x9e\x7f&\xeb\xb1\x87\xb3\xa9\x86\r\xe0\xdc\xce\x9djE\xc2\x14\x01\xf4\xc1i\xff\xf0\xcc\xe2(\x0c\x99ZN^\x9e\xf7\xe6J\xc45\xb5\xad\n\xe6O\x01\xb8\x82\xc9\xac\xf0{\x88\x85\xde8\xd9\x84Z%\xb8\xcfb\x00\xccK\xcaa\xf9\x14\x07\xd0\x9cdS\xd32<r\xc3\x86M\xfd({\x12\x7f\xa9\x86\xb7\xc9*&\xe1u\xe53\xa5\xf5x\xd8*\xcf\xc8\xdb\xfc\xce\xd6\xe8\xdd`@\x8b\xdf8r\x92\x93[!H\xa7\xd3q\x0b\xac\xca\xad*\xfd\xa3?H\xde\x1d=\x05+\x8c\\\xd1\xdfD\xdf,<\xc5\x9b\x82\x80\xd3\xed\xe1\xebQ\xf7CD\xc4\xf4c\xff\xd1O\x84\x1cz\x8a~\x03kU\xc4\xf6\x86O\xfb\xdc\xf0\x11|>\xb9"

.
.
.

Iteration 1961: b"That's why I found you don't play around with the Funky L\x06\xd8L\x90{\x95\xd4\x1c\xc8e"
Iteration 1962: b"That's why I found you don't play around with the Funky L\x06\xd8L\x90{\x95\xd4\x1c\xc8e"
Iteration 1963: b"That's why I found you don't play around with the Funky L\x06\xd8L\x90{\x95\xd4\x1c\xc8e"
Iteration 1964: b"That's why I found you don't play around with the Funky F0\n\x91.CPs\x8d6\xa9"
Iteration 1965: b"That's why I found you don't play around with the Funky F0\n\x91.CPs\x8d6\xa9"
Iteration 1966: b'That\'s why I found you don\'t play around with the Funky D\xbaW"U\xb5?\x1biR;'
Iteration 1967: b"That's why I found you don't play around with the Funky C\xff}j\xe9n6oW`\x03"
Iteration 1968: b"That's why I found you don't play around with the Funky C\xa2\x10\x8f3J\xb2\x19Nf\xe7"
Iteration 1969: b"That's why I found you don't play around with the Funky CsZ!X8\xef\xeeI\xeaY"
Iteration 1970: b"That's why I found you don't play around with the Funky CsZ!X8\xef\xeeI\xeaY"
Iteration 1971: b"That's why I found you don't play around with the Funky CsZ!X8\xef\xeeI\xeaY"
Iteration 1972: b"That's why I found you don't play around with the Funky CsZ!X8\xef\xeeI\xeaY"
Iteration 1973: b"That's why I found you don't play around with the Funky Cpn\xbaz\x87\xd3\xcb\x99\xa2\x91"
Iteration 1974: b"That's why I found you don't play around with the Funky Cpn\xbaz\x87\xd3\xcb\x99\xa2\x91"
Iteration 1975: b"That's why I found you don't play around with the Funky Co\xb3\xe0\xc3\x1b\x8c\xc2\xed\x90\x9e"
Iteration 1976: b"That's why I found you don't play around with the Funky Co\xb3\xe0\xc3\x1b\x8c\xc2\xed\x90\x9e"
Iteration 1977: b'That\'s why I found you don\'t play around with the Funky Co\x85*U@{\x00\xc2\x8c"'
Iteration 1978: b"That's why I found you don't play around with the Funky Com\xcf\x1eR\xf2\x1f\xad\t\xe4"
Iteration 1979: b"That's why I found you don't play around with the Funky Com\xcf\x1eR\xf2\x1f\xad\t\xe4"
Iteration 1980: b"That's why I found you don't play around with the Funky Com\xcf\x1eR\xf2\x1f\xad\t\xe4"
Iteration 1981: b"That's why I found you don't play around with the Funky Com\xcf\x1eR\xf2\x1f\xad\t\xe4"
Iteration 1982: b"That's why I found you don't play around with the Funky Com\xcf\x1eR\xf2\x1f\xad\t\xe4"
Iteration 1983: b"That's why I found you don't play around with the Funky Com\x14D\x9b\x85\xd8\xa4]\xd2"
Iteration 1984: b"That's why I found you don't play around with the Funky Col\xb6\xd7\xbf\xcf\xb5 \x07\xc9"
Iteration 1985: b"That's why I found you don't play around with the Funky Col\x88!Q\xf4\xa3]\xdc\xc4"
Iteration 1986: b"That's why I found you don't play around with the Funky Colp\xc6\x1b\x07\x1a|\xc7B"
Iteration 1987: b"That's why I found you don't play around with the Funky Cole\x18\x7f\x90V\x0c<\x81"
Iteration 1988: b"That's why I found you don't play around with the Funky Cole\x18\x7f\x90V\x0c<\x81"
Iteration 1989: b"That's why I found you don't play around with the Funky Cole\x18\x7f\x90V\x0c<\x81"
Iteration 1990: b"That's why I found you don't play around with the Funky Cole\x18\x7f\x90V\x0c<\x81"
Iteration 1991: b"That's why I found you don't play around with the Funky Cold]\xa5\xd8\xe9\xc53\xd5"
Iteration 1992: b"That's why I found you don't play around with the Funky Cold]\xa5\xd8\xe9\xc53\xd5"
Iteration 1993: b"That's why I found you don't play around with the Funky Cold.\xefk\x0e\xb3q\xaa"
Iteration 1994: b"That's why I found you don't play around with the Funky Cold.\xefk\x0e\xb3q\xaa"
Iteration 1995: b"That's why I found you don't play around with the Funky Cold#A\xcf\x97\xef\x01\x1f"
Iteration 1996: b"That's why I found you don't play around with the Funky Cold#A\xcf\x97\xef\x01\x1f"
Iteration 1997: b"That's why I found you don't play around with the Funky Cold Vh\xba=\xe4\xfc"
Iteration 1998: b"That's why I found you don't play around with the Funky Cold Vh\xba=\xe4\xfc"
Iteration 1999: b"That's why I found you don't play around with the Funky Cold Vh\xba=\xe4\xfc"
Iteration 2000: b"That's why I found you don't play around with the Funky Cold Vh\xba=\xe4\xfc"
Iteration 2001: b"That's why I found you don't play around with the Funky Cold Vh\xba=\xe4\xfc"
Iteration 2002: b"That's why I found you don't play around with the Funky Cold Vh\xba=\xe4\xfc"
Iteration 2003: b"That's why I found you don't play around with the Funky Cold Vh\xba=\xe4\xfc"
Iteration 2004: b"That's why I found you don't play around with the Funky Cold P\x91\xec\x82\x82\xc4"
Iteration 2005: b"That's why I found you don't play around with the Funky Cold M\xa6\x85\xa4\xd1\xa8"
Iteration 2006: b"That's why I found you don't play around with the Funky Cold M\xa6\x85\xa4\xd1\xa8"
Iteration 2007: b"That's why I found you don't play around with the Funky Cold M\xa6\x85\xa4\xd1\xa8"
Iteration 2008: b"That's why I found you don't play around with the Funky Cold M\xa6\x85\xa4\xd1\xa8"
Iteration 2009: b"That's why I found you don't play around with the Funky Cold Mw\xcf6\xf6\x96"
Iteration 2010: b"That's why I found you don't play around with the Funky Cold Mw\xcf6\xf6\x96"
Iteration 2011: b"That's why I found you don't play around with the Funky Cold Ml!\x9b\x7f\xd2"
Iteration 2012: b"That's why I found you don't play around with the Funky Cold MfJ\xcd\xc4o"
Iteration 2013: b"That's why I found you don't play around with the Funky Cold MfJ\xcd\xc4o"
Iteration 2014: b"That's why I found you don't play around with the Funky Cold MfJ\xcd\xc4o"
Iteration 2015: b"That's why I found you don't play around with the Funky Cold Me\x8f\xf4\r\x03"
Iteration 2016: b"That's why I found you don't play around with the Funky Cold Me\x8f\xf4\r\x03"
Iteration 2017: b"That's why I found you don't play around with the Funky Cold Me\x8f\xf4\r\x03"
Iteration 2018: b"That's why I found you don't play around with the Funky Cold Mex\x98\xd6\x16"
Iteration 2019: b"That's why I found you don't play around with the Funky Cold Mel\xeb:\x9f"
Iteration 2020: b"That's why I found you don't play around with the Funky Cold Meg\x14l\xe3"
Iteration 2021: b"That's why I found you don't play around with the Funky Cold Meg\x14l\xe3"
Iteration 2022: b"That's why I found you don't play around with the Funky Cold Mee\x9e\xb9u"
Iteration 2023: b"That's why I found you don't play around with the Funky Cold Med\xe3\xdf\xbd"
Iteration 2024: b"That's why I found you don't play around with the Funky Cold Med\x86r\xe1"
Iteration 2025: b"That's why I found you don't play around with the Funky Cold Med\x86r\xe1"
Iteration 2026: b"That's why I found you don't play around with the Funky Cold Medo\x17\xab"
Iteration 2027: b"That's why I found you don't play around with the Funky Cold Medo\x17\xab"
Iteration 2028: b"That's why I found you don't play around with the Funky Cold Medo\x17\xab"
Iteration 2029: b"That's why I found you don't play around with the Funky Cold Medl,D"
Iteration 2030: b"That's why I found you don't play around with the Funky Cold Medj\xb6\x90"
Iteration 2031: b"That's why I found you don't play around with the Funky Cold Medi\xfb\xb6"
Iteration 2032: b"That's why I found you don't play around with the Funky Cold Medi\x9eJ"
Iteration 2033: b"That's why I found you don't play around with the Funky Cold Medio\x93"
Iteration 2034: b"That's why I found you don't play around with the Funky Cold Medio\x93"
Iteration 2035: b"That's why I found you don't play around with the Funky Cold Medio\x93"
Iteration 2036: b"That's why I found you don't play around with the Funky Cold Medio\x93"
Iteration 2037: b"That's why I found you don't play around with the Funky Cold Medio\x93"
Iteration 2038: b"That's why I found you don't play around with the Funky Cold Medio\x93"
Iteration 2039: b"That's why I found you don't play around with the Funky Cold Medin\xd8"
Iteration 2040: b"That's why I found you don't play around with the Funky Cold Medin{"
Iteration 2041: b"That's why I found you don't play around with the Funky Cold Medin{"
Iteration 2042: b"That's why I found you don't play around with the Funky Cold Medind"
Iteration 2043: b"That's why I found you don't play around with the Funky Cold Medind"
Iteration 2044: b"That's why I found you don't play around with the Funky Cold Medind"
Iteration 2045: b"That's why I found you don't play around with the Funky Cold Medina"
```



## Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

> Challenge: https://cryptopals.com/sets/6/challenges/47

The following challenge is based on the paper: 

[Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1](https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)

We start with the setup.

We implement an Oracle, that performs the PKCS #1 padding and verify the padding correctness:
```python
class RSA_PKCS1_Type2_Oracle(RsaBase):
    """
    Implementation of RSA Encryption Scheme.
    Based on the standard PKCS #1 Version 1.5 for type-2 blocks
    https://www.rfc-editor.org/rfc/rfc2313
    """
    def __init__(self, key_len=1024):
        super().__init__(key_len)

    def pkcs_padding(self, msg: bytes) -> bytes:
        # check bounds
        if len(msg) > self.k - 11:
            raise ValueError(f'Message length must not exceeds {self.k - 11} octets')

        # encode the data
        prefix = b'\x00\x02'
        padding = bytes([randint(1, 2 ** 8 - 1) for _ in range(self.k - 3 - len(msg))])
        suffix = b'\x00'

        # EB = 00 || BT || PS || 00 || D
        msg_encoded = prefix + padding + suffix + msg
        assert len(msg_encoded) == self.k

        return msg_encoded

    def pkcs_unpadding(self, msg: bytes) -> bytes:
        """
        Un-pad the PKCS message.
        raise [AttributeError] is mark is incorrect.
        raise [ValueError] if \x00 sep is not included.
        """
        # verify the PKCS mark
        if msg[0:2] != b'\x00\x02':
            raise AttributeError('Cipher is not PKCS conforming')

        # find the 00 separator between the padding and the payload
        sep_idx = msg.index(b'\x00', 2)
        sep_idx += 1

        # decode the message block
        msg = msg[sep_idx:]
        return msg

    def encrypt(self, msg: bytes) -> int:
        # encode the message
        msg_encoded = self.pkcs_padding(msg)

        # convert to integer and encrypt
        msg_encoded = self.bytes_to_integer(msg_encoded)
        cipher = self.encrypt_base(msg_encoded)

        return cipher

    def validate_msg(self, cipher: int) -> bool:
        """ Return True if the message starts with \x00\x02 """
        # decrypt cipher and convert to bytes
        msg = self.decrypt_base(cipher)
        msg = self.integer_to_bytes_padded(msg)
        assert len(msg) == self.k

        # verify the PKCS mark
        if msg[0:2] == b'\x00\x02':
            return True
        else:
            return False
```


Next, we implement the paper. 

(In this challenge, we assume we can skip step 2.b and the union in step 3):

```python
def bleichenbacher98_attack_partial(oracle: RSA_PKCS1_Type2_Oracle, c: int):
    # Set consts
    e, n = oracle.e, oracle.n
    B = 2 ** (8 * (oracle.k-2))

    # Initialize variables
    i = 1
    M_prev = [(2*B, 3*B - 1)]
    s_prev = None

    # Step 1: Blinding.
    # (In our case, c in already PKCS conforming)
    s0 = 1
    c0 = (c * pow(s0, e, n)) % n

    while True:
        print(f'Iteration number {i} ...')

        # Step 2: Searching for PKCS conforming messages.
        # Step 2.a: find the smallest positive integer s1 >= n/3B
        if i == 1:
            s = integer_division_ceil(n, (3*B))
            while not oracle.validate_msg((c0 * pow(s, e, n)) % n):
                s += 1

        # Step 2.b: Searching with more than one interval left.
        elif len(M_prev) > 1:
            raise NotImplementedError

        # Step 2.c: Searching with one interval left.
        else:
            a, b = M_prev[0]
            r = integer_division_ceil(2 * (b * s_prev - 2 * B), n)
            s = integer_division_ceil((2 * B + r * n), b)

            while True:
                if oracle.validate_msg((c0 * pow(s, e, n)) % n):
                    break

                if s < (3 * B + r * n) // a:
                    s += 1

                else:
                    r += 1
                    s = integer_division_ceil((2 * B + r * n), b)

        # verify step 2 result
        assert oracle.validate_msg((c0 * pow(s, e, n)) % n)

        # Step 3: Narrowing the set of solutions.
        a, b = M_prev[0]

        r_up = (b*s - 2*B) // n
        r_dwn = integer_division_ceil((a*s - 3*B + 1), n)
        assert r_up == r_dwn
        r = r_dwn

        dwn = max(a, integer_division_ceil((2*B + r*n), s))
        up = min(b, (3*B - 1 + r*n) // s)

        M = [(dwn, up)]

        # Step 4: Computing the solution.
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = (M[0][0] * invmod(s0, n)) % n
            return m

        # Update prev variables
        s_prev = s
        M_prev = M
        i += 1
```

And using the attack to decrypt the cipher:
```python
oracle = RSA_PKCS1_Type2_Oracle(key_len=256)
msg = b'kick it, CC'

cipher = oracle.encrypt(msg)

decryption = bleichenbacher98_attack_partial(oracle, cipher)
decryption = oracle.integer_to_bytes_padded(decryption)
decryption = oracle.pkcs_unpadding(decryption)
assert decryption == msg
```



## Challenge 48 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

> Challenge: https://cryptopals.com/sets/6/challenges/48

This challenge extends the solution of the last one.

We start with the union function for step 3:
```python
def calc_set_union(interval_set: list) -> list:
    """
    Calc the union of given intervals
    :param interval_set: list of intervals of the form (start, end)
    :return: list of intervals corresponding to the union
    """
    interval_set.sort(key=lambda interval: interval[0])
    y = [interval_set[0]]
    for x in interval_set[1:]:
        if y[-1][1] < x[0]:
            y.append(x)
        else:
            y[-1] = y[-1][0],  max(y[-1][1], x[1])

    return y
```

Then, we complete the missing steps from the challenge:
```python
def bleichenbacher98_attack(oracle: RSA_PKCS1_Type2_Oracle, c: int):
    # Set consts
    e, n = oracle.e, oracle.n
    B = 2 ** (8 * (oracle.k-2))

    # Initialize variables
    i = 1
    M_prev = [(2*B, 3*B - 1)]
    s_prev = None

    # Step 1: Blinding.
    # (In our case, c in already PKCS conforming)
    s0 = 1
    c0 = (c * pow(s0, e, n)) % n

    while True:
        print(f'Iteration number {i} ...')

        # Step 2: Searching for PKCS conforming messages.
        # Step 2.a: find the smallest positive integer s1 >= n/3B
        if i == 1:
            s = integer_division_ceil(n, (3*B))
            while not oracle.validate_msg((c0 * pow(s, e, n)) % n):
                s += 1

        # Step 2.b: Searching with more than one interval left.
        elif len(M_prev) > 1:
            s = s_prev + 1
            while not oracle.validate_msg((c0 * pow(s, e, n)) % n):
                s += 1

        # Step 2.c: Searching with one interval left.
        else:
            a, b = M_prev[0]
            r = integer_division_ceil(2 * (b * s_prev - 2 * B), n)
            s = integer_division_ceil((2 * B + r * n), b)

            while True:
                if oracle.validate_msg((c0 * pow(s, e, n)) % n):
                    break

                if s < (3 * B + r * n) // a:
                    s += 1

                else:
                    r += 1
                    s = integer_division_ceil((2 * B + r * n), b)

        # verify step 2 result
        assert oracle.validate_msg((c0 * pow(s, e, n)) % n)

        # Step 3: Narrowing the set of solutions.
        M_tmp = []
        for a, b in M_prev:
            r_up = (b*s - 2*B) // n
            r_dwn = integer_division_ceil((a*s - 3*B + 1), n)

            for r in range(r_dwn, r_up + 1):
                dwn = max(a, integer_division_ceil((2*B + r*n), s))
                up = min(b, (3*B - 1 + r*n) // s)
                M_tmp.append((dwn, up))

        if len(M_tmp) > 1:
            M = calc_set_union(M_tmp)
        else:
            M = M_tmp

        # Step 4: Computing the solution.
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = (M[0][0] * invmod(s0, n)) % n
            return m

        # Update prev variables
        s_prev = s
        M_prev = M
        i += 1
```

And decrypting the cipher:
```python
oracle = RSA_PKCS1_Type2_Oracle(key_len=768)
msg = b'kick it, CC'

cipher = oracle.encrypt(msg)

decryption = bleichenbacher98_attack(oracle, cipher)
decryption = oracle.integer_to_bytes_padded(decryption)
decryption = oracle.pkcs_unpadding(decryption)
assert decryption == msg
```

We did it!
We did it!
We did it!

Yeah!
Hooray!
Woo!

We did it!
