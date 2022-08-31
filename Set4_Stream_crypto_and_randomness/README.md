
# Set 4: Stream crypto and randomness

## Table of contents
25. [Challenge 25 - Break "random access read/write" AES CTR](#challenge-25---break-random-access-readwrite-aes-ctr)
26. [Challenge 26 - CTR bitflipping](#challenge-26---ctr-bitflipping)
27. [Challenge 27 - Recover the key from CBC with IV=Key](#challenge-27---recover-the-key-from-cbc-with-ivkey)
28. [Challenge 28 - Implement a SHA-1 keyed MAC](#challenge-28---implement-a-sha-1-keyed-mac)
29. [Challenge 29 - Break a SHA-1 keyed MAC using length extension](#challenge-29---break-a-sha-1-keyed-mac-using-length-extension)
30. [Challenge 30 - Break an MD4 keyed MAC using length extension](#challenge-30---break-an-md4-keyed-mac-using-length-extension)
31. [Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak](#challenge-31---implement-and-break-hmac-sha1-with-an-artificial-timing-leak)






## Challenge 25 - Break "random access read/write" AES CTR

> Challenge: https://cryptopals.com/sets/4/challenges/25

First we load the file and recover the plaintext (challenge 10):
```python
# load cipher and decode base64 to bytes  
with open('25.txt', 'r') as fh:  
  ciphertext = base64.b64decode(fh.read())  
  
key = b"YELLOW SUBMARINE"  
plaintext = aes_ecb_decrypt(ciphertext=ciphertext, key=key, remove_padding=True)
```

Now we implement the requested **edit** function which is able to modify the plaintext and return the result:
```python
def edit(self, ciphertext: bytes, offset: int, new_text: bytes):  
	key_stream = self.ctr_obj.generate_key_stream(len(ciphertext))  
	key_stream = key_stream[offset: offset + len(new_text)]  

	new_cipher = xor_bytes((key_stream, new_text))  
	out = ciphertext[:offset] + new_cipher + ciphertext[offset+len(new_cipher):]  
	return out
```

In order to recover the original plaintext we can just use the **edit** function with the *ciphertext* as *new_text*.
This way, the new encryption will result in:
$$ciphertext \oplus keystream =$$
$$plaintext \oplus keystream \oplus keystream = $$
$$plaintext $$

```python
# attack  
recovered_plaintext = oracle.edit(ciphertext=ciphertext, offset=0, new_text=ciphertext)  
print(recovered_plaintext)
# b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them ..."
```


## Challenge 26 - CTR bitflipping

> Challenge: https://cryptopals.com/sets/4/challenges/26

We adjust the oracle from *challenge 16* to use CTR mode:
```python
class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.ctr_obj = AesCtr(self.key)

    def encode(self, plaintext: bytes) -> bytes:
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

        # quote out ";" and "="
        plaintext = plaintext.replace(b";", b"").replace(b"=", b"")
        plaintext = prefix + plaintext + suffix

        # encrypt and return
        ciphertext = self.ctr_obj.encrypt(plaintext)
        return ciphertext

    def parse(self, ciphertext: bytes) -> bool:
        decrypted = self.ctr_obj.decrypt(ciphertext)
        return b';admin=true;' in decrypted
```

Remember that CTR mode is just a simple stream cipher; We can use a cheap trick to modify the output.

Denote our *target* with with $p_{target}$ and choose $c_{1}$ and $c_{2}$ such that $p_{target} = c_{1} \oplus c_{2}$.

Now, encrypt $c_{1}$. The encryption will result in $c_{1} \oplus keystream$. Then XOR the result against $c_{2}$ and decrypt. The decryption will evaluate into:

$$ c_{1} \oplus keystream \oplus c_{2} \oplus keystream = $$

$$ c_{1} \oplus c_{2} = p_{target} $$

As  desired...

We start by detecting the prefix length. Because the cipher is a stream cipher, we just look for the index where the encryption of different plaintexts differ:
```python
def detect_prefix_length(oracle: Oracle) -> int:
    c1 = oracle.encode(b'A' * 5)
    c2 = oracle.encode(b'B' * 5)

    for i in range(len(c1)):
        if c1[i] != c2[i]:
            return i

    raise Exception('detect_prefix_length failed')
```

In this case our target is `b';admin=true;'` and we choose `c1=b'FFFFFFFFFFFF`:

```python
def generate_attack_sequence(oracle: Oracle, prefix_len: int):
    # target and corresponding target=c1+c2
    target = b';admin=true;'
    c1 = b'F' * len(target)
    c2 = xor_bytes((target, c1))

    # get ciphertext and build modification
    ciphertext = oracle.encode(c1)
    c2_padded = bytes([0] * prefix_len) + c2
    c2_padded += bytes([0] * (len(ciphertext) - len(c2_padded)))
    modified_ciphertext = xor_bytes((ciphertext, c2_padded))
    return modified_ciphertext
```

And inject the result:
```python
oracle = Oracle()
prefix_len = detect_prefix_length(oracle)
print(f'{prefix_len=}') # prefix_len=32

attack_sequence = generate_attack_sequence(oracle, prefix_len)
is_admin = oracle.parse(attack_sequence)
print(f'{is_admin=}') # is_admin=True
```


## Challenge 27 - Recover the key from CBC with IV=Key

> Challenge: https://cryptopals.com/sets/4/challenges/27

Let's examine the proposed method:

1. Encrypt a message that is at least 3 blocks long: `AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3`
2. Modify the message (you are now the attacker): `C_1, C_2, C_3 -> C_1, 0, C_1`
3. Decrypt the message: `P'_1, P'_2, P'_3`
4. Extract the key: `P'_1 XOR P'_3`

Remember that in CBC mode:

$$ p_{m} = D(c_{m}) \oplus c_{m-1} $$

Thus: 

$$ p'_{3} = D(c_{3}) \oplus c_{2} = D(c_{1}) \oplus 0 = D(c_{1}) $$

$$ p'_{1} = D(c_{1}) \oplus IV $$

After step 4 we get (since IV=KEY):

$$ p'_{1} \oplus p'_{3} =  D(c_{1}) \oplus IV \oplus D(c_{1}) = IV = KEY $$


So, let's implement it:

We use the same oracle from challenge 16 (except the IV), and verify each byte of the plaintext for ASCII compliance:
```python
class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.nonce = self.key

    def encode(self, plaintext: bytes) -> bytes:
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

        # quote out ";" and "="
        plaintext = plaintext.replace(b";", b"").replace(b"=", b"")
        plaintext = prefix + plaintext + suffix

        # encrypt and return
        ciphertext = aes_cbc_encrypt(plaintext, key=self.key, nonce=self.nonce, add_padding=True)
        return ciphertext

    def parse(self, ciphertext: bytes) -> bool:
        decrypted = aes_cbc_decrypt(ciphertext, key=self.key, nonce=self.nonce, remove_padding=True)

        # verify each byte of the plaintext for ASCII compliance
        try:
            decoded = decrypted.decode('ascii')
        except UnicodeDecodeError:
            raise ValueError('Ciphertext contain illegal characters!', decrypted)

        return ';admin=true;' in decoded
```

Then, we detect the key using the described method:
```python
def detect_key(oracle: Oracle):
    # some ciphertext with at least 3 blocks
    ciphertext = oracle.encode(b'A' * 3 * AES_BLOCK_SIZE)
    ciphertext = bytearray(ciphertext)

    # modify ciphertext: C_1, C_2, C_3 -> C_1, 0, C_1
    ciphertext[AES_BLOCK_SIZE:2*AES_BLOCK_SIZE] = bytes([0]*AES_BLOCK_SIZE)
    ciphertext[2*AES_BLOCK_SIZE:3*AES_BLOCK_SIZE] = ciphertext[:AES_BLOCK_SIZE]

    # send modified ciphertext to oracle
    try:
        oracle.parse(ciphertext)
        raise Exception('detect_key failed')
    except ValueError as e:
        decrypted = e.args[1]

    # parse key: P'_1 XOR P'_3
    key = xor_bytes((decrypted[:AES_BLOCK_SIZE], decrypted[2*AES_BLOCK_SIZE:3*AES_BLOCK_SIZE]))
    return key
```

Finally, we check if the recovered key is valid:
```python
oracle = Oracle()
key = detect_key(oracle)

ciphertext = oracle.encode(b'cryptopals')
plaintext = aes_cbc_decrypt(ciphertext=ciphertext, key=key, nonce=key, remove_padding=True)
print(plaintext)

# b'comment1=cooking%20MCs;userdata=cryptopals;comment2=%20like%20a%20pound%20of%20bacon'
```


## Challenge 28 - Implement a SHA-1 keyed MAC

> Challenge: https://cryptopals.com/sets/4/challenges/28

We start by implementing SHA-1 (https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode)

```python
def SHA1(msg: bytes) -> bytes:
    # Initialize variables
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # message length in bits
    ml = len(msg) * 8

    # Pre-processing:
    # append the bit '1' to the message
    msg += bytes([0x80])

    # append bits '0' to match len of 448 (mod 512)
    pad_len = (448 // 8) - (len(msg) % (512 // 8))
    pad_len = (512 // 8) + pad_len if pad_len < 0 else pad_len
    msg += bytes(pad_len)

    # append ml, the original message length in bits, as a 64-bit big-endian integer.
    msg += ml.to_bytes(64 // 8, byteorder='big')

    # the total length is a multiple of 512 bits.
    assert (len(msg) % 64 == 0)

    # break message into 512-bit chunks
    for chunk_idx in range(0, len(msg), 64):
        chunk = msg[chunk_idx:chunk_idx + 64]

        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = [int.from_bytes(chunk[i:i + 4], 'big') for i in range(0, len(chunk), 4)]

        # extend the sixteen 32-bit words into eighty 32-bit words
        for i in range(16, 80):
            tmp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            tmp_shifted = circular_left_shit(num=tmp, shift=1)
            w.append(tmp_shifted)

        assert (len(w) == 80)

        # Initialize hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (circular_left_shit(num=a, shift=5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = circular_left_shit(num=b, shift=30)
            b = a
            a = temp

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian) as a 160-bit number
    hh = (struct.pack('>I', i) for i in [h0, h1, h2, h3, h4])
    hh = b''.join(hh)
    return hh
```

Now, the function to authenticate a message under a secret key:
```python
def sha1_mac(msg: bytes, key: bytes):
    return SHA1(key + msg)
```

And an example of usage:
```python
key = get_random_bytes(16)
msg = b"Don't cheat. It won't work."
digestion = sha1_mac(msg=msg, key=key)
print(digestion)  # b'\x0c\xddB\x045U\xf5GZ\xaab\x15\xac}\xa0\xbfbTZb'
```


## Challenge 29 - Break a SHA-1 keyed MAC using length extension

> Challenge: https://cryptopals.com/sets/4/challenges/29

We start by writing a function that computes the MD padding of an arbitrary message. 

The function logic is the same as the padding in SHA-1, except that it eccept the message length as input instead of the message itself:
```python
def md_padding(msg_len: int) -> bytes:
    # message length in bits
    ml = msg_len * 8

    # append the bit '1' to the message
    padding = bytes([0x80])

    # append bits '0' to match len of 448 (mod 512) bits
    pad_len = (448 // 8) - ((msg_len + len(padding)) % (512 // 8))
    pad_len = (512 // 8) + pad_len if pad_len < 0 else pad_len
    padding += bytes(pad_len)

    # append ml, the original message length in bits, as a 64-bit big-endian integer.
    padding += ml.to_bytes(64 // 8, byteorder='big')

    # the total length is a multiple of 512 bits (64 bytes)
    assert ((msg_len + len(padding)) % 64 == 0)

    return padding
```

Now, we can forge the MAC according to `new_msg` of our choice.

- We start by restoring the SHA-1 state:

    `h0, h1, h2, h3, h4 = [struct.unpack('>I', org_mac[i:i + 4])[0] for i in range(0, 20, 4)]`

- Then, we build the final message using the "glue-padding" we retrieve from md_padding:

    `final_msg = org_msg + padding + new_msg`

- And finally we generate the new MAC using the SHA-1 state and the final message length:

    `fake_len = len(final_msg) + key_len`
    
    `forged_mac = SHA1(new_msg, h0=h0, h1=h1, h2=h2, h3=h3, h4=h4, force_len=fake_len)`

We pack these actions in an **attack** function:
```python
def attack(org_msg: bytes, org_mac: bytes, new_msg: bytes, key_len: int):
    # unpack sha1 state
    h0, h1, h2, h3, h4 = [struct.unpack('>I', org_mac[i:i + 4])[0] for i in range(0, 20, 4)]

    # build final message
    msg_len = key_len + len(org_msg)
    padding = md_padding(msg_len)
    final_msg = org_msg + padding + new_msg

    # build new hash
    fake_len = len(final_msg) + key_len
    forged_mac = SHA1(new_msg, h0=h0, h1=h1, h2=h2, h3=h3, h4=h4, force_len=fake_len)

    return final_msg, forged_mac
```

To check if it works, we evaluate the SHA-1 MAC of the msg:
```python
# create SHA-1 keyed MAC on original message
key = get_random_bytes(16)
msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
mac = sha1_mac(msg=msg, key=key)
print(f'{mac=}')  # mac=b'Gw\xe06k Z\x1e^G\x00\xef\xc7\xe8V\xe7=\xbe\x1b\xe6'
```

Then, We guess the key length (16), and generate [forged_mac] using our **attack** function:
```python
# generate fake SHA-1 keyed MAC
key_len = 16
new_msg = b";admin=true"
final_msg, forged_mac = attack(org_msg=msg, org_mac=mac, new_msg=new_msg, key_len=key_len)
print(f'{final_msg=}')  # final_msg=b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon\x80\x00\x00\x00\x ... \x00\x00\x00\x00\x02\xe8;admin=true'
print(f'{forged_mac=}')  # forged_mac=b'\xdfk(\t\x02Cpv3\xce}\xa3>\xfd\x89\xdd\x89\xb0J\x92'
```

To validate [forged_mac], we recompute SHA-1 MAC on [final_msg] with the original key, and compare the MAC result:
```python
# check for [forged_mac] validity
new_mac = sha1_mac(msg=final_msg, key=key)
print(forged_mac == new_mac)  # True
```



## Challenge 30 - Break an MD4 keyed MAC using length extension

> Challenge: https://cryptopals.com/sets/4/challenges/30

We take MD4 base implementation from [here](https://gist.github.com/kangtastic/c3349fc4f9d659ee362b12d7d8c639b6) and modify to our needs:

```python
class MD4:
    """
    An implementation of the MD4 hash algorithm.
    Taken from https://gist.github.com/kangtastic/c3349fc4f9d659ee362b12d7d8c639b6
    """

    width = 32
    mask = 0xFFFFFFFF

    @staticmethod
    def process(msg, h=None, force_len=None) -> bytes:
        if h is None:
            h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

        # message length in bits
        if force_len is None:
            ml = len(msg) * 8
        else:
            ml = force_len * 8

        # Pre-processing: Total length is a multiple of 512 bits.
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)

        # Process the message in successive 512-bit chunks.
        chunks = [msg[i: i + 64] for i in range(0, len(msg), 64)]
        for chunk in chunks:
            X, h_tmp = list(struct.unpack("<16I", chunk)), h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h_tmp[i] + MD4.F(h_tmp[j], h_tmp[k], h_tmp[l]) + X[K]
                h_tmp[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h_tmp[i] + MD4.G(h_tmp[j], h_tmp[k], h_tmp[l]) + X[K] + 0x5A827999
                h_tmp[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h_tmp[i] + MD4.H(h_tmp[j], h_tmp[k], h_tmp[l]) + X[K] + 0x6ED9EBA1
                h_tmp[i] = MD4.lrot(hn & MD4.mask, S)

            h = [((v + n) & MD4.mask) for v, n in zip(h, h_tmp)]

        return struct.pack("<4L", *h)

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits
```

We create `md4_mac` the same as in challenge 28:
```python
def md4_mac(msg: bytes, key: bytes):
    return MD4.process(key + msg)
```

Then, we create the **atack** function:
```python
def attack(org_msg: bytes, org_mac: bytes, new_msg: bytes, key_len: int):
    # unpack sha1 state
    h = [*struct.unpack('<4L', org_mac)]

    # build final message
    msg_len = key_len + len(org_msg)
    padding = md_padding(msg_len)
    final_msg = org_msg + padding + new_msg

    # build new hash
    fake_len = len(final_msg) + key_len
    forged_mac = MD4.process(new_msg, h=h, force_len=fake_len)

    return final_msg, forged_mac
```

And verify correctness:
```python
# create MD4 keyed MAC on original message
key = get_random_bytes(16)
msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
mac = md4_mac(msg=msg, key=key)
print(f'{mac=}')  # mac=b'\xa9+g:\xd2"\xb7&\xb7\xbbG\x85\xban\x9a\x14'

# generate fake MD4 keyed MAC
key_len = 16
new_msg = b";admin=true"
final_msg, forged_mac = attack(org_msg=msg, org_mac=mac, new_msg=new_msg, key_len=key_len)
print(f'{final_msg=}')  # final_msg=b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon\x80\x00\x00\x ... \x00\x00;admin=true'
print(f'{forged_mac=}')  # forged_mac=b'\xb3\x8c\xfaBk\xff\x84\xc8t\xc6\nC\x92\x0f\x7fj'

# check for [forged_mac] validity
new_mac = md4_mac(msg=final_msg, key=key)
print(forged_mac == new_mac)  # True
```



## Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak

> Challenge: https://cryptopals.com/sets/4/challenges/31