
# Set 4: Stream crypto and randomness

## Table of contents
25. [Challenge 25 - Break "random access read/write" AES CTR](#challenge-25---break-random-access-readwrite-aes-ctr)
26. [Challenge 26 - CTR bitflipping](#challenge-26---ctr-bitflipping)
27.  [Challenge 27 - Recover the key from CBC with IV=Key](#challenge-27---recover-the-key-from-cbc-with-ivkey)





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

