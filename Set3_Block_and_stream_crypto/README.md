

# Set 3: Block & stream crypto

## Table of contents
17. [Challenge 17 - The CBC padding oracle](#challenge-17---the-cbc-padding-oracle)
18. [Challenge 18 - Implement CTR, the stream cipher mode](#challenge-18---implement-ctr-the-stream-cipher-mode)
19. [Challenge 19 - Break fixed-nonce CTR mode using substitutions](#challenge-19---break-fixed-nonce-ctr-mode-using-substitutions)
20. [Challenge 20 - Break fixed-nonce CTR statistically](#challenge-20---break-fixed-nonce-ctr-statistically)
21. [Challenge 21 - Implement the MT19937 Mersenne Twister RNG](#challenge-21---implement-the-mt19937-mersenne-twister-rng)
22. [Challenge 22 - Crack an MT19937 seed](#challenge-22---crack-an-mt19937-seed)
23. [Challenge 23 - Clone an MT19937 RNG from its output](#challenge-23---clone-an-mt19937-rng-from-its-output)
24. [Challenge 24 - Create the MT19937 stream cipher and break it](#challenge-24---create-the-mt19937-stream-cipher-and-break-it)



## Challenge 17 - The CBC padding oracle

> Challenge: https://cryptopals.com/sets/3/challenges/17

We start by implementing two functions: 
The first one chooses a random string from the list, encrypts it, and returns the result to the user.
The second one receives ciphertext from the user, decrypts it, and returns whether it has valid padding.
```python
class Oracle:  
	def __init__(self):  
		self.key = get_random_bytes(AES_BLOCK_SIZE)  
		self.nonce = get_random_bytes(AES_BLOCK_SIZE)  
		self.data = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',  
		b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',  
		b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',  
		b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',  
		b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',  
		b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',  
		b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',  
		b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',  
		b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',  
		b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']  

	def encrypt(self) -> tuple[bytes, bytes]:  
		# select rand string  
		plaintext = random.choice(self.data)
		# pad and encrypt  
		ciphertext = aes_cbc_encrypt(plaintext, key=self.key, nonce=self.nonce, add_padding=True)  
		return ciphertext, self.nonce  

	def decrypt(self, ciphertext: bytes) -> bool:  
		try:  
			aes_cbc_decrypt(ciphertext, key=self.key, nonce=self.nonce, remove_padding=True)  
			return True  
		except ValueError:  
			return False
```

So how can we decrypt the ciphertext produced by the oracle??
Let's take a look again at the CBC decryption scheme. We know that each plaintext block, denoted by $p_i$, is generated by: $$p_i=c_{i-1}+D(c_i)$$ 
We already know the ciphertext ($c_i$), so if we were able to detect $D(c_i)$ for each block, we would be able able to break the encryption. 
Luckily, **oracle.decrypt()** let us to do just that! Think about $D(c_i)$ as a mask, denoted by  $M_i$.  We can evaluate the values of $M_i$ one at a time from end to start. The function **oracle.decrypt()** tells us if the input blocks have valid padding, and we know the padding values. So, for each byte of $p_i$, we can iterate the possible byte values of the corresponding byte of $c_{i-1}$ until we detect valid padding. Then, we know the corresponding byte of $M_i$, has the value of the detected value XORed with the padding value.

We write a function that decrypts the mask $M_i$ of each block:
```python
def decrypt_block_mask(oracle: Oracle, current_block: bytes) -> bytes:  
	# initialize empty mask  
	mask = bytearray(AES_BLOCK_SIZE)  

	# decrypt byte at a time from end to start  
	for byte_idx in range(AES_BLOCK_SIZE-1, -1, -1):  
		# build the previous block  
		pad_value = AES_BLOCK_SIZE - byte_idx  
		last_block = bytearray(xor_bytes((bytes([pad_value] * AES_BLOCK_SIZE), mask)))  

		# iterate values until the padding is correct  
		for byte_val in range(2**8):  
			last_block[byte_idx] = byte_val  
			sequence = last_block + current_block  
			# stop when the padding is correct  
			if oracle.decrypt(sequence):  
				# we know the plaintext byte value, so we calc the mask byte value  
				mask[byte_idx] = byte_val ^ pad_value  
				break  

	return mask
```

And another function that evaluates the mask values of each block, and deciphers the whole stream:
```python
def padding_attack(oracle: Oracle, ciphertext: bytes, iv: bytes) -> bytes:  
	# verify input  
	if len(ciphertext) % AES_BLOCK_SIZE:  
		raise ValueError('ciphertext doesnt have proper padding')  

	plaintext = bytes()  
	last_block = iv  
	for block_loc in range(0, len(ciphertext), AES_BLOCK_SIZE):  
		# decrypt current block  
		current_block = ciphertext[block_loc:block_loc+AES_BLOCK_SIZE]  
		mask = decrypt_block_mask(oracle, current_block)  
		plaintext += xor_bytes((last_block, mask))  

		# update last block for next iteration  
		last_block = current_block  

	# remove padding and return  
	return pkcs7_unpad(plaintext, AES_BLOCK_SIZE)
```

Finally, we can check if it works:
```python
oracle = Oracle()  
for _ in range(100):  
	ciphertext, iv = oracle.encrypt()  
	plaintext = padding_attack(oracle, ciphertext, iv)  
	assert plaintext in oracle.data  
  
print('All tests passed successfully')
```


## Challenge 18 - Implement CTR, the stream cipher mode

> Challenge: https://cryptopals.com/sets/3/challenges/18

Notice that in CTR mode, the encryption and decryption are the same operation. So, we implement a function **generate_key_stream** and xor its result against the input:
```python
class AesCtr:  
	def __init__(self, key: bytes, nonce: bytes = None, byteorder: Literal["little", "big"] = "little"):  
		# verify input  
		if byteorder not in ["big", "little"]:  
			raise ValueError('byteorder must be "big" or "little"')  

		if nonce is None:  
			self.nonce = random.randbytes(8)  
		else:  
			self.nonce = nonce  

		# init vals  
		self.key = key  
		self.byteorder = byteorder  
		self.cipher_obj = AES.new(self.key, AES.MODE_ECB)  

	def generate_key_stream(self, input_len: int) -> bytes:  
		key_stream = bytes()  
		counter = 0  
		for _ in range(math.ceil(input_len / AES.block_size)):  
			# create and encrypt counter block  
			counter_block = self.nonce + counter.to_bytes(AES.block_size // 2, byteorder=self.byteorder)  
			key_stream += self.cipher_obj.encrypt(counter_block)  

			# update for next block  
			counter += 1  

		# trim and return  
		key_stream = key_stream[:input_len]  
		return key_stream  

	def encrypt(self, plaintext: bytes) -> bytes:  
		key_stream = self.generate_key_stream(len(plaintext))  
		ciphertext = xor_bytes((plaintext, key_stream))  
		return ciphertext  

	def decrypt(self, ciphertext: bytes) -> bytes:  
		key_stream = self.generate_key_stream(len(ciphertext))  
		plaintext = xor_bytes((ciphertext, key_stream))  
		return plaintext
```

And decrypt the given string:
```python
ciphertext = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')  
  
aes_ctr = AesCtr(b'YELLOW SUBMARINE', nonce=bytes(8), byteorder='little')  
plaintext = aes_ctr.decrypt(ciphertext)  
print(plaintext)
# b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
```


## Challenge 19 - Break fixed-nonce CTR mode using substitutions

> Challenge: https://cryptopals.com/sets/3/challenges/19

As mentioned in the challenge, because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. Therefore, we can use the method of **challenge 6 - Break repeating-key XOR** and decrypt the ciphertexts.
We start with transposing the streams, such that each new stream is a *Single-byte XOR cipher*:
```python 
def transpose_streams(streams: list[bytes]) -> list[bytes]:  
	"""  
	Transpose the streams: make a stream that is the first byte of every stream, 
	and a stream that is the second byte of every stream, 
	and so on... 
	"""  
	max_len = max(map(len, streams))  
	out_streams = [bytes() for _ in range(max_len)]  
	for stream in streams:  
		for idx, i in enumerate(stream):  
			out_streams[idx] += bytes([i])  

	return out_streams
```

Then, we can break each *Single-byte XOR cipher* and build the key stream:
```python
def detect_key_stream(streams: list[bytes]) -> bytes:  
	inv_stream = transpose_streams(streams)  
	# each stream is a single-character XOR cipher  
	# we detect it, to build the key stream  
	key_stream = bytes(map(decode_single_byte_xor_cypher, inv_stream))  
	return key_stream
```

And combining it all together:
```python
# encrypt all the lines with the same nonce  
key = get_random_bytes(AES_BLOCK_SIZE)  
aes_ctr = AesCtr(key=key, nonce=bytes(8), byteorder='little')  
strings_enc = list(map(aes_ctr.encrypt, strings))  

# detect key stream  
key_stream = detect_key_stream(strings_enc)  

# decrypt the strings  
for stream in strings_enc:  
	key_stream_trimmed = key_stream[:len(stream)]  
	decrypted_string = xor_bytes((stream, key_stream_trimmed))  
	print(decrypted_string)

# b'I have met them at close of dac'
# b'Coming with vivid faces'
# b'From counter or desk among grec'
# b'Eighteenth-century houses.'
# b'I have passed with a nod of th\x7f h 46'
# b'Or polite meaningless words,'
# b'Or have lingered awhile and sasd'
# b'Polite meaningless words,'
# b'And thought before I had done'
# b'Of a mocking tale or a gibe'
# b'To please a companion'
# b'Around the fire at the club,'
# b'Being certain that they and I'
# b'But lived where motley is worn '
# b'All changed, changed utterly:'
# b'A terrible beauty is born.'
# b"That woman's days were spent"
# b'In ignorant good will,'
# b'Her nights in argument'
# b'Until her voice grew shrill.'
# b'What voice more sweet than heri'
# b'When young and beautiful,'
# b'She rode to harriers?'
# b'This man had kept a school'
# b'And rode our winged horse.'
# b'This other his helper and frietd'
# b'Was coming into his force;'
# b'He might have won fame in the \x7fndi'
# b'So sensitive his nature seemed6'
# b'So daring and sweet his thoughn.'
# b'This other man I had dreamed'
# b'A drunken, vain-glorious lout.'
# b'He had done most bitter wrong'
# b'To some who are near my heart,'
# b'Yet I number him in the song;'
# b'He, too, has resigned his part'
# b'In the casual comedy;'
# b'He, too, has been changed in hss 1    '
# b'Transformed utterly:'
# b'A terrible beauty is born.'
```

Note that because we have less information about the end of the long sentences, their decryption is a little messed up.

## Challenge 20 - Break fixed-nonce CTR statistically

> Challenge: https://cryptopals.com/sets/3/challenges/20

We solve this challenge the same as the last one:
```python
# load file and base64 decode  
with open('20.txt', 'r') as fh:  
	lines = fh.readlines()  
strings = list(map(base64.b64decode, lines))  

# encrypt all the lines with the same nonce  
key = get_random_bytes(AES_BLOCK_SIZE)  
aes_ctr = AesCtr(key=key, nonce=bytes(8), byteorder='little')  
strings_enc = list(map(aes_ctr.encrypt, strings))  

# detect key stream  
key_stream = break_fixed_nonce_ctr_statistically(strings_enc)  

# decrypt the strings  
for stream in strings_enc:  
	stream = stream[:len(key_stream)]  
	decrypted_string = xor_bytes((stream, key_stream))  
	print(decrypted_string)
```

## Challenge 21 - Implement the MT19937 Mersenne Twister RNG

> Challenge: https://cryptopals.com/sets/3/challenges/21

We use the pseudocode from [Wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister):
```python
class MT19937:  
	# The coefficients of MT19937  
	(w, n, m, r) = (32, 624, 397, 31)  
	a = 0x9908B0DF  
	(u, d) = (11, 0xFFFFFFFF)  
	(s, b) = (7, 0x9D2C5680)  
	(t, c) = (15, 0xEFC60000)  
	l = 18  
	f = 1812433253  

	# Create masks  
	w_bit_mask = (1 << w) - 1  
	lower_mask = (1 << r) - 1  
	upper_mask = w_bit_mask & ~lower_mask  

	def __init__(self, seed: int = 5489):  
		self.MT = self.seed_mt(seed)  
		self.index = self.n  

	def __iter__(self):  
		""" Extract a tempered value based on MT[index] """  
		while True:  
			# calling twist() every n numbers  
			if self.index == self.n:  
				self.twist()  

			# calc next value  
			y = self.MT[self.index]  
			y = y ^ ((y >> self.u) & self.d)  
			y = y ^ ((y << self.s) & self.b)  
			y = y ^ ((y << self.t) & self.c)  
			y = y ^ (y >> self.l)  

			self.index += 1  
			yield self.w_bit_mask & y  

	@classmethod  
	def seed_mt(cls, seed: int) -> list[int]:  
		""" Initialize the generator from a seed """  
		# MT[0] := seed  
		MT = [seed]  
		for i in range(1, cls.n):  
			# MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)  
			MT.append(cls.w_bit_mask & (cls.f * (MT[i-1] ^ (MT[i-1] >> (cls.w-2))) + i))  

		return MT  

	def twist(self):  
		""" Generate the next n values from the series x_i """  
		for i in range(self.n):  
			x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)  
			xA = x >> 1  
			if x % 2 != 0: # lowest bit of x is 1  
				xA = xA ^ self.a  
			self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA  

		self.index = 0
```

and print some random values:
```python
rng = iter(MT19937(seed=54325))  
print(next(rng))  # 2094164258
print(next(rng))  # 3111452682
print(next(rng))  # 2470966426
```


## Challenge 22 - Crack an MT19937 seed

> Challenge: https://cryptopals.com/sets/3/challenges/22

We create a routine function that:
- Sleeps a few seconds (random between 40 and 1000),
- Picks a seed value based on the current time,
- Sleeps a few more random seconds,
- Returns the first 32-bit output generated by MT19937 with the chosen seed.
```python
def generate_rand() -> tuple[int, int]:  
	# sleep a random seconds between 40 and 1000.  
	time.sleep(random.randint(40, 1000))  
	seed = round(time.time())  

	# generate rng  
	rng = iter(MT19937(seed=seed))  
	time.sleep(random.randint(10, 40))  

	# return first 32 bit  
	return next(rng), seed
```

We need to recover the seed value based on the 32-bit result. 
A simple brute-force approach will probably take too much time (there are 2^32 possible seed values).
Remember that the seed value is not random and is chosen based on the time of execution. We don't know its exact running time, but we can estimate its value and narrow down our search:
```python
def crack_mt19937_seed(rand_val: int) -> int:  
	# initial value  
	seed_value = round(time.time())  
	while True:  
		res = next(iter(MT19937(seed_value)))  
		if res == rand_val:  
			return seed_value  
		seed_value = (seed_value - 1) % (2 ** 32)
```

And check the results:
```python
rand_val, true_seed = generate_rand()  
detected_seed = crack_mt19937_seed(rand_val)  
print(f'{detected_seed=}')  # 1658083938
print(detected_seed == true_seed)  # True
```


## Challenge 23 - Clone an MT19937 RNG from its output

> Challenge: https://cryptopals.com/sets/3/challenges/23

We start with the "untemper" function, which ought to inverse the following operation:
```python
# Gloabls
(u, d) = (11, 0xFFFFFFFF)  
(s, b) = (7, 0x9D2C5680)  
(t, c) = (15, 0xEFC60000)
l = 18

# tempering operation
y = y ^ ((y >> u) & d)  
y = y ^ ((y << s) & b)  
y = y ^ ((y << t) & c)  
y = y ^ (y >> l)
```

There are two operations we need to undo:
The first one is: XOR against a right-shifted value.
Take a look at the bits output of this operation with shift = 11
```
src = |31|30|...|0|
out = |31|...|21||20^31||19^30|...|0^11|
```
To undo the right-shift operation, we can loop from MSB to LSB and correct each bit at a time:
```python
def invert_right(x: int, shift: int) -> int:  
	out = int_2_list(x)  
	for idx in range(shift, 32):  
		out[idx] = out[idx] ^ out[idx - shift]  
	return list_2_int(out)
```

The second one is: XOR against a left-shifted value AND'd with a magic number.
Take a look at the bits output of this operation with shift = 7
```
src = |31|30|...|0|
mask = |m31|m30|...|m0|
out = |31^(24&m31)|...|8^(1&m8)|7^(0&m7)||6|...|2|1|0|
```
To undo the left-shift-mask operation, we can loop from LSB to MSB and correct each bit at a time using the mask values:
```python
def invert_left_mask(x: int, shift: int, mask: int) -> int:  
	mask = int_2_list(mask)  
	out = int_2_list(x)  
	for idx in range(32-shift-1, -1, -1):  
		out[idx] = out[idx] ^ (out[idx+shift] & mask[idx])  

	return list_2_int(out)
```

Combining these two operations we create the untempering function:
```python
def untempter(y: int) -> int:  
	"""  
	Takes an MT19937 output, 
	and transforms it back into the corresponding element of the MT19937 state array. 
	"""  
	y = invert_right(y, l)  
	y = invert_left_mask(y, t, c)  
	y = invert_left_mask(y, s, b)  
	y = invert_right(y, u)  
	return y
```

Next, we create the function **clone_mt19937** which determines the state using the **untemper** function and returns MT19937 object.
```python
def clone_mt19937(rng):  
	# determine state  
	state = []  
	for i in range(n):  
		state.append(untempter(next(rng)))  

	# clone MT19937 using state  
	return MT19937().init_from_state(state)
```

And check if it works:
```python
seed = random.randint(0, 2**32-1)  
rng = iter(MT19937(seed))  
cloned_rng = iter(clone_mt19937(rng))  
  
for _ in range(20000):  
	assert next(cloned_rng) == next(rng)
```


## Challenge 24 - Create the MT19937 stream cipher and break it

> Challenge: https://cryptopals.com/sets/3/challenges/24

Start with implementing the MT19937 stream cipher:
```python
class MT19937Cipher:  
	def __init__(self, seed: int):  
		# verify input  
		if seed > (2**16 - 1):  
			raise ValueError('seed value exceeds 16 bits')  

		self.seed = seed  

	def generate_key_stream(self, input_len: int) -> bytes:  
		# number of 4-bytes number to generate  
		num_words = math.ceil(input_len / 4)  

		# generate random sequence  
		key_stream_gen = (i.to_bytes(4, byteorder='little') for i in MT19937(seed=self.seed, length=num_words))  
		key_stream = b''.join(key_stream_gen)  

		# trim and return  
		key_stream = key_stream[:input_len]  
		return key_stream  

	def encrypt(self, plaintext: bytes) -> bytes:  
		key_stream = self.generate_key_stream(len(plaintext))  
		ciphertext = xor_bytes((plaintext, key_stream))  
		return ciphertext  

	def decrypt(self, ciphertext: bytes) -> bytes:  
		key_stream = self.generate_key_stream(len(ciphertext))  
		plaintext = xor_bytes((ciphertext, key_stream))  
		return plaintext
```

The seed has only 16 bits, and consequently a simple brute-force attack will suffice:
```python
def detect_seed(ciphertext: bytes, known_plaintext: bytes) -> int:  
	""" Brute force all 16-bit seed possibilities"""  
	for seed in range(2**16):  
		cipher_obj = MT19937Cipher(seed=seed)  
		decryption = cipher_obj.decrypt(ciphertext)  
		if known_plaintext in decryption:  
			return seed
```

And test the flow:
```python
# Randomize key  
key = random.getrandbits(16)  
cipher_obj = MT19937Cipher(seed=key)  
  
# Generate input  
prefix = get_random_bytes(random.randrange(5, 15))  
plaintext = b'A' * 14  
ciphertext = cipher_obj.encrypt(prefix + plaintext)  
  
# Recover seed  
detected_seed = detect_seed(ciphertext, b'A'*14)  
print(detected_seed == key) # True
```