
# Set 2: Block crypto

## Table of contents
9. [Challenge 9 - Implement PKCS#7 padding](#challenge-9---implement-pkcs7-padding)
10. [Challenge 10 - Implement CBC mode](#challenge-10---implement-cbc-mode)
11. [Challenge 11 - An ECB/CBC detection oracle](#challenge-11---an-ecbcbc-detection-oracle)
12. [Challenge 12 - Byte-at-a-time ECB decryption (Simple)](#challenge-12---byte-at-a-time-ecb-decryption-simple)
13. [Challenge 13 - ECB cut-and-paste](#challenge-13---ecb-cut-and-paste)
14. [Challenge 14 - Byte-at-a-time ECB decryption (Harder)](#challenge-14---byte-at-a-time-ecb-decryption-harder)
15. [Challenge 15 - PKCS#7 padding validation](#challenge-15---pkcs7-padding-validation)
16. [Challenge 16 - CBC bitflipping attacks](#challenge-16---cbc-bitflipping-attacks)


## Challenge 9 - Implement PKCS#7 padding

> Challenge: https://cryptopals.com/sets/2/challenges/9

We simply calc how many bytes are missing and append them to the end of the stream:
```python
def pkcs7_pad(stream: bytes, block_size: int) -> bytes:  
  pad_len = block_size - (len(stream) % block_size)  
  return stream + bytes([pad_len] * pad_len)
```
```python
src = b"YELLOW SUBMARINE"  
target = b"YELLOW SUBMARINE\x04\x04\x04\x04"  
  
result = pkcs7_pad(src, 20)  
print(result == target)
```

## Challenge 10 - Implement CBC mode

> Challenge: https://cryptopals.com/sets/2/challenges/10

We implement AES CBC encryption as described: each ciphertext block is added to the next plaintext block before the next call to the cipher core.
```python
def aes_cbc_encrypt(plaintext: bytes, key: bytes, nonce: bytes = bytes(AES_BLOCK_SIZE)) -> bytes:  
	# verify input  
	if len(nonce) != AES_BLOCK_SIZE:  
		raise ValueError(f"Nonce must be of size {AES_BLOCK_SIZE}")  
	if len(plaintext) % AES_BLOCK_SIZE != 0:  
		raise ValueError(f"plaintext length must be a multiply of the block size")  

	# create AES ECB mode object  
	cipher_obj = AES.new(key, AES.MODE_ECB)  

	# loop blocks to generate cipher  
	prev_iv = nonce  
	cipher = bytes()  
	for i in range(0, len(plaintext), AES_BLOCK_SIZE):  
		# extract block and XOR with last ciphertext block  
		extracted_block = plaintext[i:i+AES_BLOCK_SIZE]  
		extracted_block = xor_bytes(extracted_block, prev_iv)  
		encrypted_block = cipher_obj.encrypt(extracted_block)  
		cipher += encrypted_block  

		# update prev block  
		prev_iv = encrypted_block  

	return cipher
```

AES CBC decryption in the inverse operation: after the ECB decryption of each block, we add the ciphertext of last block.
```python
def aes_cbc_decrypt(ciphertext: bytes, key: bytes, nonce: bytes = bytes(AES_BLOCK_SIZE)) -> bytes:  
	# verify input  
	if len(nonce) != AES_BLOCK_SIZE:  
		raise ValueError(f"Nonce must be of size {AES_BLOCK_SIZE}")  
	if len(ciphertext) % AES_BLOCK_SIZE != 0:  
		raise ValueError(f"ciphertext must have length multiple of the block size")  

	# create AES ECB mode object  
	cipher_obj = AES.new(key, AES.MODE_ECB)  

	# loop blocks to generate cipher  
	prev_iv = nonce  
	plaintext = bytes()  
	for i in range(0, len(ciphertext), AES_BLOCK_SIZE):  
		# extract block, decrypt and XOR with last plaintext block  
		extracted_block = ciphertext[i:i+AES_BLOCK_SIZE]  
		plaintext_block = cipher_obj.decrypt(extracted_block)  
		plaintext_block = xor_bytes(plaintext_block, prev_iv)  
		plaintext += plaintext_block  

		# update prev block  
		prev_iv = extracted_block  

	return plaintext
```

Now we can check the decryption of the given file:
```python
# load cipher and decode base64 to bytes  
with open('10.txt', 'r') as fh:  
	ciphertext = base64.b64decode(fh.read())  
  
key = b"YELLOW SUBMARINE"  
plaintext = aes_cbc_decrypt(ciphertext=ciphertext, key=key)  
print(f'{plaintext=}')
# plaintext=b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
```

## Challenge 11 - An ECB/CBC detection oracle

> Challenge: https://cryptopals.com/sets/2/challenges/11

To generate a random AES key, we use **Crypto.Random.get_random_bytes** for cryptographic secure random.
```python
from Crypto.Random import get_random_bytes

def gen_rand_aes_key():  
	return get_random_bytes(AES_BLOCK_SIZE)
```

The function that randomly generates ECB/CBC cipher:
```python
def encryption_oracle(plaintext: bytes) -> tuple[bytes, str]:  
	# generates a random key  
	key = gen_rand_aes_key()  

	# append 5-10 bytes before and after the plaintext  
	pad_before = get_random_bytes(random.randint(5, 10))  
	pad_after = get_random_bytes(random.randint(5, 10))  
	plaintext = pad_before + plaintext + pad_after  
	plaintext = PKCS7_pad(plaintext, AES_BLOCK_SIZE)  

	if random.random() < 0.5:  
		# encrypt with ECB mode  
		cipher_obj = AES.new(key, AES.MODE_ECB)  
		ciphertext = cipher_obj.encrypt(plaintext)  
		return ciphertext, 'ECB'  

	else:  
		# encrypt with CBC mode  
		nonce = get_random_bytes(AES_BLOCK_SIZE)  
		ciphertext = aes_cbc_encrypt(plaintext, key, nonce)  
		return ciphertext, 'CBC'
```

Now, we have the black box **encryption_oracle** and we need to be able to detect the cipher mode of the function.

Remember that in ECB mode, the same input has the same output. So if we create two identical input blocks, and get two identical output blocks, the mode has to be ECB. 
We define a function that counts repeating blocks and predicts the encryption mode:
```python
def detect_encryption_mode(cipher: bytes):  
	# split cipher to blocks  
	blocks = [cipher[i:i + AES_BLOCK_SIZE] for i in range(0, len(cipher), AES_BLOCK_SIZE)]  

	# evaluate number of repeating blocks  
	repetitions = len(blocks) - len(set(blocks))  

	if repetitions > 0:  
		return 'ECB'  
	else:  
		return 'CBC'
```

The encryption function adds random padding before our input stream. Consequently, our input blocks won't necessarily align with the ECB blocks. To deal with that, we set the input to be 3 following identical blocks. That way, each division to ECB blocks will result in at least 2 identical following blocks.
To verify our prediction, we return on the following experiment many times:
```python
plaintext = bytes(AES_BLOCK_SIZE) * 3  
cipher, real_mode = encryption_oracle(plaintext)  
predicted_mode = detect_encryption_mode(cipher)  
print(real_mode == predicted_mode)
```

## Challenge 12 - Byte-at-a-time ECB decryption (Simple)

> Challenge: https://cryptopals.com/sets/2/challenges/12

First, we update the encryption oracle:
```python
def encryption_oracle(plaintext: bytes) -> bytes:  
	unknown_string = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
	"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
	"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
	"YnkK")  
	plaintext = plaintext + unknown_string  
	plaintext = PKCS7_pad(plaintext, AES_BLOCK_SIZE)  

	# encrypt with ECB mode  
	cipher_obj = AES.new(KEY, AES.MODE_ECB)  
	ciphertext = cipher_obj.encrypt(plaintext)  
	return ciphertext
```

1) Discover the block size of the cipher:
We can utilize the fact that before encryption the stream must be padded to match the block size length. So, to determine this block size, we can change the input length, and look for a jump in the output length. This jump size will match the block size:
```python
def detect_block_size() -> int:  
	max_block_size = 100  
	base_len = len(encryption_oracle(b''))  
	for i in range(1, max_block_size):  
		plaintext = b'A' * i  
		new_len = len(encryption_oracle(plaintext))  
		if new_len != base_len:  
			return new_len - base_len  

	raise StopIteration('Max block size exceeded')
```

2) Detect that the function is using ECB:
We can use the function **detect_encryption_mode** from last challenge:
```python
mode = detect_encryption_mode(encryption_oracle(b'1'*50))
```

3) Detect message length: the encryption oracle pad the stream using PKCS#7. We want to be able to extract the message itself without the padding. One way is to determine the length of the padding like we did in **detect_block_size**:
```python
def detect_msg_length(block_size: int) -> int:  
	# check how much we can pad before the output length jump  
	base_len = len(encryption_oracle(b''))  
	for i in range(block_size+1):  
		tmp_len = len(encryption_oracle(b'A'*i))  
		if tmp_len > base_len:  
			# the padding we added indicates the padding of base_len  
			return base_len - i
```

4) Decrypt the cipher: we decrypt one byte at a time (256 possibilities) using a brute-force approach. 
Remember that AES encryption acts on blocks the size of 16 bytes, so to decrypt each byte at a time, we need to know 15 bytes of the block and brute-force the remaining one. This can be done by padding the start of the stream, such that in each iteration, only one unknown byte is shifted into our observable block.
We create a function for brute-forcing the last byte in the block:
```python
def detect_single_byte(ref_block: bytes, padding: bytes, block_size: int) -> int:  
	# verify inputs  
	if len(ref_block) % block_size != 0:  
		raise ValueError('ref_block length error')  
	if (len(padding) + 1) % block_size != 0:  
		raise ValueError('padding length error')  

	# look for correct single byte  
	for i in range(2 ** 8):  
		guess_block = padding + bytes([i])  
		res = encryption_oracle(guess_block)  
		res = res[:block_size]  

		if res == ref_block:  
			return i  

	raise StopIteration('None of the bytes matched')
```

And another function to loop in the cipher bytes, and decrypt each byte at a time:
```python
def decrypt_ecb():  
	# detect basic params  
	block_size = detect_block_size()  
	msg_len = detect_msg_length(block_size)  
	mode = detect_encryption_mode(encryption_oracle(b'1' * 50))  
	print(f"{mode} detected.")  

	# decrypt hidden cipher  
	plaintext = b'A' * (block_size - 1)  

	for i in range(msg_len):  
		# create reference block  
		pad_len = (block_size - i - 1) % block_size  
		ref_block = encryption_oracle(b'A' * pad_len)  
		ref_block_idx = i - (i % block_size)  
		ref_block = ref_block[ref_block_idx: ref_block_idx + block_size]  

		# detect single byte  
		padding = plaintext[-block_size+1:]  
		new_byte = detect_single_byte(ref_block, padding, block_size)  
		plaintext += bytes([new_byte])  

	# remove initial padding and return  
	return plaintext[block_size-1:]
```

Finally we can check the results:
```python
plaintext = decrypt_ecb()  
print(plaintext)
# b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
```

***Note that the same approach can be used to decrypt AES-CBC mode.***  
You can check it out in **"challenge_12_cbc.py"**

## Challenge 13 - ECB cut-and-paste

> Challenge: https://cryptopals.com/sets/2/challenges/13

We start by creating **UserProfiler** which has two functionalities: 
1. It allows the user to enter his **user_mail**. Then, the profiler generates a profile expression, encrypts it, and returns the result.
2. It allows the user to enter his **encrypted profile**. Then, the profiler decrypts the profile and parses it to extract its contents.

```python
class UserProfile:  
	def __init__(self):  
		self.key = get_random_bytes(AES_BLOCK_SIZE)  

	@staticmethod  
	def key_val_parser(expression: str) -> dict:  
		parsed = {}  
		# split to key,val pairs  
		for pair in expression.split('&'):  
			# split to key and val  
			key, val = pair.split('=')  
			parsed[key] = val  

		return parsed  

	@staticmethod  
	def profile_for(user_mail: str) -> str:  
		# remove illegal characters  
		user_mail = user_mail.replace('&', '').replace('=', '')  
		# build expression  
		expr = f'mail={user_mail}&uid=10&role=user'  
		return expr  

	def get_user_profile(self, user_mail: str) -> bytes:  
		# get expression  
		expr = self.profile_for(user_mail)  
		expr = expr.encode('ascii')  

		# encrypt the profile and send 
		cipher = aes_ecb_encrypt(expr, self.key)  
		return cipher  

	def set_user_profile(self, cipher: bytes):  
		# decrypt and decode the received profile
		plaintext = aes_ecb_decrypt(cipher, self.key, remove_padding=True)  
		plaintext = plaintext.decode('ascii')  
		parsed = self.key_val_parser(plaintext)  
		print(parsed)
``` 

Now, as the **attacker** we have access to **get_user_profile** which provides us with the encrypted profile. Our target is to build an encrypted profile which will be parsed as **role=admin**.
Because the encryption is ECB mode we can generate different blocks at a time and then concatenate them all together.

We start by encrypting the string: 'mail=foo@hackme.com&uid=10&role='
The length of this string is 32, which is exactly two AES blocks.
The encryption is done using **get_user_profile** and setting user_mail to **foo@hackme.com**. Then we need to remove the last block which contain the string 'user' and PKCS7 padding.
```python
# generate the initial blocks which contain the string: 'mail=foo@hackme.com&uid=10&role='  
# this string length is a multiple of AES block length,  
# that way, we will be able to append another block after it.  
starting_blocks = user_profile.get_user_profile('foo@hackme.com')  
starting_blocks = starting_blocks[:-AES_BLOCK_SIZE] # remove last block
```

In the next block, we want to have the string 'admin' and PKCS7 padding. That way, we can append it to the last 2 blocks we create and form the encryption of: 'mail=foo@hackme.com&uid=10&role=admin'
To encrypt this block, we align its plaintext into the second block of **get_user_profile** and extract the second block of the cipher:
```python
# generate the last block which contains the string 'admin' and PKCS7 padding.  
# we encrypt its plaintext, by padding its start by 11 and aligning it to the second block.  
# that way, the input plaintext become:  
# block1 - 'mail=AAAAAAAAAAA'  
# block2 - 'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'  
# block3 - etc.
last_block_plaintext = 'admin' + '\x0b' * 11  
last_block_plaintext = 'A' * 11 + last_block_plaintext  
last_block = user_profile.get_user_profile(last_block_plaintext)  
last_block = last_block[AES_BLOCK_SIZE:2*AES_BLOCK_SIZE] # extract second block
```

Now, we concat the blocks and pass them to the profiler:
```python
# connect blocks to create the attack sequence  
attack_sequence = starting_blocks + last_block  
user_profile.set_user_profile(attack_sequence)

# Parsed expression = 
# {'mail': 'foo@hackme.com', 'uid': '10', 'role': 'admin'}
```

## Challenge 14 - Byte-at-a-time ECB decryption (Harder)

> Challenge: https://cryptopals.com/sets/2/challenges/14

The main problem in this challenge is that we don't know the length of the prefix, and as a result, we are not aligned with the cipher blocks.

Therefore, we start by evaluating the prefix length, and then continue the same as in [challenge 12](#challenge-12---byte-at-a-time-ecb-decryption-simple).

1. The first function evaluates the padding length required to extend the prefix into an integer number of cipher block lengths. We can utilize the ECB property of the cipher, and look for the alignment needed to create two identical blocks in the output ciphertext:
```python
def detect_alignment(oracle: Oracle, block_size: int) -> int:  
	"""  
	Evaluate the padding length required to extend the prefix, 
	into an integer number of [block_size] lengths. 
	"""  
	base_repetitions = count_repetitions(oracle.encrypt(b''))  

	# repeat [num_attempts] to avoid random correct alignment  
	num_attempts = 5  
	for i in range(num_attempts):  
		repetitions = []  
		for pad_len in range(block_size):  
			stream = b'A' * pad_len + 2 * bytes(range(i, block_size+i))  
			num_repetitions = count_repetitions(oracle.encrypt(stream))  
			repetitions.append(num_repetitions)  

			# if only one padding align, we know it is correct  
			rep_max_val = max(repetitions)  
			if repetitions.count(rep_max_val) == 1:  
				return repetitions.index(rep_max_val)  

	raise ValueError('Cipher mode is probably not ECB')
``` 

2. Now, we know the alignment, and we can look for the output block that changes as a result of a change in the input. (The ECB property guarantees it will be a single block..)

```python
def detect_attacker_index(oracle: Oracle, block_size: int, alignment_pad: int) -> int:  
	"""  
	Detect the starting location of our plaintext in the output ciphertext. 
	The function assumes the cipher is ECB-AES, and searches for the output block 
	that changes as a result of a change in the input. 
	"""  
	command1 = b'A' * alignment_pad + b'1' * block_size  
	response1 = oracle.encrypt(command1)  
	command2 = b'A' * alignment_pad + b'2' * block_size  
	response2 = oracle.encrypt(command2)  

	for i in range(0, len(response1), block_size):  
		block1 = response1[i:i+block_size]  
		block2 = response2[i:i + block_size]  

		if block1 != block2:  
			return i  

	raise ValueError('detect_attacker_index failed')
```

3. We have the prefix length, so we can trim it from the output ciphertext. For simplicity, we create **AttackerOracle**, which deals with the prefix for us:

```python
class AttackerOracle:  
	def __init__(self, oracle: Oracle):  
		self.oracle = oracle  
		self.block_size = detect_block_size(self.oracle)  
		self.alignment_pad = detect_alignment(self.oracle, self.block_size)  
		self.attacker_idx = detect_attacker_index(self.oracle, self.block_size, self.alignment_pad)  

	def encrypt(self, plaintext):  
		ext_plaintext = self.alignment_pad * b'A' + plaintext  
		ciphertext = self.oracle.encrypt(ext_plaintext)  
		ciphertext = ciphertext[self.attacker_idx:]  
		return ciphertext
```

4. Now, we can detect one byte at a time just like challenge 12:

```python
def decrypt_ecb():  
	oracle = Oracle()  
	attacker_oracle = AttackerOracle(oracle)  

	block_size = attacker_oracle.block_size  
	msg_len = detect_msg_length(attacker_oracle, block_size)  

	# decrypt hidden cipher  
	plaintext = b'A' * (block_size - 1)  

	for i in range(msg_len):  
		# create reference block  
		pad_len = (block_size - i - 1) % block_size  
		ref_block = attacker_oracle.encrypt(b'A' * pad_len)  
		ref_block_idx = i - (i % block_size)  
		ref_block = ref_block[ref_block_idx: ref_block_idx + block_size]  

		# detect single byte  
		padding = plaintext[-block_size+1:]  
		new_byte = detect_single_byte(attacker_oracle, ref_block, padding, block_size)  
		plaintext += bytes([new_byte])  

	# remove initial padding and return  
	return plaintext[block_size-1:]
```

The result:
```python
decrypted_target = decrypt_ecb()  
print(decrypted_target)
# b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
```

## Challenge 15 - PKCS#7 padding validation

> Challenge: https://cryptopals.com/sets/2/challenges/15

To determines if the input has a valid PKCS#7 padding, we iterate all the possible padding lengths (=block_size) and check the validity of each one. When we find valid padding, we can just remove it from the input end.

```python
def pkcs7_unpad(stream: bytes, block_size: int) -> bytes:  
	if len(stream) % block_size != 0:  
		raise ValueError('steam length must be a multiply of block_size')  

	for i in range(block_size, 0, -1):  
		guessed_padding = stream[-i:]  
		# check if the guess is valid  
		padding_vals = set(guessed_padding)  
		if len(padding_vals) == 1 and padding_vals.pop() == i:  
			return stream[:-i]  

	# no padding was found  
	raise AssertionError('No padding was found!')
```

And check if it works:
```python
assert b'ICE ICE BABY' == pkcs7_unpad(b'ICE ICE BABY\x04\x04\x04\x04', AES_BLOCK_SIZE)  

try:  
	pkcs7_unpad(b'ICE ICE BABY\x05\x05\x05\x05', AES_BLOCK_SIZE)  
except AssertionError:  
	print('No padding was found')  
else:  
	assert False  

try:  
	pkcs7_unpad(b'ICE ICE BABY\x01\x02\x03\x04', AES_BLOCK_SIZE)  
except AssertionError:  
	print('No padding was found')  
else:  
	assert False
```

## Challenge 16 - CBC bitflipping attacks

> Challenge: https://cryptopals.com/sets/2/challenges/16

We start by implementing two functions. 
The first one prepends and appends some string to the user plaintext. Then, it encrypts the result in AES-CBC mode under some random key.
The second function decrypt the user ciphertext, parse the result and look for the pair **admin=true**.
```python
class Oracle:  
	def __init__(self):  
		self.key = get_random_bytes(AES_BLOCK_SIZE)  
		self.nonce = get_random_bytes(AES_BLOCK_SIZE)  

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
		return b';admin=true;' in decrypted
```

Now, as the **attacker** we have access to **encode** which provides us with the encoded message. Our target is to build an encoded message which will be parsed as **admin=true**.

Let's take a look at the AES-CBC scheme. 
Remember that $c_m=E(p_m+c_{m-1})$, and imagine we want to force the decryption of $p_m$ into some value of our own choice denoted by $p_{target}$.

We know the original values of $c_{m}$, $c_{m-1}$, $p_{m}$.
And thus if we set:

$$\widehat{c_{m-1}}=c_{m-1}+p_{target}+p_m$$ 

The decryption of $p_{m}$ will evaluate into:

$$\widehat{p_m}=\widehat{c_{m-1}}+D(c_m)=\widehat{c_{m-1}}+p_m+c_{m-1}=$$

$$c_{m-1}+p_{target}+p_m+p_m+c_{m-1}=p_{target}$$

In our case, we want to set $p_{target}$ to ";admin=true;". 
So all we need to do is to align our input into some block and use the described method to inject the target.

We start by detecting the prefix length (we already know it equals 32, but it doesn't have to be...). 
In AES-CBC mode, a change in the input will only affect its matching block in the output and the following blocks. We use this property to detect the prefix length:
```python
def detect_prefix_length(oracle: Oracle, block_size: int) -> int:  
	# detect how many complete block_size fit into the prefix  
	full_block_len = 0  
	c1 = oracle.encode(b'')  
	c2 = oracle.encode(b'A')  
	for i in range(0, len(c2), block_size):  
		if c1[i:i+block_size] != c2[i:i+block_size]:  
			full_block_len = i  
			break  

	# detect the prefix length in its final block  
	block_idx = slice(full_block_len, full_block_len+block_size)  
	prev_block = c1[block_idx]  
	pad_len = 0  
	for i in range(1, block_size+2):  
		new_block = oracle.encode(b'A'*i)[block_idx]  
		if new_block == prev_block:  
			pad_len = i - 1  
			break  
		prev_block = new_block  

	# combine the length in blocks and the padding length  
	prefix_len = full_block_len + block_size - pad_len  
	return prefix_len
```

Given the prefix length, we use the described method to create the attack sequence:
```python
def generate_attack_sequence(oracle: Oracle, prefix_len: int):  
	# align our input to new block  
	if prefix_len % AES_BLOCK_SIZE != 0:  
		pad_len = AES_BLOCK_SIZE - (prefix_len % AES_BLOCK_SIZE)  
	else:  
		pad_len = 0  

	prev_blocks_len = prefix_len + pad_len  

	# encode two blocks of repeating 'A'  
	known_plaintext = b'B' * pad_len + b'A' * 2 * AES_BLOCK_SIZE  
	ciphertext = oracle.encode(known_plaintext)  

	# create target block  
	target = b';admin=true'  
	target = b'A' * (AES_BLOCK_SIZE - len(target)) + target  

	# modify c_1 to inject [target] into p_2  
	c1_original = ciphertext[prev_blocks_len: prev_blocks_len + AES_BLOCK_SIZE]  
	p2_original = b'A' * AES_BLOCK_SIZE  
	c1_modified = xor_bytes((c1_original, p2_original, target))  

	# build attack sequence  
	attack_sequence = ciphertext[:prev_blocks_len]  
	attack_sequence += c1_modified  
	attack_sequence += ciphertext[prev_blocks_len + AES_BLOCK_SIZE:]  

	return attack_sequence
```

Now, we can test the **attack_sequence** and check if **admin=true**:
```python
oracle = Oracle()  
prefix_len = detect_prefix_length(oracle, AES_BLOCK_SIZE)  
print(f'{prefix_len=}')  # prefix_len=32
attack_sequence = generate_attack_sequence(oracle, prefix_len=prefix_len)  
is_admin = oracle.parse(attack_sequence)  
print(f'{is_admin=}')  # is_admin=True
```
