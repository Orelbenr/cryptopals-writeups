

# Set 1: Basics

## Table of contents
1. [Challenge 1 - Convert hex to base64](#challenge-1---convert-hex-to-base64)
2. [Challenge 2 - Fixed XOR](#challenge-2---fixed-xor)
3. [Challenge 3 - Single-byte XOR cipher](#challenge-3---single-byte-xor-cipher)
4. [Challenge 4 - Detect single-character XOR](#challenge-4---detect-single-character-xor)
5. [Challenge 5 - Implement repeating-key XOR](#challenge-5---implement-repeating-key-xor)
6. [Challenge 6 - Break repeating-key XOR](#challenge-6---break-repeating-key-xor)
7. [Challenge 7 - AES in ECB mode](#challenge-7---aes-in-ecb-mode)
8. [Challenge 8 - Detect AES in ECB mode](#challenge-8---detect-aes-in-ecb-mode)

##  Challenge 1 - Convert hex to base64

> Challenge: https://cryptopals.com/sets/1/challenges/1

Using **bytes.fromhex** to decode the hex string into bytes object.
Then, using **base64.b64encode** to represent each char by 6 bits.
```python
string_src = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'  
raw_src = bytes.fromhex(string_src)  
# raw_src = b"I'm killing your brain like a poisonous mushroom"  
  
# encode to base64  
b64_string = base64.b64encode(raw_src)  
# b64_string = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

# checking result  
out = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'  
print(b64_string == out)
```

## Challenge 2 - Fixed XOR

> Challenge: https://cryptopals.com/sets/1/challenges/2

First, create a function that xor bytes objects.
The function xor each byte in a loop.
```python
def xor_bytes(b1: bytes, b2: bytes) -> bytes:  
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])
```

Now, use **bytes.fromhex** to decode the strings, and **hex** to encode the result:
```python
src = bytes.fromhex('1c0111001f010100061a024b53535009181c')  
mask = bytes.fromhex('686974207468652062756c6c277320657965')  
result = xor_bytes(src, mask)  
result_hex = result.hex()  
# result = b"the kid don't play"  
  
# checking result  
out = '746865206b696420646f6e277420706c6179'  
print(result_hex == out)
```

## Challenge 3 - Single-byte XOR cipher

> Challenge: https://cryptopals.com/sets/1/challenges/3

Using the following characters distribution:
```python
{'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,  
 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,  
 'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,  
 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}
```

We give each string a score that indicates how much its character distribution is similar to the real one.
To evaluate this 'similarity' we use the **Bhattacharyya distance** (https://en.wikipedia.org/wiki/Bhattacharyya_distance)

```python
def bhattacharyya_distance(dist1: dict, dist2: dict) -> float:  
    bc_coeff = 0  
	for letter in FREQ.keys():  
	    bc_coeff += math.sqrt(dist1[letter] * dist2[letter])  
  
    return -math.log(bc_coeff)
```

The scoring function is:
```python
def score_string(word: bytes) -> float:  
	curr_freq = {letter: 0 for letter in FREQ.keys()}  

	# calc letter dist for current word  
	num_letters = 0  
	for i in word:  
		if chr(i).lower() in FREQ.keys():  
			curr_freq[chr(i).lower()] += 1  
			num_letters += 1  

	if num_letters != 0:  
		curr_freq = {letter: val / num_letters for letter, val in curr_freq.items()}  
	else:  
		return 0  

	# evaluate dist using the Bhattacharyya distance  
	distance = bhattacharyya_distance(FREQ, curr_freq)  
	return 1 / distance
```

And now we iterate each possible byte value  and return the best result:
```python
src = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')  
  
max_score = 0  
best_res = b''  
for i in range(2 ** 8):  
    tmp = xor_bytes_const(src, i)  
    score = score_string(tmp)  
  
    if score > max_score:  
        max_score = score  
        best_res = tmp  
  
print(best_res)  
# b"Cooking MC's like a pound of bacon"
```

## Challenge 4 - Detect single-character XOR

> Challenge: https://cryptopals.com/sets/1/challenges/4

We know that only one line has been encrypted by single-character XOR.
Thus, we use the previous challenge approach and find the best likely line:

```python
# read given file  
with open('4_list.txt', 'r') as fh:  
    Lines = fh.readlines()  
  
# evaluate each line and find best word  
max_score = 0  
best_word = b''  
for line in Lines:  
    tmp_word, tmp_score = decode_single_byte_xor_cypher(line)  
  
    if tmp_score > max_score:  
        max_score = tmp_score  
        best_word = tmp_word  
  
print(best_word)  
# b'Now that the party is jumping\n'
```

## Challenge 5 - Implement repeating-key XOR

> Challenge: https://cryptopals.com/sets/1/challenges/5

Xor each byte of the given string with its matching byte from the key. The byte index of the key is periodic of len(key)

 ```python
def repeating_key_xor(stream: bytes, key: bytes) -> bytes:  
    return bytes([letter ^ key[idx % len(key)] for idx, letter in enumerate(stream)])
```

 ```python
stream = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"  
key = b'ICE'  
  
res = repeating_key_xor(stream, key)  
out = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' \  
      'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'  
print(res.hex() == out)
```

## Challenge 6 - Break repeating-key XOR

> Challenge: https://cryptopals.com/sets/1/challenges/6

We start with Hamming distance. To count the bit difference between two bytes objects, we xor them and count the remaining bits. The counting of bits in each byte is accomplished by a global lookup table for faster calculations:
```python
# global 
COUNTS = [bin(x).count("1") for x in range(256)]

def hamming_dist(b1: bytes, b2: bytes):  
  """ Number of different bits """  
  diff = xor_bytes(b1, b2)  
  count = sum(map(lambda x: COUNTS[x], diff))  
  return count
```

We estimate the **key size** by bruteforcing many possible values. For each value, we xor chunks of length keysize, and checking hamming difference between close blocks.
```python
def eval_key_size(stream: bytes, max_key_size: int) -> int:  
	# default values  
	min_dist = max_key_size * 8  
	best_key_size = 2  

	# find best key size  
	for key_size in range(2, max_key_size):  
		# calc dist between close chunks  
		idx_list = combinations(range(5), 2)  
		dist_list = []  
		for idx in idx_list:  
			block1 = stream[idx[0] * key_size:(idx[0]+1) * key_size]  
			block2 = stream[idx[1] * key_size:(idx[1]+1) * key_size]  
			dist_list.append(hamming_dist(block1, block2))  

		# calc and update best result  
		total_dist = statistics.mean(dist_list) / key_size  
		if total_dist < min_dist:  
			min_dist = total_dist  
			best_key_size = key_size  

	return best_key_size
```

Now we divide and transpose the cipher to blocks, such that each block contains letters that were xor'd with the same byte:
```python
def transpose_blocks(stream: bytes, key_size: int) -> list:  
	block_list = []  
	for shift in range(key_size):  
		block_list.append(stream[shift::key_size])  

	return block_list
```

Each block is a **single-character XOR cipher** that we know to decipher. So, we reconstruct the full key by deciphering the blocks.
```python
key = []  
for block in block_list:  
  key.append(decode_single_byte_xor_cypher(block))  
  
key = bytes(key)  
print(key) # b'Terminator X: Bring the noise'
```

Finally we can decrypt the code:
```python
word = repeating_key_xor(cypher, key)  
print(f'{word=}') 
# b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
```

## Challenge 7 - AES in ECB mode

> Challenge: https://cryptopals.com/sets/1/challenges/7

We use [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html) to decrypt the cipher (after decoding base64):
```python
from Crypto.Cipher import AES

# decrypt using AES-128  
key = b"YELLOW SUBMARINE"  
cipher = AES.new(key, AES.MODE_ECB)  
plaintext = cipher.decrypt(ciphertext)  
print(plaintext)
# b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
```

## Challenge 8 - Detect AES in ECB mode

> Challenge: https://cryptopals.com/sets/1/challenges/8

The ECB mode is semantically insecure and exposes correlation between blocks. Thus, we check for the relative number of distinct blocks and the total number of blocks:
```python
def score_ecb_mode(cipher: bytes) -> float:  
	""" evaluate repetition of blocks """  
	blocks = []  
	for i in range(0, len(cipher), AES_BLOCK_SIZE):  
		blocks.append(cipher[i:i+AES_BLOCK_SIZE])  

	# evaluate number of distinct blocks relative to the total number of blocks  
	return len(set(blocks)) / len(blocks)
```

If we detect repeating blocks, the cipher is probably in ECB mode:
```python
min_count = float('inf')  
best_cipher = 0  
for idx, ciphertext in enumerate(ciphertext_list):  
	count = score_ecb_mode(ciphertext)  
	if count < min_count:  
		min_count = count  
		best_cipher = idx  

print(f'{best_cipher=}')
# best_cipher=132 
```
