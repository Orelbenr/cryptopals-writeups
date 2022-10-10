
# cryptopals-writeups

My writeups and Python solutions to the challenges of https://cryptopals.com/.

The **Matasano crypto challenges** (cryptopals) take the form of practical attacks against cryptographic vulnerabilities. 

Some of the cryptographic topics covered:

- Basic substitution and XOR
- Pseudo-random number generators
- Stream and  block ciphers and their modes of operation
- Message authentication codes
- Diffie-Hellman key exchange
- RSA (public-key cryptography)

## Table of Contents
1. [Set 1: Basics](Set1_Basics)
	1. Challenge 1 - Convert hex to base64
	2. Challenge 2 - Fixed XOR
	3. Challenge 3 - Single-byte XOR cipher
	4. Challenge 4 - Detect single-character XOR
	5. Challenge 5 - Implement repeating-key XOR
	6. Challenge 6 - Break repeating-key XOR
	7. Challenge 7 - AES in ECB mode
	8. Challenge 8 - Detect AES in ECB mode

2. [Set 2: Block crypto](Set2_Block_crypto)
	1. Challenge 9 - Implement PKCS#7 padding
	2. Challenge 10 - Implement CBC mode
	3. Challenge 11 - An ECB/CBC detection oracle
	4. Challenge 12 - Byte-at-a-time ECB decryption (Simple)
	5. Challenge 13 - ECB cut-and-paste
	6. Challenge 14 - Byte-at-a-time ECB decryption (Harder)
	7. Challenge 15 - PKCS#7 padding validation
	8. Challenge 16 - CBC bitflipping attacks

3. [Set 3: Block & stream crypto](Set3_Block_and_stream_crypto)
	1. Challenge 17 - The CBC padding oracle
	2. Challenge 18 - Implement CTR, the stream cipher mode
	3. Challenge 19 - Break fixed-nonce CTR mode using substitutions
	4. Challenge 20 - Break fixed-nonce CTR statistically
	5. Challenge 21 - Implement the MT19937 Mersenne Twister RNG
	6. Challenge 22 - Crack an MT19937 seed
	7. Challenge 23 - Clone an MT19937 RNG from its output
	8. Challenge 24 - Create the MT19937 stream cipher and break it

4. [Set 4: Stream crypto and randomness](Set4_Stream_crypto_and_randomness)
	1. Challenge 25 - Break "random access read/write" AES CTR
	2. Challenge 26 - CTR bitflipping
	3. Challenge 27 - Recover the key from CBC with IV=Key
	4. Challenge 28 - Implement a SHA-1 keyed MAC
	5. Challenge 29 - Break a SHA-1 keyed MAC using length extension
	6. Challenge 30 - Break an MD4 keyed MAC using length extension
	7. Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak
	8. Challenge 32 - Break HMAC-SHA1 with a slightly less artificial timing leak

5. [Set 5: Diffie-Hellman and friends](Set5_Diffie-Hellman_and_friends)
	1. Challenge 33 - Implement Diffie-Hellman
	2. Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
	3. Challenge 35 - Implement DH with negotiated groups, and break with malicious "g" parameters
	4. Challenge 36 - Implement Secure Remote Password (SRP)
	5. Challenge 37 - Break SRP with a zero key
	6. Challenge 38 - Offline dictionary attack on simplified SRP
	7. Challenge 39 - Implement RSA
	8. Challenge 40 - Implement an E=3 RSA Broadcast attack


6. [Set 6: RSA and DSA](Set6_RSA_and_DSA)
	1. Challenge 41 - Implement unpadded message recovery oracle
	2. Challenge 42 - Bleichenbacher's e=3 RSA Attack
	3. Challenge 43 - DSA key recovery from nonce
	4. Challenge 44 - DSA nonce recovery from repeated nonce
	5. Challenge 45 - DSA parameter tampering
	6. Challenge 46 - RSA parity oracle
	7. Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
	8. Challenge 48 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
