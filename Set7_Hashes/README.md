# Set 7: Hashes

## Table of contents
49. [Challenge 49 - CBC-MAC Message Forgery](#challenge-49---cbc-mac-message-forgery)
50. [Challenge 50 - Hashing with CBC-MAC](#challenge-50---hashing-with-cbc-mac)
51. [Challenge 51 - Compression Ratio Side-Channel Attacks](#challenge-51---compression-ratio-side-channel-attacks)
52. [Challenge 52 - Iterated Hash Function Multicollisions](#challenge-52---iterated-hash-function-multicollisions)





## Challenge 49 - CBC-MAC Message Forgery

> Challenge: https://cryptopals.com/sets/7/challenges/49

We create the CBC-MAC functionality:
```python
class CbcMac:
    @staticmethod
    def sign(msg: bytes, key: bytes, iv: bytes) -> bytes:
        c = aes_cbc_encrypt(plaintext=msg, key=key, nonce=iv, add_padding=True)
        return c[-AES_BLOCK_SIZE:]

    @staticmethod
    def verify(msg: bytes, sig: bytes, key: bytes, iv: bytes) -> bool:
        c = aes_cbc_encrypt(plaintext=msg, key=key, nonce=iv, add_padding=True)
        return sig == c[-AES_BLOCK_SIZE:]
```

Next, we create the API Server and the web client.

Note: 
    
- The Server and WebClient shares a secret key.
    
- WebClient uses user_id=1 which is the identity of the attacker. That way, the attacker can generate valid messages only for accounts he controls.

```python
class Server:
    def __init__(self, key: bytes):
        self._key = key

    def process_request(self, request: Request) -> bool:
        # verify request
        auth = CbcMac.verify(request.msg, request.mac, self._key, request.iv)
        if not auth:
            print('SERVER: Authentication Failed!')
            return False

        # execute request
        print(f'SERVER: transfer approved - {request.msg.decode()}')
        return True


class WebClient:
    def __init__(self, key: bytes):
        self._key = key
        self.user_id = 1  # the attacker ID

    def generate_request(self, to: int, amount: int) -> Request:
        # generate IV for current request
        iv = get_random_bytes(AES_BLOCK_SIZE)

        # encode the message
        msg = f'from=#{self.user_id:02d}&to=#{to:02d}&amount=#{amount}'.encode()
        mac = CbcMac.sign(msg=msg, key=self._key, iv=iv)
        return Request(msg=msg, iv=iv, mac=mac)
```

Now, as the attacker, we want to craft legitimate request with our choice of parametes.

In this case, the attacker has control over the IV, and thus full control over the first block of the message.

```python
def gen_attack_request(web_client: WebClient, req_from: int, req_to: int, req_amount: int):
    # create legitimate request
    old_request = web_client.generate_request(to=req_to, amount=req_amount)
    old_msg = old_request.msg
    old_iv = old_request.iv

    # modify first block of the message to alter 'from'
    idx_start = old_msg.index(b'#')
    new_msg = bytearray(old_msg)
    new_msg[idx_start:idx_start + 2] = f'{req_from:02d}'.encode()

    new_iv = xor_bytes((old_iv, old_msg[:AES_BLOCK_SIZE], new_msg[:AES_BLOCK_SIZE]))

    # pack attack request
    attack_request = Request(msg=bytes(new_msg), iv=new_iv, mac=old_request.mac)
    return attack_request
```

And the results:
```python
# server and web-client shared key
key = get_random_bytes(AES_BLOCK_SIZE)
server = Server(key)
web_client = WebClient(key)

# generate invalid request
attack_request = gen_attack_request(web_client, req_from=3, req_to=1, req_amount=1000000)

# send the fake request to the server
server.process_request(attack_request)  # SERVER: transfer approved - from=#03&to=#01&amount=#1000000
```

---

Now, the IV is fixed, and the attacker can't use it to forge messages.

We update WebClient and add support for muliple transactions in a single request:
```python
class WebClient:
    def __init__(self, key: bytes):
        self._key = key

    def generate_request(self, user_id: int, transactions: list[tuple[int, int]]) -> Request:
        # encode the message
        transactions = ';'.join([f'{to:02d}:{amount}' for to, amount in transactions])
        msg = f'from=#{user_id:02d}&tx_list=#{transactions}'.encode()
        mac = CbcMac.sign(msg=msg, key=self._key, iv=bytes(AES_BLOCK_SIZE))
        return Request(msg=msg, mac=mac)
```

Our goal is to add a transaction paying the attacker's account 1M spacebucks.

Assume we can capture a valid message from the target user. 

The message will have the form: `from=#TARGET_ID&tx_list=#{transactions}`

As the attacker, we can generate valid message of the form: `from=#ATTACKER_ID_ID&tx_list=#{transactions}`

We will use length extension attack to combine these two messages.

Imagine the target message blocks are:

TM0 | TM1 | TM2

And the corresponding cipher blocks:

CT0 = E(TM0 + IV) | CT1 = E(TM1 + CT0) | MAC_T = CT2 = E(TM2 + CT1)

The same way, the attacker message and cipher blocks:

AM0 | AM1 | AM2

CA0 = E(AM0 + IV) | CA1 = E(AM1 + CA0) | MAC_A = CA2 = E(TA2 + CA1)

We can forge the following message:

TM0 | TM1 | padd(TM2) | AM0 + MAC_T | AM1 | AM2

And it's CBC MAC will be the same as MAC_A.

```python
def gen_attack_request(target_request: Request, attacker_request: Request):
    target_msg = pkcs7_pad(target_request.msg, AES_BLOCK_SIZE)
    attacker_msg = attacker_request.msg

    # create new message by length extension
    overlap_block = xor_bytes((target_request.mac, attacker_msg[:AES_BLOCK_SIZE]))
    new_msg = target_msg + overlap_block + attacker_msg[AES_BLOCK_SIZE:]

    # pack request
    return Request(msg=new_msg, mac=attacker_request.mac)
```

We can use the attack the following way:
```python
ATTACKER_ID = 1
TARGET_ID = 2

# server and web-client shared key
key = get_random_bytes(AES_BLOCK_SIZE)
server = Server(key)
web_client = WebClient(key)

# capture a valid message from your target user
target_request = web_client.generate_request(user_id=TARGET_ID, transactions=[(6, 789), (9, 321)])

# use length extension to add a transaction paying the attacker's account 1M.
attacker_request = web_client.generate_request(user_id=ATTACKER_ID, transactions=[(ATTACKER_ID, 1000000)])
forged_request = gen_attack_request(target_request, attacker_request)

# send the fake request to the server
server.process_request(forged_request)

## SERVER: transfer approved - b'from=#02&tx_list=#06:789;09:321\x011\xe7\x8aK\x8ar\x83\x8a\x8e1Q;j\x05\xebE=#01:1000000'
```

As we can see, the *overlap_block* has no meaning, but we were able to add a transction to the end of the list.



## Challenge 50 - Hashing with CBC-MAC

> Challenge: https://cryptopals.com/sets/7/challenges/50

We have the following JS snippet: `alert('MZA who was that?');`

With CBC-MAC = `296b8d7cb78a243dda4d0a61d33bbdd1`

Our goal is to create a JS snippet that alerts "Ayo, the Wu is back!" and hashes to the same value.

We can use length extension attack like we did in the last challenge - building a message that starts with our new message, and append the previous message, such that the MAC is preserved.

We start with the desired snippet (the comment allow us to append the snippet without affecting the excecution):
```python
# forged mac
new_msg = b"alert('Ayo, the Wu is back!');" + b'//'
```

Now, we look for a block to append the msg which will result in ascii compliance:
```python
while True:
    suffix = bytes([random.randint(33, 127) for _ in range(AES_BLOCK_SIZE)])
    tmp_iv = aes_cbc_encrypt(new_msg + suffix, key=key, add_padding=False)[-AES_BLOCK_SIZE:]
    overlap_block = xor_bytes((tmp_iv, msg[:AES_BLOCK_SIZE]))
    try:
        overlap_block.decode('ascii')
        break
    except UnicodeDecodeError:
        continue
```

Then, we create the full snippet:
```python
final_msg = new_msg + suffix + overlap_block + msg[AES_BLOCK_SIZE:]
assert CbcMac.verify(final_msg, sig=mac, key=key, iv=bytes(AES_BLOCK_SIZE))

print(final_msg.decode('ascii'))
# alert('Ayo, the Wu is back!');//B_z\qFTES^$%FzFm2=rf|(vJ@jG*las that?');
```



## Challenge 51 - Compression Ratio Side-Channel Attacks

> Challenge: https://cryptopals.com/sets/7/challenges/51

We create the Compression Oracle. 

The Oracle format the data with http header, compress the request, encrypt it and return the resulting length:
```python
SESSION_ID = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='

class CompressionOracle:
    def __init__(self, enc_type: Literal['CTR', 'CBC']):
        self.enc_type = enc_type

    def gen_request(self, data: str):
        # format the request
        request = self._format_request(data)

        # compress request
        request = zlib.compress(request)

        # encrypt with random key / IV
        key = get_random_bytes(AES_BLOCK_SIZE)
        nonce = get_random_bytes(AES_BLOCK_SIZE // 2)

        if self.enc_type == 'CTR':
            request = AesCtr(key=key, nonce=nonce).encrypt(request)
        elif self.enc_type == 'CBC':
            request = aes_cbc_encrypt(request, key=key, nonce=nonce, add_padding=True)
        else:
            raise ValueError

        # return the byte length of the request
        return len(request)

    @staticmethod
    def _format_request(data: str) -> bytes:
        """ Format of the request """
        request = 'POST / HTTP/1.1\n'
        request += 'Host: hapless.com\n'
        request += f'Cookie: sessionid={SESSION_ID}\n'
        request += f'Content-Length: {len(data)}\n'
        request += f'{data}'

        return request.encode()
```

Our target is to evaluate the *sessionid*.

We use Compression Side Channel Attacks:

*In compression algorithms any phrase that is repeated gets stored once. This means that if a certain string of characters is repeated somewhere in the text, it is only stored the first time. The second time it occurs as a reference to the first occurrence, therefore when a text occurs multiple times it is very efficiently compressed so the size is smaller. This characteristic can be used in a compression side channel attack.* (https://www.venafi.com/blog/what-are-compression-side-channel-attacks)

So, when the enctyption is a stream cipher, the length of the response reveals the exact plain text length. In order to decode the sessionid, we loop one byte at a time and look for the shortest encryption. (In order to avoid oulier cases, we make sure only one byte correspond to the shortest length):
```python
def decode_session_id(oracle: CompressionOracle):
    # consts
    prefix = 'sessionid='
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/=' + '\n'
    max_len = 100
    max_attempts = 15

    # output string
    session_id = prefix

    # decode each character at a time
    for _ in range(max_len):
        for shift in range(max_attempts):
            # find minimum compression length
            len_list = [oracle.gen_request(session_id[shift:] + new_chr) for new_chr in alphabet]
            min_len = min(len_list)
            chr_list = [alphabet[idx] for idx, comp_len in enumerate(len_list) if comp_len == min_len]

            # check uniqueness
            if len(chr_list) == 1:
                break

        new_chr = chr_list[0]
        # assume [session_id] ends with '\n'
        if new_chr == '\n':
            break

        # update output string
        session_id += new_chr

    return session_id[len(prefix):]
```

And it looks like its working:
```python
# stream cipher (CTR)
oracle_ctr = CompressionOracle(enc_type='CTR')
session_id = decode_session_id(oracle_ctr)
assert session_id == SESSION_ID
```

---
Now, we use CBC (Block Cipher) to encrypt the response. This time, the response may not be aligned at the end of the block, and the block will hide the exact plain text length.

In order to deal with it, we align the response to a tipping point, by brute forcing all posible padding lengths.

The updated *decode_session_id* become:
```python
def decode_session_id(oracle: CompressionOracle):
    # consts
    prefix = 'sessionid='
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/=' + '\n'
    max_len = 100
    max_shift = 2

    # output string
    session_id = prefix

    # decode each character at a time
    for _ in range(max_len):
        for shift, pad_len in product(range(max_shift), range(AES_BLOCK_SIZE)):
            # find minimum compression length
            padding = string.ascii_uppercase[:pad_len]
            len_list = [oracle.gen_request(padding + session_id[shift:] + new_chr) for new_chr in alphabet]
            min_len = min(len_list)
            chr_list = [alphabet[idx] for idx, comp_len in enumerate(len_list) if comp_len == min_len]

            # check uniqueness
            if len(chr_list) == 1:
                break

        new_chr = chr_list[0]
        # assume [session_id] ends with '\n'
        if new_chr == '\n':
            break

        # update output string
        session_id += new_chr

    return session_id[len(prefix):]
```

And it works too:
```python
# block cipher (CBC)
oracle_cbc = CompressionOracle(enc_type='CBC')
session_id = decode_session_id(oracle_cbc)
assert session_id == SESSION_ID
```



## Challenge 52 - Iterated Hash Function Multicollisions

> Challenge: https://cryptopals.com/sets/7/challenges/52
