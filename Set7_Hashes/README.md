# Set 7: Hashes

## Table of contents
49. [Challenge 49 - CBC-MAC Message Forgery](#challenge-49---cbc-mac-message-forgery)
50. [Challenge 50 - Hashing with CBC-MAC](#challenge-50---hashing-with-cbc-mac)
51. [Challenge 51 - Compression Ratio Side-Channel Attacks](#challenge-51---compression-ratio-side-channel-attacks)
52. [Challenge 52 - Iterated Hash Function Multicollisions](#challenge-52---iterated-hash-function-multicollisions)
53. [Challenge 53 - Kelsey and Schneier's Expandable Messages](#challenge-53---kelsey-and-schneiers-expandable-messages)
54. [Challenge 54 - Kelsey and Kohno's Nostradamus Attack](#challenge-54---kelsey-and-kohnos-nostradamus-attack)




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

The challenge is based on the paper [BREACH: REVIVING THE CRIME ATTACK](https://www.breachattack.com/resources/BREACH%20-%20SSL,%20gone%20in%2030%20seconds.pdf).

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

The challenge is based on the paper [Multicollisions in iterated hash functions](https://www.iacr.org/archive/crypto2004/31520306/multicollisions.pdf).

We implement Merkle-Damgard hash function:
```python
def merkle_damgard_aes128(msg: bytes, state: bytes, state_size: int) -> bytes:
    if len(state) != state_size:
        raise ValueError(f'H must have length of {state_size}')

    # pad the message
    reminder = len(msg) % AES.block_size
    if reminder > 0:
        msg += bytes(AES.block_size - reminder)

    # loop message blocks
    for i in range(0, len(msg), AES.block_size):
        # pad H to key size
        assert len(state) == state_size
        state += bytes(AES.block_size - len(state))

        # encrypt
        msg_block = msg[i:i + AES.block_size]
        state = AES.new(state, AES.MODE_ECB).encrypt(msg_block)
        state = state[:state_size]

    return state
```

Now, we need to create a function f(n) that will generate 2^n collisions in this hash function.

According to the [Birthday Paradox](https://en.wikipedia.org/wiki/Birthday_problem), The naive approach of brute-forcing the search will result in $\Theta(2^{n} \cdot 2^{b \cdot (2^{n}-1) / 2^{n}})$ guesses in average (where b is the bit-size of the hash function).

To narrow down the search, we use [Joux’s multicollision attack](https://cs.uwaterloo.ca/~dstinson/Pyth4.pdf).

The idea is to find $n$ successive collisions in the compression function, each of which requires time $\Theta(2^{b/2})$, resulting in total of $\Theta(n \cdot 2^{b/2})$ .

The attack: we find the following collisions (total of n collisions) - 

$$ z_{1} = C(y_{1}^{1}, z_{0}) = C(y_{1}^{2}, z_{0}) $$

$$ z_{2} = C(y_{2}^{1}, z_{1}) = C(y_{2}^{2}, z_{1}) $$

$$ ... $$

$$ z_{n} = C(y_{n}^{1}, z_{n-1}) = C(y_{n}^{2}, z_{n-1}) $$

Then, the set:

$$ \{y_{1}^{1},y_{1}^{2}\} \times \{y_{2}^{1},y_{2}^{2}\} \times ... \times \{y_{n}^{1},y_{n}^{2}\} $$ 

is a $2^{n}$ multicollision.

For the attack we need a function that search for a single collision in $\Theta(2^{b/2})$ time. ([more about the function comlexity](https://www.learnpythonwithrune.org/birthday-paradox-and-hash-function-collisions-by-example/))
```python
def find_collision(state: bytes, state_size: int):
    """
    Find two messages that collide
    :param state: previous state
    :param state_size: state size in bytes
    :return: (first message, second message, next state)
    """
    if len(state) != state_size:
        raise ValueError(f'state must have length of {state_size}')

    hash_dict = {}
    while True:
        msg = random.randbytes(AES.block_size)
        hash_result = merkle_damgard_aes128(msg, state, state_size)

        # check for collision
        if hash_result in hash_dict:
            return msg, hash_dict[hash_result], hash_result
        else:
            hash_dict[hash_result] = msg
```

And then, we can use the described method to generate multiple collisions:
```python
def generate_collisions(n: int, state: bytes, state_size: int):
    """ Create a 2^n multi collision set """
    msg_set = []
    for _ in range(n):
        y1, y2, state = find_collision(state, state_size)
        msg_set.append((y1, y2))

    # return msg_set
    for i in product([0, 1], repeat=n):
        yield b''.join([block[i[idx]] for idx, block in enumerate(msg_set)])
```

Finally, we can check all the messages indeed collide:
```python
# generate collisions and verify all messages collide
n = 4  # look for 2^n collisions
state_size = 2  # state size in bytes
initial_state = random.randbytes(state_size)
msg_set = generate_collisions(n, initial_state, state_size)
hash_vals = [merkle_damgard_aes128(msg, initial_state, state_size) for msg in msg_set]
all_collide = hash_vals.count(hash_vals[0]) == len(hash_vals)
print(f'{all_collide=}')  # all_collide=True
```

---

In the second part of the challenge we need to find collision to h(x) = f(x) || g(x).

Instead of looking for collisions in h(x), we can generate collisions in f(x) (the cheaper hash funcion) and check for collision in g(x).

We use f(x) with output size of 16 bits, and g(x) with output size of 32 bit:
```python
# define f and g:
b1 = 2  # f state_size
b2 = 4  # g state_size

# initial states
f_initial_state = random.randbytes(b1)
g_initial_state = random.randbytes(b2)

# define h = f|g
def h(msg: bytes):
    f = merkle_damgard_aes128(msg=msg, state=f_initial_state, state_size=b1)
    g = merkle_damgard_aes128(msg=msg, state=g_initial_state, state_size=b2)
    return f + g

# look for collision in h(x) = f(x) || g(x)
found_collision = False
while not found_collision:
    # generate colliding messages in f
    f_msg_set = generate_collisions(n=b2*3, state=f_initial_state, state_size=b1)

    # there's a good chance the message pool has a collision in g - find it
    hash_dict = {}
    for msg in f_msg_set:
        hash_result = merkle_damgard_aes128(msg=msg, state=g_initial_state, state_size=b2)

        # check for collision
        if hash_result in hash_dict:
            m1, m2 = msg, hash_dict[hash_result]
            found_collision = True
            break
        else:
            hash_dict[hash_result] = msg

# verify the hash h(x) collide
is_collision = h(m1) == h(m2)
print(f'{is_collision=}')  # is_collision=True
```

There were 400 calls to the collision function.



## Challenge 53 - Kelsey and Schneier's Expandable Messages

> Challenge: https://cryptopals.com/sets/7/challenges/53

The challenge is based on the paper [Second Preimages on n-bit Hash Functions for Much Less than 2^n Work](https://www.schneier.com/wp-content/uploads/2016/02/paper-preimages.pdf).

We update Merkle-Damgard hash function to have a secure padding:
```python
def merkle_damgard_aes128(msg: bytes, state: bytes, state_size: int, add_len_pad: bool = True) -> bytes:
    if len(state) != state_size:
        raise ValueError(f'H must have length of {state_size}')

    # pad the message, use secure padding:
    # (https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction#Length_padding_example)
    reminder = len(msg) % AES.block_size
    msg_len = len(msg)
    if reminder > 0:
        msg += b'\x80'  # first bit in padding is 1
        msg += bytes(AES.block_size - reminder - 1)  # zeros to match block size

    if add_len_pad:
        # the message length is added in an extra block at the end
        msg += msg_len.to_bytes(AES.block_size, 'big')

    # loop message blocks
    for i in range(0, len(msg), AES.block_size):
        # pad H to key size
        assert len(state) == state_size
        state += bytes(AES.block_size - len(state))

        # encrypt
        msg_block = msg[i:i + AES.block_size]
        state = AES.new(state, AES.MODE_ECB).encrypt(msg_block)
        state = state[:state_size]

    return state
```

For the attack we need to implement *Expandable Message*. This is actually a set of messages of length $(k, k + 2^{k} - 1)$ with the same hash value.

Using these messages, we can choose a prefix with length of our own choice with known hash result.

We start with with a function that find a collision between 1-block message and a message of $\alpha = 2^{(k-j)}+1$ blocks.

Note - this function has to efficient (birthday paradox), otherwise the whole search would be pointless and we would get stuck here. 

For efficiency, we constructs about $2^{n/2}$ messages of length
1, and about the same number of length $\alpha$ , and looks for a collision:
```python
def find_collision(state: bytes, k: int, j: int):
    """
    Find a collision between a single-block message and a message of 2^(k-j)+1 blocks.
    :return: (1-block message, 2^(k-j)+1 block message, next state)
    """

    n = len(state) * 8  # state length in bits

    one_block_hash = {}
    while True:
        # constructs about 2^(n/2) messages of length 1
        for _ in range(n//2+1):
            msg = random.randbytes(AES.block_size)
            msg_hash = merkle_damgard_aes128(msg, state, len(state), add_len_pad=False)
            one_block_hash[msg_hash] = msg

        # find collision with messages of length 2^(k-j)+1
        prefix = random.randbytes(AES.block_size * (2 ** (k - j)))
        prefix_hash = merkle_damgard_aes128(prefix, state, len(state), add_len_pad=False)

        for _ in range(n//2+1):
            last_block = random.randbytes(AES.block_size)
            hash_result = merkle_damgard_aes128(last_block, prefix_hash, len(prefix_hash), add_len_pad=False)

            # check for collision
            if hash_result in one_block_hash:
                m1 = one_block_hash[hash_result]
                m2 = prefix + last_block
                hash_out = hash_result

                assert len(m1) == AES.block_size
                assert len(m2) == AES.block_size * (2 ** (k-j) + 1)
                assert merkle_damgard_aes128(m1, state, len(state), add_len_pad=False) == hash_out
                assert merkle_damgard_aes128(m2, state, len(state), add_len_pad=False) == hash_out
                return m1, m2, hash_out
```

Then, we create *ExpandableMessage* class which generate the discussed set, and produce a message with length of our own choice:
```python
class ExpandableMessage:
    def __init__(self, k: int, initial_state: bytes):
        """ Produce a set of messages of length (k, k + 2^k - 1) """
        msg_set = []
        state = initial_state
        for j in range(1, k + 1):
            m1, m2, state = find_collision(state, k, j)
            msg_set.append((m1, m2))

        self.k = k
        self.initial_state = initial_state
        self.msg_set = msg_set
        self.hash = state

    def generate_msg(self, num_blocks: int) -> bytes:
        """ Generate msg of [n] blocks """
        if num_blocks < self.k or num_blocks > (self.k + 2 ** self.k - 1):
            raise ValueError('n is out of bounds')

        # build the message using binary representation
        num_added_blocks = num_blocks - self.k
        seq = [1 if digit == '1' else 0 for digit in format(num_added_blocks, f'0{self.k}b')]
        msg = b''.join([block[seq[idx]] for idx, block in enumerate(self.msg_set)])

        # validate message
        assert len(msg)/AES.block_size == num_blocks

        return msg
```

Now, the attack goes like this:
- Save the hash value of intermediate blocks of the message.
- Find a collision between a *bridged* block to one of the saved hash values from previus step.
- Build a forged message with the length of the original message. The forged message contain a prefix (which derive from the expandable message), the bridged block, and the second part of the original image.

```python
def preimage_attack(msg: bytes, initial_state: bytes):
    # Generate an expandable message
    k = math.floor(math.log2(len(msg)/AES.block_size))
    expandable_msg = ExpandableMessage(k=k, initial_state=initial_state)

    # generate a map of intermediate hash states to the block indices that they correspond to
    hash_states = {}
    state = initial_state
    state_size = len(initial_state)
    for i in range(0, len(msg), AES.block_size):
        # pad H to key size
        state += bytes(AES.block_size - len(state))

        # encrypt
        msg_block = msg[i:i + AES.block_size]
        if len(msg_block) != AES.block_size:
            break
        state = AES.new(state, AES.MODE_ECB).encrypt(msg_block)
        state = state[:state_size]

        # add state to table
        if i >= (k-1) * AES.block_size:
            hash_states[state] = i

    # find a single-block "bridge" to intermediate state in the map
    while True:
        bridge_block = random.randbytes(AES.block_size)
        next_state = merkle_damgard_aes128(bridge_block, expandable_msg.hash, state_size, add_len_pad=False)
        if next_state in hash_states:
            suffix_idx = hash_states[next_state] + AES.block_size
            break

    # generate a prefix of the right length such that len(prefix || bridge || M[i..]) = len(M)
    suffix = msg[suffix_idx:]
    prefix_len = (len(msg) - len(suffix)) // AES.block_size - 1
    prefix = expandable_msg.generate_msg(num_blocks=prefix_len)

    # generate the fake message
    forged_msg = prefix + bridge_block + msg[suffix_idx:]

    # check validity
    assert len(forged_msg) == len(msg)
    assert merkle_damgard_aes128(msg, initial_state, state_size) ==\
           merkle_damgard_aes128(forged_msg, initial_state, state_size)

    return forged_msg
```

Using *preimage_attack* we can forge preimage for any long message:
```python
# generate source message and hash
k = 8
msg = random.randbytes(AES.block_size * (2 ** k) + 19)

state_size = 4    # state size in bytes
initial_state = random.randbytes(state_size)
msg_hash = merkle_damgard_aes128(msg, initial_state, state_size)

# forge message
forged_msg = preimage_attack(msg, initial_state)
assert merkle_damgard_aes128(forged_msg, initial_state, state_size) == msg_hash
```

We found a collision for a state of 32 bit long in just a few seconds !!! 

Using a naive approche would require $2^n = 4,294,967,296$ iterations.



## Challenge 54 - Kelsey and Kohno's Nostradamus Attack

> Challenge: https://cryptopals.com/sets/7/challenges/54

The challenge is based on the paper [Herding Hash Functions and the Nostradamus Attack](https://link.springer.com/chapter/10.1007/11761679_12).

