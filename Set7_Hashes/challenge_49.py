"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/49

CBC-MAC Message Forgery

Let's talk about CBC-MAC.

CBC-MAC is like this:
1. Take the plaintext P.
2. Encrypt P under CBC with key K, yielding ciphertext C.
3. Chuck all of C but the last block C[n].
4. C[n] is the MAC.

Suppose there's an online banking application,
and it carries out user requests by talking to an API server over the network.
Each request looks like this:
message || IV || MAC

The message looks like this:
from=#{from_id}&to=#{to_id}&amount=#{amount}

Now, write an API server and a web frontend for it.
(NOTE: No need to get ambitious and write actual servers and web apps. Totally fine to go lo-fi on this one.)
The client and server should share a secret key K to sign and verify messages.

The API server should accept messages, verify signatures, and carry out each transaction if the MAC is valid.
It's also publicly exposed - the attacker can submit messages freely assuming he can forge the right MAC.

The web client should allow the attacker to generate valid messages for accounts he controls.
(Feel free to sanitize params if you're feeling anal-retentive.)
Assume the attacker is in a position to capture and inspect messages from the client to the API server.

One thing we haven't discussed is the IV.
Assume the client generates a per-message IV and sends it along with the MAC.
That's how CBC works, right?

Wrong.

For messages signed under CBC-MAC, an attacker-controlled IV is a liability.
Why? Because it yields full control over the first block of the message.

Use this fact to generate a message transferring 1M spacebucks from a target victim's account into your account.

I'll wait. Just let me know when you're done.

... waiting

... waiting

... waiting

All done? Great - I knew you could do it!

Now let's tune up that protocol a little bit.

As we now know, you're supposed to use a fixed IV with CBC-MAC, so let's do that. We'll set ours at 0 for simplicity.
This means the IV comes out of the protocol:
message || MAC

Pretty simple, but we'll also adjust the message.
For the purposes of efficiency, the bank wants to be able to process multiple transactions in a single request.
So the message now looks like this:
from=#{from_id}&tx_list=#{transactions}

With the transaction list formatted like:
to:amount(;to:amount)*

There's still a weakness here: the MAC is vulnerable to length extension attacks. How?

Well, the output of CBC-MAC is a valid IV for a new message.

"But we don't control the IV anymore!"

With sufficient mastery of CBC, we can fake it.

Your mission: capture a valid message from your target user.
Use length extension to add a transaction paying the attacker's account 1M spacebucks.

Hint!
This would be a lot easier if you had full control over the first block of your message,
huh? Maybe you can simulate that.

Food for thought: How would you modify the protocol to prevent this?
"""

from dataclasses import dataclass
from Crypto.Random import get_random_bytes

from Utils.AES import aes_cbc_encrypt
from Utils.bytes_logic import xor_bytes


# declare types
@dataclass
class Request:
    msg: bytes
    iv: bytes
    mac: bytes


AES_BLOCK_SIZE = 16


class CbcMac:
    @staticmethod
    def sign(msg: bytes, key: bytes, iv: bytes) -> bytes:
        c = aes_cbc_encrypt(plaintext=msg, key=key, nonce=iv, add_padding=True)
        return c[-AES_BLOCK_SIZE:]

    @staticmethod
    def verify(msg: bytes, sig: bytes, key: bytes, iv: bytes) -> bool:
        c = aes_cbc_encrypt(plaintext=msg, key=key, nonce=iv, add_padding=True)
        return sig == c[-AES_BLOCK_SIZE:]


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


def gen_attack_request(web_client: WebClient, req_from: int, req_to: int, req_amount: int):
    # create legitimate request
    old_request = web_client.generate_request(to=req_to, amount=req_amount)
    old_msg = old_request.msg
    old_iv = old_request.iv

    # modify first block of the message to alter 'from'
    idx_start = old_msg.index(b'#')
    new_msg = bytearray(old_msg)
    new_msg[idx_start + 1:idx_start + 3] = f'{req_from:02d}'.encode()

    new_iv = xor_bytes((old_iv, old_msg[:AES_BLOCK_SIZE], new_msg[:AES_BLOCK_SIZE]))

    # pack attack request
    attack_request = Request(msg=bytes(new_msg), iv=new_iv, mac=old_request.mac)
    return attack_request


def main():
    # server and web-client shared key
    key = get_random_bytes(AES_BLOCK_SIZE)
    server = Server(key)
    web_client = WebClient(key)

    # generate invalid request
    attack_request = gen_attack_request(web_client, req_from=3, req_to=1, req_amount=1000000)

    # send the fake request to the server
    server.process_request(attack_request)


if __name__ == '__main__':
    main()
