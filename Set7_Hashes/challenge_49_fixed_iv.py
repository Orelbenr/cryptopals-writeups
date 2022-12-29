"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/49
"""

from dataclasses import dataclass
from Crypto.Random import get_random_bytes

from Utils.AES import aes_cbc_encrypt
from Utils.BytesLogic import xor_bytes
from Utils.Padding import pkcs7_pad


# declare types
@dataclass
class Request:
    msg: bytes
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
        auth = CbcMac.verify(request.msg, request.mac, self._key, bytes(AES_BLOCK_SIZE))
        if not auth:
            print('SERVER: Authentication Failed!')
            return False

        # execute request
        print(f'SERVER: transfer approved - {request.msg}')
        return True


class WebClient:
    def __init__(self, key: bytes):
        self._key = key

    def generate_request(self, user_id: int, transactions: list[tuple[int, int]]) -> Request:
        # encode the message
        transactions = ';'.join([f'{to:02d}:{amount}' for to, amount in transactions])
        msg = f'from=#{user_id:02d}&tx_list=#{transactions}'.encode()
        mac = CbcMac.sign(msg=msg, key=self._key, iv=bytes(AES_BLOCK_SIZE))
        return Request(msg=msg, mac=mac)


def gen_attack_request(target_request: Request, attacker_request: Request):
    target_msg = pkcs7_pad(target_request.msg, AES_BLOCK_SIZE)
    attacker_msg = attacker_request.msg

    # create new message by length extension
    overlap_block = xor_bytes((target_request.mac, attacker_msg[:AES_BLOCK_SIZE]))
    new_msg = target_msg + overlap_block + attacker_msg[AES_BLOCK_SIZE:]

    # pack request
    return Request(msg=new_msg, mac=attacker_request.mac)


def main():
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


if __name__ == '__main__':
    main()
