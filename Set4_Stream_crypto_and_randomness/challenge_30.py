"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/30

Break an MD4 keyed MAC using length extension
Second verse, same as the first, but use MD4 instead of SHA-1.
Having done this attack once against SHA-1, the MD4 variant should take much less time;
mostly just the time you'll spend Googling for an implementation of MD4.

You're thinking, why did we bother with this?
Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an H(k, m) MAC with SHA1.
Which meant that SHA1 code was floating all over the Internet. MD4 code, not so much.
"""

import struct

from Crypto.Random import get_random_bytes

from Utils.Hash import MD4


def md4_mac(msg: bytes, key: bytes):
    return MD4.process(key + msg)


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
    padding += struct.pack("<Q", ml)

    # the total length is a multiple of 512 bits (64 bytes)
    assert ((msg_len + len(padding)) % 64 == 0)

    return padding


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


def main():
    # create MD4 keyed MAC on original message
    key = get_random_bytes(16)
    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = md4_mac(msg=msg, key=key)
    print(f'{mac=}')

    # generate fake MD4 keyed MAC
    key_len = 16
    new_msg = b";admin=true"
    final_msg, forged_mac = attack(org_msg=msg, org_mac=mac, new_msg=new_msg, key_len=key_len)
    print(f'{final_msg=}')
    print(f'{forged_mac=}')

    # check for [forged_mac] validity
    new_mac = md4_mac(msg=final_msg, key=key)
    print(forged_mac == new_mac)


if __name__ == '__main__':
    main()
