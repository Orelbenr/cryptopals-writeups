"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/29

Break a SHA-1 keyed MAC using length extension
Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the output of SHA-1
and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion
will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message;
your forged message will need to include that padding. We call this "glue padding".
The final message you actually forge will be:
SHA1(key || original-message || glue-padding || new-message)
(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit length of the message;
the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an arbitrary message
and verify that you're generating the same padding that your SHA-1 implementation is using.
This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash ---
and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c
(they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key
(choose a random word from /usr/share/dict/words or something) of the string:
"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

Forge a variant of this message that ends with ";admin=true".

This is a very useful attack.
For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.
"""

import struct

from Crypto.Random import get_random_bytes

from Utils.Hash import SHA1
from challenge_28 import sha1_mac


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
    padding += ml.to_bytes(64 // 8, byteorder='big')

    # the total length is a multiple of 512 bits (64 bytes)
    assert ((msg_len + len(padding)) % 64 == 0)

    return padding


def attack(org_msg: bytes, org_mac: bytes, new_msg: bytes, key_len: int):
    # unpack sha1 state
    h0, h1, h2, h3, h4 = [struct.unpack('>I', org_mac[i:i + 4])[0] for i in range(0, 20, 4)]

    # build final message
    msg_len = key_len + len(org_msg)
    padding = md_padding(msg_len)
    final_msg = org_msg + padding + new_msg

    # build new hash
    fake_len = len(final_msg) + key_len
    forged_mac = SHA1(new_msg, h0=h0, h1=h1, h2=h2, h3=h3, h4=h4, force_len=fake_len)

    return final_msg, forged_mac


def main():
    # create SHA-1 keyed MAC on original message
    key = get_random_bytes(16)
    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = sha1_mac(msg=msg, key=key)
    print(f'{mac=}')

    # generate fake SHA-1 keyed MAC
    key_len = 16
    new_msg = b";admin=true"
    final_msg, forged_mac = attack(org_msg=msg, org_mac=mac, new_msg=new_msg, key_len=key_len)
    print(f'{final_msg=}')
    print(f'{forged_mac=}')

    # check for [forged_mac] validity
    new_mac = sha1_mac(msg=final_msg, key=key)
    print(forged_mac == new_mac)


if __name__ == '__main__':
    main()
