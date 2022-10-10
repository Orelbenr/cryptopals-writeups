"""
Orel Ben-Reuven
https://cryptopals.com/sets/6/challenges/42

Bleichenbacher's e=3 RSA Attack

Crypto-tourism informational placard.
This attack broke Firefox's TLS certificate validation several years ago.
You could write a Python script to fake an RSA signature for any certificate.
We find new instances of it every other year or so.

RSA with an encrypting exponent of 3 is popular, because it makes the RSA math faster.

With e=3 RSA, encryption is just cubing a number mod the public encryption modulus:
    c = m ** 3 % n

e=3 is secure as long as we can make assumptions about the message blocks we're encrypting.
The worry with low-exponent RSA is that the message blocks we process won't be large enough to wrap the modulus after
being cubed. The block 00:02 (imagine sufficient zero-padding) can be "encrypted" in e=3 RSA; it is simply 00:08.

When RSA is used to sign, rather than encrypt, the operations are reversed;
the verifier "decrypts" the message by cubing it. This produces a "plaintext" which the verifier checks for validity.

When you use RSA to sign a message, you supply it a block input that contains a message digest.
The PKCS1.5 standard formats that block as:
    00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH

As intended, the ffh bytes in that block expand to fill the whole block, producing a "right-justified" hash
(the last byte of the hash is the last byte of the message).

There was, 7 years ago, a common implementation flaw with RSA verifiers: they'd verify signatures by "decrypting" them
(cubing them modulo the public exponent) and then "parsing" them by looking for 00h 01h ... ffh 00h ASN.1 HASH.

This is a bug because it implies the verifier isn't checking all the padding.
If you don't check the padding, you leave open the possibility that instead of hundreds of ffh bytes,
you have only a few, which if you think about it means there could be squizzilions of possible numbers that
could produce a valid-looking signature.

How to find such a block? Find a number that when cubed (a) doesn't wrap the modulus (thus bypassing the key entirely)
and (b) produces a block that starts "00h 01h ffh ... 00h ASN.1 HASH".

There are two ways to approach this problem:
- You can work from Hal Finney's writeup, available on Google, of how Bleichenbacher explained the math
  "so that you can do it by hand with a pencil".
- You can implement an integer cube root in your language, format the message block you want to forge,
  leaving sufficient trailing zeros at the end to fill with garbage, then take the cube-root of that block.

Forge a 1024-bit RSA signature for the string "hi mom". Make sure your implementation actually accepts the signature!
"""

import hashlib
import math

from Utils.PublicKey import RSA
from Utils.Number import invpow_integer


class RSA_SIG_PKCS1:
    """
    Implementation of RSA Signature.
    Based on the standard PKCS #1 Version 1.5
    https://www.rfc-editor.org/rfc/rfc2313
    Using MD5 digest.
    """
    ASN1_MD5 = b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'

    def __init__(self):
        self.rsa_obj = RSA(key_len=1024, squeeze_output=False)

    def sign(self, msg: bytes) -> int:
        # digest the message
        msg_hash = hashlib.md5(msg).digest()
        msg_hash = self.ASN1_MD5 + msg_hash

        # encode the data
        prefix = b'\x00\x01'
        padding = b'\xFF' * (self.rsa_obj.k - 3 - len(msg_hash))
        suffix = b'\x00'

        # EB = 00 || BT || PS || 00 || D
        msg_encoded = prefix + padding + suffix + msg_hash
        assert len(msg_encoded) == self.rsa_obj.k

        # convert to int and sign
        sig = self.rsa_obj.decrypt(msg_encoded, input_bytes=True, output_bytes=False)

        return sig

    def verify(self, msg: bytes, sig: int) -> bool:
        # decrypt sig and convert to bytes
        sig = self.rsa_obj.encrypt(sig, input_bytes=False, output_bytes=True)

        # find the signature  marker
        if sig[0:2] != b'\x00\x01':
            return False

        # find the 00 separator between the padding and the payload
        try:
            sep_idx = sig.index(b'\x00', 2)
            sep_idx += 1
        except ValueError:
            return False

        # parse ASN1
        if not sig[sep_idx:].startswith(self.ASN1_MD5):
            return False

        # parse hash
        msg_hash = sig[sep_idx+len(self.ASN1_MD5):sep_idx+len(self.ASN1_MD5)+16]
        real_msg_hash = hashlib.md5(msg).digest()

        # check message integrity
        return msg_hash == real_msg_hash


def forge_sig(msg: bytes, sig_len: int):
    # create ASN1 | HASH
    msg_hash = hashlib.md5(msg).digest()
    msg_hash = RSA_SIG_PKCS1.ASN1_MD5 + msg_hash

    # format the message block
    msg_encoded = b'\x00\x01\xFF\xFF\xFF\xFF\x00'
    msg_encoded += msg_hash
    msg_encoded += b'\x00' * (sig_len - len(msg_encoded))

    # transform to integer
    msg_encoded = RSA.bytes_to_integer(msg_encoded)

    # cube root the result (floor)
    sig = invpow_integer(msg_encoded, 3)

    return sig + 1


def main():
    # create signature object
    rsa_sig = RSA_SIG_PKCS1()

    # the message we choose
    msg = b'hi mom'

    # real signature
    real_sig = rsa_sig.sign(msg)

    # forged signature
    sig_len = math.ceil(math.log2(rsa_sig.rsa_obj.n) / 8)
    forged_sig = forge_sig(msg, sig_len)

    # verify signature
    real_sig_res = rsa_sig.verify(msg, real_sig)
    print(f'{real_sig_res=}')
    forged_sig_res = rsa_sig.verify(msg, forged_sig)
    print(f'{forged_sig_res=}')


if __name__ == '__main__':
    main()
