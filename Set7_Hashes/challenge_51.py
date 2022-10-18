"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/51

Compression Ratio Side-Channel Attacks

Internet traffic is often compressed to save bandwidth. Until recently, this included HTTPS headers,
and it still includes the contents of responses.

Why does that matter?

Well, if you're an attacker with:
1. Partial plaintext knowledge and
2. Partial plaintext control and
3. Access to a compression oracle

You've got a pretty good chance to recover any additional unknown plaintext.

What's a compression oracle? You give it some input and it tells you how well the full message compresses,
i.e. the length of the resultant output.

This is somewhat similar to the timing attacks we did way back in set 4 in that we're taking advantage of
incidental side channels rather than attacking the cryptographic mechanisms themselves.

Scenario: you are running a MITM attack with an eye towards stealing secure session cookies.
You've injected malicious content allowing you to spawn arbitrary requests and observe them in flight.
(The particulars aren't terribly important, just roll with it.)

So! Write this oracle:
    oracle(P) -> length(encrypt(compress(format_request(P))))

Format the request like this:
    POST / HTTP/1.1
    Host: hapless.com
    Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
    Content-Length: ((len(P)))
    ((P))

(Pretend you can't see that session id. You're the attacker.)

Compress using zlib or whatever.

Encryption... is actually kind of irrelevant for our purposes, but be a sport. Just use some stream cipher.
Dealer's choice. Random key/IV on every call to the oracle.

And then just return the length in bytes.

Now, the idea here is to leak information using the compression library.
A payload of "sessionid=T" should compress just a little bit better than, say, "sessionid=S".

There is one complicating factor. The DEFLATE algorithm operates in terms of individual bits,
but the final message length will be in bytes.
Even if you do find a better compression, the difference may not cross a byte boundary. So that's a problem.

You may also get some incidental false positives.

But don't worry! I have full confidence in you.

Use the compression oracle to recover the session id.

I'll wait.

Got it? Great.

Now swap out your stream cipher for CBC and do it again.
"""

import string
import zlib
from typing import Literal
from itertools import product

from Utils.AES import AesCtr, aes_cbc_encrypt

from Crypto.Random import get_random_bytes

# Consts
AES_BLOCK_SIZE = 16

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

        if self.enc_type == 'CTR':
            request = AesCtr(key=key).encrypt(request)
        elif self.enc_type == 'CBC':
            nonce = get_random_bytes(AES_BLOCK_SIZE)
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


def main():
    # stream cipher (CTR)
    oracle_ctr = CompressionOracle(enc_type='CTR')
    session_id = decode_session_id(oracle_ctr)
    assert session_id == SESSION_ID

    # block cipher (CBC)
    oracle_cbc = CompressionOracle(enc_type='CBC')
    session_id = decode_session_id(oracle_cbc)
    assert session_id == SESSION_ID


if __name__ == '__main__':
    main()
