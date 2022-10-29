"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/53

Kelsey and Schneier's Expandable Messages

One of the basic yardsticks we use to judge a cryptographic hash function is its resistance to second preimage attacks.
That means that if I give you x and y such that H(x) = y,
you should have a tough time finding x' such that H(x') = H(x) = y.

How tough? Brute-force tough. For a 2^b hash function, we want second preimage attacks to cost 2^b operations.

This turns out not to be the case for very long messages.

Consider the problem we're trying to solve:
we want to find a message that will collide with H(x) in the very last block.
But there are a ton of intermediate blocks, each with its own intermediate hash state.

What if we could collide into one of those?
We could then append all the following blocks from the original message to produce the original H(x). Almost.

We can't do this exactly because the padding will mess things up.

What we need are expandable messages.

In the last problem we used multicollisions to produce 2^n colliding messages for n*2^(b/2) effort.
We can use the same principles to produce a set of messages of length (k, k + 2^k - 1) for a given k.

Here's how:
- Starting from the hash function's initial state,
  find a collision between a single-block message and a message of 2^(k-1)+1 blocks.
  DO NOT hash the entire long message each time. Choose 2^(k-1) dummy blocks, hash those, then focus on the last block.

- Take the output state from the first step.
  Use this as your new initial state and find another collision between a single-block message and a message
  of 2^(k-2)+1 blocks.

- Repeat this process k total times. Your last collision should be between a single-block message and a message
  of 2^0+1 = 2 blocks.

Now you can make a message of any length in (k, k + 2^k - 1) blocks by choosing the appropriate message (short or long)
from each pair.

Now we're ready to attack a long message M of 2^k blocks.
- Generate an expandable message of length (k, k + 2^k - 1) using the strategy outlined above.
- Hash M and generate a map of intermediate hash states to the block indices that they correspond to.
- From your expandable message's final state, find a single-block "bridge" to intermediate state in your map.
  Note the index i it maps to.
- Use your expandable message to generate a prefix of the right length such that
  len(prefix || bridge || M[i..]) = len(M).

The padding in the final block should now be correct, and your forgery should hash to the same value as M.
"""

import math
import random

from Crypto.Cipher import AES


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


def main():
    # generate source message and hash
    k = 8
    msg = random.randbytes(AES.block_size * (2 ** k) + 19)

    state_size = 4    # state size in bytes
    initial_state = random.randbytes(state_size)
    msg_hash = merkle_damgard_aes128(msg, initial_state, state_size)

    # forge message
    forged_msg = preimage_attack(msg, initial_state)
    assert merkle_damgard_aes128(forged_msg, initial_state, state_size) == msg_hash


if __name__ == '__main__':
    main()
