"""
Orel Ben-Reuven
https://cryptopals.com/sets/7/challenges/54

Kelsey and Kohno's Nostradamus Attack

Hash functions are sometimes used as proof of a secret prediction.

For example, suppose you wanted to predict the score of every Major League Baseball game in a season. (2,430 in all.)
You might be concerned that publishing your predictions would affect the outcomes.

So instead you write down all the scores, hash the document, and publish the hash.
Once the season is over, you publish the document.
Everyone can then hash the document to verify your soothsaying prowess.

But what if you can't accurately predict the scores of 2.4k baseball games?
Have no fear - forging a prediction under this scheme reduces to another second preimage attack.

We could apply the long message attack from the previous problem, but it would look pretty shady.
Would you trust someone whose predicted message turned out to be 2^50 bytes long?

It turns out we can run a successful attack with a much shorter suffix. Check the method:
1. Generate a large number of initial hash states. Say, 2^k.
2. Pair them up and generate single-block collisions. Now you have 2^k hash states that collide into 2^(k-1) states.
3. Repeat the process. Pair up the 2^(k-1) states and generate collisions. Now you have 2^(k-2) states.
4. Keep doing this until you have one state. This is your prediction.
5. Well, sort of. You need to commit to some length to encode in the padding.
   Make sure it's long enough to accommodate your actual message, this suffix, and a little bit of glue to join them up.
   Hash this padding block using the state from step 4 - THIS is your prediction.

What did you just build? It's basically a funnel mapping many initial states into a common final state.
What's critical is we now have a big field of 2^k states we can try to collide into,
but the actual suffix will only be k+1 blocks long.

The rest is trivial:
1. Wait for the end of the baseball season. (This may take some time.)
2. Write down the game results. Or, you know, anything else. I'm not too particular.
3. Generate enough glue blocks to get your message length right.
   The last block should collide into one of the leaves in your tree.
4. Follow the path from the leaf all the way up to the root node and build your suffix using the message
   blocks along the way.

The difficulty here will be around 2^(b-k).
By increasing or decreasing k in the tree generation phase, you can tune the difficulty of this step.
It probably makes sense to do more work up-front, since people will be waiting on you to supply your message
once the event passes. Happy prognosticating!
"""

import math
import random
from dataclasses import dataclass

from Crypto.Cipher import AES

from challenge_53 import merkle_damgard
from Utils.helpers import timeit


@dataclass
class StateNode:
    state: bytes
    next_node = None
    msg = None


def find_collision(state1: bytes, state2: bytes):
    """
    Find a collision between two single-block messages from different initial states
    :return: (block message 1, block message 2, next state)
    """

    if len(state1) != len(state2):
        raise ValueError('both states must have the same length')

    n = len(state1) * 8  # state length in bits

    block1_hash = {}
    while True:
        # constructs about 2^(n/2) messages from state1
        for _ in range(n//2):
            msg1 = random.randbytes(AES.block_size)
            msg1_hash = merkle_damgard(msg1, state1, len(state1), add_len_pad=False)
            block1_hash[msg1_hash] = msg1

        # find collision with messages from state2
        for _ in range(n//2):
            msg2 = random.randbytes(AES.block_size)
            msg2_hash = merkle_damgard(msg2, state2, len(state2), add_len_pad=False)

            # check for collision
            if msg2_hash in block1_hash:
                m1 = block1_hash[msg2_hash]
                m2 = msg2
                hash_out = msg2_hash

                assert len(m1) == len(m2) == AES.block_size
                assert merkle_damgard(m1, state1, len(state1), add_len_pad=False) == hash_out
                assert merkle_damgard(m2, state2, len(state2), add_len_pad=False) == hash_out
                return m1, m2, hash_out


@timeit
def build_diamond_structure(k: int, state_size: int) -> (list[StateNode], bytes):
    """
    Build the diamond structure
    :param k: number of levels in the tree
    :param state_size: hash func output size
    :return: - list of [StateNode] with the tree leaves
             - state of root node
    """
    # Generate 2^k initial hash states
    initial_states = [StateNode(random.randbytes(state_size)) for _ in range(2**k)]

    state_list = initial_states
    # build the tree one level at a time (starting from leaves)
    for _ in range(k):
        next_state_list = []
        # Pair the states and generate single-block collisions
        for idx in range(0, len(state_list), 2):
            node1, node2 = state_list[idx], state_list[idx+1]
            m1, m2, hash_out = find_collision(node1.state, node2.state)

            # update the tree structure
            new_node = StateNode(hash_out)
            next_state_list.append(new_node)
            node1.msg, node2.msg = m1, m2
            node1.next_node, node2.next_node = new_node, new_node

        # update node list for next level
        state_list = next_state_list

    return initial_states, state_list[0].state


class Prognosticating:
    def __init__(self, k: int, initial_state: bytes, max_msg_blocks: int):
        self.k = k
        self.initial_state, self.state_size = initial_state, len(initial_state)
        self.max_msg_blocks = max_msg_blocks
        self.diamond_leaves, self.root_state = build_diamond_structure(k, self.state_size)

    def get_hash_prediction(self):
        """ Compute the padded hash value we commit """
        # create padding block
        prediction_len = (self.max_msg_blocks + 1 + self.k) * AES.block_size
        padding_block = prediction_len.to_bytes(AES.block_size, 'big')

        # find finale hash
        hash_prediction = merkle_damgard(padding_block, self.root_state, len(self.root_state), add_len_pad=False)
        return hash_prediction

    @timeit
    def generate_prediction(self, prefix: bytes):
        """ Generate a prediction containing given [prefix] """
        # validate prefix max length
        if math.ceil(len(prefix) / AES.block_size) > self.max_msg_blocks:
            raise ValueError('prefix is too long')

        # pad the prefix to match multiply of block size
        reminder = len(prefix) % AES.block_size
        if reminder > 0:
            prefix += bytes(AES.block_size - reminder)

        # find collision with one of the tree leaves
        prefix_hash = merkle_damgard(prefix, self.initial_state, self.state_size, add_len_pad=False)
        while True:
            link_msg = random.randbytes(AES.block_size)
            tmp_hash = merkle_damgard(link_msg, prefix_hash, self.state_size, add_len_pad=False)

            leaf = next((x for x in self.diamond_leaves if x.state == tmp_hash), None)
            if leaf is not None:
                break

        # build message
        msg = prefix + link_msg
        tmp_node = leaf
        while tmp_node.next_node is not None:
            msg += tmp_node.msg
            tmp_node = tmp_node.next_node

        return msg


@timeit
def main():
    k = 9  # number of levels in the diamond structure
    state_size = 4  # state size in bytes
    initial_state = random.randbytes(state_size)

    # create proof of a secret prediction
    prognosticating = Prognosticating(k=k, initial_state=initial_state, max_msg_blocks=2)
    hash_prediction = prognosticating.get_hash_prediction()
    print(f'Published hash: {hash_prediction}')

    # generate prediction
    challenger_prefix = b'Team ABC won with 30 points'
    prediction = prognosticating.generate_prediction(challenger_prefix)
    print(f'Prediction: {prediction}')

    # verify result
    real_prediction_hash = merkle_damgard(prediction, initial_state, state_size)
    print(f'Prediction hash: {real_prediction_hash}')
    assert real_prediction_hash == hash_prediction


if __name__ == '__main__':
    main()
