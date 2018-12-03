# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This file implements a test vectors generator for the shuffling algorithm described in the Ethereum
# specs as of https://github.com/ethereum/eth2.0-specs/blob/2983e68f0305551083fac7fcf9330c1fc9da3411/specs/core/0_beacon-chain.md#get_new_shuffling

# Reference picture: http://vitalik.ca/files/ShuffleAndAssign.png
# and description from Py-EVM: https://github.com/ethereum/py-evm/blob/f2d0d5d187400ba46a6b8f5b1f1c9997dc7fbb5a/eth/beacon/helpers.py#L272-L344
#
# validators:
#     [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
# After shuffling:
#     [6, 0, 2, 12, 14, 8, 10, 4, 9, 1, 5, 13, 15, 7, 3, 11]
# Split by slot:
#     [
#         [6, 0, 2, 12, 14], [8, 10, 4, 9, 1], [5, 13, 15, 7, 3, 11]
#     ]
# Split by shard:
#     [
#         [6, 0], [2, 12, 14], [8, 10], [4, 9, 1], [5, 13, 15] ,[7, 3, 11]
#     ]
# Fill to output:
#     [
#         # slot 0
#         [
#             ShardAndCommittee(shard_id=0, committee=[6, 0]),
#             ShardAndCommittee(shard_id=1, committee=[2, 12, 14]),
#         ],
#         # slot 1
#         [
#             ShardAndCommittee(shard_id=2, committee=[8, 10]),
#             ShardAndCommittee(shard_id=3, committee=[4, 9, 1]),
#         ],
#         # slot 2
#         [
#             ShardAndCommittee(shard_id=4, committee=[5, 13, 15]),
#             ShardAndCommittee(shard_id=5, committee=[7, 3, 11]),
#         ],
#     ]

# Note that as of 2018-12-03, several implementations are outdated
# as they are still using dynasty or min_committee_size that are not in the specs

# ################################################################
#
#                  Imports and simplified types
#
# ################################################################

from typing import(
    List, Any, Dict, NewType
)

from enum import IntEnum
import random

Hash32 = NewType('Hash32', bytes)
from hashlib import blake2b

def hash(x):
    return blake2b(x).digest()[:32]

class ValidatorStatus(IntEnum):
    PENDING_ACTIVATION = 0
    ACTIVE = 1
    EXITED_WITHOUT_PENALTY = 2
    EXITED_WITH_PENALTY = 3
    # Not in specs anymore - https://github.com/ethereum/eth2.0-specs/issues/216
    PENDING_EXIT = 4

class ValidatorRecord:
    fields = {
        # Status code
        'status': 'ValidatorStatus'
    }

    def __init__(self, **kwargs):
        for k in self.fields.keys():
            setattr(self, k, kwargs.get(k))

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)

    def __getattribute__(self, name: str) -> Any:
        return super().__getattribute__(name)

class ShardAndCommittee:
    fields = {
        # Shard number
        'shard': 'uint64',
        # Validator indices
        'committee': ['uint24'],
        # Total validator count (for proofs of custody)
        'total_validator_count': 'uint64',
    }

    def __init__(self, **kwargs):
        for k in self.fields.keys():
            setattr(self, k, kwargs.get(k))

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)

    def __getattribute__(self, name: str) -> Any:
        return super().__getattribute__(name)

# ################################################################
#
#                    Environment variables
#
# ################################################################

SHARD_COUNT           = 2**10 # 1024
EPOCH_LENGTH          = 2**6  # 64 slots, 6.4 minutes
TARGET_COMMITTEE_SIZE = 2**8  # 256 validators

# ################################################################
#
#              Procedures (copy-pasted from specs)
#
# ################################################################

def get_active_validator_indices(validators: [ValidatorRecord]) -> List[int]:
    """
    Gets indices of active validators from ``validators``.
    """
    return [i for i, v in enumerate(validators) if v.status in [ValidatorStatus.ACTIVE, ValidatorStatus.PENDING_EXIT]]

def shuffle(values: List[Any], seed: Hash32) -> List[Any]:
    """
    Returns the shuffled ``values`` with ``seed`` as entropy.
    """
    values_count = len(values)

    # Entropy is consumed from the seed in 3-byte (24 bit) chunks.
    rand_bytes = 3
    # The highest possible result of the RNG.
    rand_max = 2 ** (rand_bytes * 8) - 1

    # The range of the RNG places an upper-bound on the size of the list that
    # may be shuffled. It is a logic error to supply an oversized list.
    assert values_count < rand_max

    output = [x for x in values]
    source = seed
    index = 0
    while index < values_count - 1:
        # Re-hash the `source` to obtain a new pattern of bytes.
        source = hash(source)
        # Iterate through the `source` bytes in 3-byte chunks.
        for position in range(0, 32 - (32 % rand_bytes), rand_bytes):
            # Determine the number of indices remaining in `values` and exit
            # once the last index is reached.
            remaining = values_count - index
            if remaining == 1:
                break

            # Read 3-bytes of `source` as a 24-bit big-endian integer.
            sample_from_source = int.from_bytes(source[position:position + rand_bytes], 'big')

            # Sample values greater than or equal to `sample_max` will cause
            # modulo bias when mapped into the `remaining` range.
            sample_max = rand_max - rand_max % remaining

            # Perform a swap if the consumed entropy will not cause modulo bias.
            if sample_from_source < sample_max:
                # Select a replacement index for the current index.
                replacement_position = (sample_from_source % remaining) + index
                # Swap the current index with the replacement index.
                output[index], output[replacement_position] = output[replacement_position], output[index]
                index += 1
            else:
                # The sample causes modulo bias. A new sample should be read.
                pass

    return output

def split(values: List[Any], split_count: int) -> List[Any]:
    """
    Splits ``values`` into ``split_count`` pieces.
    """
    list_length = len(values)
    return [
        values[(list_length * i // split_count): (list_length * (i + 1) // split_count)]
        for i in range(split_count)
    ]

def clamp(minval: int, maxval: int, x: int) -> int:
    """
    Clamps ``x`` between ``minval`` and ``maxval``.
    """
    if x <= minval:
        return minval
    elif x >= maxval:
        return maxval
    else:
        return x

def get_new_shuffling(seed: Hash32,
                      validators: List[ValidatorRecord],
                      crosslinking_start_shard: int) -> List[List[ShardAndCommittee]]:
    """
    Shuffles ``validators`` into shard committees using ``seed`` as entropy.
    """
    active_validator_indices = get_active_validator_indices(validators)

    committees_per_slot = clamp(
        1,
        SHARD_COUNT // EPOCH_LENGTH,
        len(active_validator_indices) // EPOCH_LENGTH // TARGET_COMMITTEE_SIZE,
    )

    # Shuffle with seed
    shuffled_active_validator_indices = shuffle(active_validator_indices, seed)

    # Split the shuffled list into epoch_length pieces
    validators_per_slot = split(shuffled_active_validator_indices, EPOCH_LENGTH)

    output = []
    for slot, slot_indices in enumerate(validators_per_slot):
        # Split the shuffled list into committees_per_slot pieces
        shard_indices = split(slot_indices, committees_per_slot)

        shard_id_start = crosslinking_start_shard + slot * committees_per_slot

        shards_and_committees_for_slot = [
            ShardAndCommittee(
                shard=(shard_id_start + shard_position) % SHARD_COUNT,
                committee=indices,
                total_validator_count=len(active_validator_indices),
            )
            for shard_position, indices in enumerate(shard_indices)
        ]
        output.append(shards_and_committees_for_slot)

    return output

# ################################################################
#
#                       Testing
#
# ################################################################

if __name__ == '__main__':
    random.seed(int("0xEF00BEAC", 16))


    seedhash = bytes(random.randint(0, 255) for byte in range(32))
    list_val_state = list(ValidatorStatus)
    validators = [ValidatorRecord(status=random.choice(list_val_state)) for num_val in range(256)]
    crosslinking_start_shard = random.randint(0, SHARD_COUNT)

    print(f"Hash: 0x{seedhash.hex()}")
    print(f"validators: {validators}")
    print(f"crosslinking_start_shard: {crosslinking_start_shard}")

    shuffle = get_new_shuffling(seedhash, validators, crosslinking_start_shard)
    print(f"shuffling: {shuffle}")
