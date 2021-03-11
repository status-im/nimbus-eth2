# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  tables,
  stew/[assign2, endians2, io2, objects, results],
  serialization, chronicles,
  eth/db/[kvstore, kvstore_sqlite3],
  ./spec/[crypto, datatypes, digest],
  ./ssz/[ssz_serialization, merkleization],
  filepath

type 
  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#beaconstate
  BeaconStateNoImmutableValidators* = object
    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader ##\
    ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: array[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## Needed to process attestations, older to newer

    state_roots*: array[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    historical_roots*: List[Eth2Digest, Limit HISTORICAL_ROOTS_LIMIT]

    # Eth1
    eth1_data*: Eth1Data
    eth1_data_votes*:
      List[Eth1Data, Limit(EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)]
    eth1_deposit_index*: uint64

    # Registry
    validators*: List[ValidatorStatus, Limit VALIDATOR_REGISTRY_LIMIT]
    balances*: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

    # Randomness
    randao_mixes*: array[Limit EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]

    # Slashings
    slashings*: array[Limit EPOCHS_PER_SLASHINGS_VECTOR, uint64] ##\
    ## Per-epoch sums of slashed effective balances

    # Attestations
    previous_epoch_attestations*:
      List[PendingAttestation, Limit(MAX_ATTESTATIONS * SLOTS_PER_EPOCH)]
    current_epoch_attestations*:
      List[PendingAttestation, Limit(MAX_ATTESTATIONS * SLOTS_PER_EPOCH)]

    # Finality
    justification_bits*: uint8 ##\
    ## Bit set for every recent justified epoch
    ## Model a Bitvector[4] as a one-byte uint, which should remain consistent
    ## with ssz/hashing.

    previous_justified_checkpoint*: Checkpoint ##\
    ## Previous epoch snapshot

    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

func updateBeaconStateNoImmutableValidators*[T, U](tgt: var U, src: T) =
  # This copies all fields, except validators.
  template assign[V, W](tgt: var HashList[V, W], src: List[V, W]) =
    # https://github.com/status-im/nimbus-eth2/blob/3f6834cce7b60581cfe3cdd9946e28bdc6d74176/beacon_chain/ssz/bytes_reader.nim#L144
    tgt.clear()
    assign(tgt.data, src)
    tgt.growHashes()

  template assign[V, W](dummy, tgt: var HashArray[V, W], src: array[V, W]) =
    # https://github.com/status-im/nimbus-eth2/blob/3f6834cce7b60581cfe3cdd9946e28bdc6d74176/beacon_chain/ssz/bytes_reader.nim#L148
    static: doAssert tgt.len == src.len
    for h in tgt.hashes.mitems():
      clearCache(h)
    assign(tgt.data, src)

  template assign[V, W](tgt: var List[V, W], src: HashList[V, W]) =
    assign(tgt, src.data)

  template assign[V, W](
      dummy: HashArray[V, W], tgt: var array[V, W], src: HashArray[V, W]) =
    assign(tgt, src.data)

  # https://github.com/nim-lang/Nim/issues/17253 workaround
  template type_binder(maybe_array_0, maybe_array_1: untyped): untyped =
    when maybe_array_0 is array:
      maybe_array_1
    else:
      maybe_array_0

  template arrayAssign(tgt, src: untyped) =
    assign(type_binder(tgt, src), tgt, src)

  tgt.genesis_time = src.genesis_time
  tgt.genesis_validators_root = src.genesis_validators_root
  tgt.slot = src.slot
  tgt.fork = src.fork
  assign(tgt.latest_block_header, src.latest_block_header)
  arrayAssign(tgt.block_roots, src.block_roots)
  arrayAssign(tgt.state_roots, src.state_roots)
  assign(tgt.historical_roots, src.historical_roots)
  assign(tgt.eth1_data, src.eth1_data)
  assign(tgt.eth1_data_votes, src.eth1_data_votes)
  assign(tgt.eth1_deposit_index, src.eth1_deposit_index)
  assign(tgt.balances, src.balances)
  arrayAssign(tgt.randao_mixes, src.randao_mixes)
  arrayAssign(tgt.slashings, src.slashings)
  assign(tgt.previous_epoch_attestations, src.previous_epoch_attestations)
  assign(tgt.current_epoch_attestations, src.current_epoch_attestations)
  tgt.justification_bits = src.justification_bits
  assign(tgt.previous_justified_checkpoint, src.previous_justified_checkpoint)
  assign(tgt.current_justified_checkpoint, src.current_justified_checkpoint)
  assign(tgt.finalized_checkpoint, src.finalized_checkpoint)

proc loadImmutableValidators*(dbSeq: var auto): seq[ImmutableValidatorData] =
  for i in 0 ..< dbSeq.len:
    result.add dbSeq.get(i)
