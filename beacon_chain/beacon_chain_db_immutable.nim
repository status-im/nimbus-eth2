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

# TODO better name: get here generally means retrieve from database,
# which this isn't. another argument, perhaps, for the module split.
func getBeaconStateNoImmutableValidators*[T, U](x: T): ref U =
  # TODO this whole approach is a kludge; should be able to avoid copying and
  # get SSZ to just serialize result.validators differently, concatenate from
  # before + changed + after, or etc. also adding any additional copies, or a
  # non-ref return type, hurts performance significantly.
  #
  # This copies all fields, except validators.
  template assign[V, W](x: HashList[V, W], y: List[V, W]) =
    # https://github.com/status-im/nimbus-eth2/blob/3f6834cce7b60581cfe3cdd9946e28bdc6d74176/beacon_chain/ssz/bytes_reader.nim#L144
    assign(x.data, y)
    x.hashes.setLen(0)
    x.growHashes()

  template assign[V, W](dummy, x: HashArray[V, W], y: array[V, W]) =
    # https://github.com/status-im/nimbus-eth2/blob/3f6834cce7b60581cfe3cdd9946e28bdc6d74176/beacon_chain/ssz/bytes_reader.nim#L148
    assign(x.data, y)
    for h in x.hashes.mitems():
      clearCache(h)

  template assign[V, W](x: List[V, W], y: HashList[V, W]) =
    assign(x, y.data)

  template assign[V, W](
      dummy: HashArray[V, W], x: array[V, W], y: HashArray[V, W]) =
    assign(x, y.data)

  # https://github.com/nim-lang/Nim/issues/17253 workaround
  template type_binder(maybe_array_0, maybe_array_1: untyped): untyped =
    when maybe_array_0 is array:
      maybe_array_1
    else:
      maybe_array_0

  template arrayAssign(x, y: untyped) =
    assign(type_binder(x, y), x, y)

  result = new U
  result.genesis_time = x.genesis_time
  result.genesis_validators_root = x.genesis_validators_root
  result.slot = x.slot
  result.fork = x.fork
  assign(result.latest_block_header, x.latest_block_header)
  arrayAssign(result.block_roots, x.block_roots)
  arrayAssign(result.state_roots, x.state_roots)
  assign(result.historical_roots, x.historical_roots)
  assign(result.eth1_data, x.eth1_data)
  assign(result.eth1_data_votes, x.eth1_data_votes)
  assign(result.eth1_deposit_index, x.eth1_deposit_index)
  assign(result.balances, x.balances)
  arrayAssign(result.randao_mixes, x.randao_mixes)
  arrayAssign(result.slashings, x.slashings)
  assign(
    result.previous_epoch_attestations, x.previous_epoch_attestations)
  assign(
    result.current_epoch_attestations, x.current_epoch_attestations)
  result.justification_bits = x.justification_bits
  assign(result.previous_justified_checkpoint, x.previous_justified_checkpoint)
  assign(result.current_justified_checkpoint, x.current_justified_checkpoint)
  assign(result.finalized_checkpoint, x.finalized_checkpoint)
