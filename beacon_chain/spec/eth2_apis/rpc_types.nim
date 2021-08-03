# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Types used in the JSON-RPC (legacy) API - these are generally derived from
# the common REST API, https://ethereum.github.io/eth2.0-APIs/#/

{.push raises: [Defect].}

import
  ".."/datatypes/base,
  ".."/[digest, crypto]

export base, crypto, digest

type
  RpcAttesterDuties* = tuple
    public_key: ValidatorPubKey
    validator_index: ValidatorIndex
    committee_index: CommitteeIndex
    committee_length: uint64
    validator_committee_index: uint64
    slot: Slot

  RpcValidatorDuties* = tuple
    public_key: ValidatorPubKey
    validator_index: ValidatorIndex
    slot: Slot

  RpcBeaconGenesis* = tuple
    genesis_time: uint64
    genesis_validators_root: Eth2Digest
    genesis_fork_version: Version

  RpcBeaconStatesFinalityCheckpoints* = tuple
    previous_justified: Checkpoint
    current_justified: Checkpoint
    finalized: Checkpoint

  RpcBeaconStatesValidators* = tuple
    validator: Validator
    index: uint64
    status: string
    balance: uint64

  RpcBeaconStatesCommittees* = tuple
    index: uint64
    slot: uint64
    validators: seq[uint64] # each object in the sequence should have an index field...

  RpcBeaconHeaders* = tuple
    root: Eth2Digest
    canonical: bool
    header: SignedBeaconBlockHeader

  RpcNodeIdentity* = tuple
    peer_id: string
    enr: string
    p2p_addresses: seq[string]
    discovery_addresses: seq[string]
    metadata: tuple[seq_number: uint64, attnets: string]

  RpcNodePeer* = tuple
    peer_id: string
    enr: string
    last_seen_p2p_address: string
    state: string
    direction: string
    agent: string # This is not part of specification
    proto: string # This is not part of specification

  RpcNodePeerCount* = tuple
    disconnected: int
    connecting: int
    connected: int
    disconnecting: int

  RpcAttestation* = tuple
    aggregation_bits: string
    data: AttestationData
    signature: ValidatorSig

  RpcBalance* = tuple
    index: uint64
    balance: uint64

  RpcSyncInfo* = tuple
    head_slot: Slot
    sync_distance: uint64
    is_syncing: bool
