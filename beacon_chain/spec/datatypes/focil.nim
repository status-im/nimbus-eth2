# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Types specific to Fulu (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

import
  std/[sequtils, typetraits],
  "."/[phase0, base, electra],
  chronicles,
  chronos,
  json_serialization,
  ssz_serialization/[merkleization, proofs],
  ssz_serialization/types as sszTypes,
  ../digest,
  kzg4844/[kzg, kzg_abi]

from std/strutils import join
from stew/bitops2 import log2trunc
from stew/byteutils import to0xHex
from ./altair import
  EpochParticipationFlags, InactivityScores, SyncAggregate, SyncCommittee,
  TrustedSyncAggregate, SyncnetBits, num_active_participants
from ./bellatrix import BloomLogs, ExecutionAddress, Transaction
from ./capella import
  ExecutionBranch, HistoricalSummary, SignedBLSToExecutionChange,
  SignedBLSToExecutionChangeList, Withdrawal, EXECUTION_PAYLOAD_GINDEX
from ./deneb import Blobs, BlobsBundle, KzgCommitments, KzgProofs
from ./constants import DomainType

export json_serialization, base

const
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#domain-types
  DOMAIN_INCLUSION_LIST_COMMITTEE* = DomainType([byte 0x0C, 0x00, 0x00, 0x00])

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#preset
  INCLUSION_LIST_COMMITTEE_SIZE* = 16'u64
  # https://github.com/ethereum/consensus-specs/blob/master/specs/_features/eip7805/fork-choice.md#configuration
  VIEW_FREEZE_DEADLINE* = chronos.seconds (SECONDS_PER_SLOT * 3 div 4 )
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/validator.md#configuration
  INCLUSION_LIST_SUBMISSION_DUE = chronos.seconds (SECONDS_PER_SLOT * 2 div 3)
  PROPOSER_INCLUSION_LIST_CUT_OFF = chronos.seconds (SECONDS_PER_SLOT - 1)


  MAX_REQUEST_INCLUSION_LIST* = 16'u64
  MAX_BYTES_PER_INCLUSION_LIST* = 8192'u64


type
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#inclusionlist
  InclusionList* = object
    slot*: Slot
    validator_index*: ValidatorIndex
    inclusion_list_committee_root: Eth2Digest
    transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#signedinclusionlist
  SignedInclusionList* = object
    message*: InclusionList
    signature*: ValidatorSig

  InclusionListKey* = tuple[slot: Slot, committeeRoot: Eth2Digest]

  InclusionListStore* = object
    ## Inclusion lists accepted prior to the view-freeze deadline.
    inclusionLists*: Table[InclusionListKey, seq[InclusionList]]
    ## Tracking of validators that equivocated for a particular (slot, root).
    equivocators*: Table[InclusionListKey, HashSet[ValidatorIndex]]

template makeKey*(slot: Slot, root: Eth2Digest): InclusionListKey =
  (slot: slot, committeeRoot: root)

proc init*(T: typedesc[InclusionListStore]): T =
  InclusionListStore(
    inclusionLists: initTable[InclusionListKey, seq[InclusionList]](),
    equivocators: initTable[InclusionListKey, HashSet[ValidatorIndex]](),
  )

template mgetOrPutSeq(tab: var Table[InclusionListKey, seq[InclusionList]],
                      key: InclusionListKey): var seq[InclusionList] =
  tab.mgetOrPut(key, @[])

template mgetOrPutSet(tab: var Table[InclusionListKey, HashSet[ValidatorIndex]],
                      key: InclusionListKey): var HashSet[ValidatorIndex] =
  tab.mgetOrPut(key, initHashSet[ValidatorIndex]())

proc markEquivocator(
    store: var InclusionListStore, key: InclusionListKey, validator: ValidatorIndex
) =
  store.equivocators.mgetOrPutSet(key).incl(validator)

proc isKnownEquivocator(
    store: InclusionListStore, key: InclusionListKey, validator: ValidatorIndex
): bool =
  store.equivocators.withValue(key, equivocators):
    return validator in equivocators[]
  false

proc process_inclusion_list*(
    store: var InclusionListStore,
    inclusionList: InclusionList,
    accept: bool
) {.raises: [].} =
  ## Record `inclusionList` if `accept` is true. Validators that equivocate are
  ## remembered and future lists from them are ignored.
  let key = makeKey(inclusionList.slot, inclusionList.inclusion_list_committee_root)

  if store.isKnownEquivocator(key, inclusionList.validator_index):
    return

  var lists = store.inclusionLists.mgetOrPutSeq(key)
  for idx, existing in lists.pairs:
    if existing.validator_index != inclusionList.validator_index:
      continue

    if existing == inclusionList:
      return

    # Equivocation detected: drop previous entry and mark validator.
    store.markEquivocator(key, inclusionList.validator_index)
    lists.delete(idx)
    return

  if accept:
    lists.add(inclusionList)

proc getInclusionListsForKey*(
    store: InclusionListStore, key: InclusionListKey
): seq[InclusionList] =
  store.inclusionLists.withValue(key, value):
    return value[]
  @[]

proc getEquivocatorsForKey*(
    store: InclusionListStore, key: InclusionListKey
): HashSet[ValidatorIndex] =
  store.equivocators.withValue(key, equivocators):
    return equivocators[]
  initHashSet[ValidatorIndex]()

proc prune*(store: var InclusionListStore, keepFromSlot: Slot) {.raises: [].} =
  ## Drop entries for slots older than `keepFromSlot`.
  var toDelete: seq[InclusionListKey]
  for key in store.inclusionLists.keys:
    if key.slot < keepFromSlot:
      toDelete.add(key)

  for key in toDelete:
    discard store.inclusionLists.del(key)
    discard store.equivocators.del(key)

## Temporary global store.
## TODO: wire a beacon-node owned instance once the
## gossip integration for inclusion lists lands.
var globalInclusionListStore*: ref InclusionListStore

proc ensureGlobalStore() =
  if globalInclusionListStore.isNil:
    globalInclusionListStore = new(InclusionListStore)
    globalInclusionListStore[] = InclusionListStore.init()

proc get_inclusion_list_store*(): var InclusionListStore =
  ensureGlobalStore()
  globalInclusionListStore[]

proc setGlobalInclusionListStore*(store: ref InclusionListStore) =
  globalInclusionListStore = store

proc resetGlobalInclusionListStore*() =
  if not globalInclusionListStore.isNil:
    globalInclusionListStore[] = InclusionListStore.init()
  else:
    ensureGlobalStore()
