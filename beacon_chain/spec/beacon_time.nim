# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[hashes, typetraits],
  chronos/timer,
  json_serialization,
  ./presets

export hashes, timer, json_serialization, presets

# A collection of time units that permeate the spec - common to all of them is
# that they expressed relative to the genesis of the chain at varying
# granularities:
#
# * BeaconTime - nanoseconds since genesis
# * uint64 - SLOTS_PER_SECOND seconds since genesis
# * uint64 - EPOCHS_PER_SLOT slots since genesis
# * SyncCommitteePeriod - EPOCHS_PER_SYNC_COMMITTEE_PERIOD epochs since genesis

type
  BeaconTime* = object
    ## A point in time, relative to the genesis of the chain
    ##
    ## Implemented as nanoseconds since genesis - negative means before
    ## the chain started.
    ns_since_genesis*: int64

  TimeDiff* = object
    nanoseconds*: int64
    ## Difference between two points in time with nanosecond granularity
    ## Can be negative (unlike timer.Duration)

const
  # Earlier spec versions had these at a different slot
  GENESIS_SLOT* = 0
  GENESIS_EPOCH* = 0

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/fork-choice.md#constant
  INTERVALS_PER_SLOT* = 3

  FAR_FUTURE_BEACON_TIME* = BeaconTime(ns_since_genesis: int64.high())

  NANOSECONDS_PER_SLOT* = SECONDS_PER_SLOT * 1_000_000_000'u64

template ethTimeUnit*(typ: type) {.dirty.} =
  func `+`*(x: typ, y: uint64): typ {.borrow.}
  func `-`*(x: typ, y: uint64): typ {.borrow.}
  func `-`*(x: uint64, y: typ): typ {.borrow.}

  # Not closed over type in question (Slot or uint64)
  func `mod`*(x: typ, y: uint64): uint64 {.borrow.}
  func `div`*(x: typ, y: uint64): uint64 {.borrow.}
  func `div`*(x: uint64, y: typ): uint64 {.borrow.}
  func `-`*(x: typ, y: typ): uint64 {.borrow.}

  iterator countdown*(a, b: typ, step: Positive = 1): typ =
    # otherwise we use the signed version that breaks at the boundary
    for i in countdown(distinctBase(a), distinctBase(b), step):
      yield typ(i)

  func `*`*(x: typ, y: uint64): uint64 {.borrow.}

  func `+=`*(x: var typ, y: typ) {.borrow.}
  func `+=`*(x: var typ, y: uint64) {.borrow.}
  func `-=`*(x: var typ, y: typ) {.borrow.}
  func `-=`*(x: var typ, y: uint64) {.borrow.}

  # Comparison operators
  func `<`*(x: typ, y: typ): bool {.borrow.}
  func `<`*(x: typ, y: uint64): bool {.borrow.}
  func `<`*(x: uint64, y: typ): bool {.borrow.}
  func `<=`*(x: typ, y: typ): bool {.borrow.}
  func `<=`*(x: typ, y: uint64): bool {.borrow.}
  func `<=`*(x: uint64, y: typ): bool {.borrow.}

  func `==`*(x: typ, y: typ): bool {.borrow.}
  func `==`*(x: typ, y: uint64): bool {.borrow.}
  func `==`*(x: uint64, y: typ): bool {.borrow.}

  # Nim integration
  func `$`*(x: typ): string {.borrow.}
  func hash*(x: typ): Hash {.borrow.}

  template asUInt64*(v: typ): uint64 = distinctBase(v)
  template shortLog*(v: typ): auto = distinctBase(v)

  # Serialization
  proc writeValue*(writer: var JsonWriter, value: typ) {.raises: [IOError].} =
    writeValue(writer, uint64 value)

  proc readValue*(reader: var JsonReader, value: var typ)
                 {.raises: [IOError, SerializationError].} =
    value = typ reader.readValue(uint64)

template `<`*(a, b: BeaconTime): bool = a.ns_since_genesis < b.ns_since_genesis
template `<=`*(a, b: BeaconTime): bool = a.ns_since_genesis <= b.ns_since_genesis
template `<`*(a, b: TimeDiff): bool = a.nanoseconds < b.nanoseconds
template `<=`*(a, b: TimeDiff): bool = a.nanoseconds <= b.nanoseconds
template `<`*(a: TimeDiff, b: Duration): bool = a.nanoseconds < b.nanoseconds

func toSlot*(t: BeaconTime): tuple[afterGenesis: bool, slot: uint64] =
  if t == FAR_FUTURE_BEACON_TIME:
    (true, (not 0'u64))
  elif t.ns_since_genesis >= 0:
    (true, uint64(uint64(t.ns_since_genesis) div NANOSECONDS_PER_SLOT))
  else:
    (false, uint64(uint64(-t.ns_since_genesis) div NANOSECONDS_PER_SLOT))

template `+`*(t: BeaconTime, offset: Duration | TimeDiff): BeaconTime =
  BeaconTime(ns_since_genesis: t.ns_since_genesis + offset.nanoseconds)

template `-`*(t: BeaconTime, offset: Duration | TimeDiff): BeaconTime =
  BeaconTime(ns_since_genesis: t.ns_since_genesis - offset.nanoseconds)

template `-`*(a, b: BeaconTime): TimeDiff =
  TimeDiff(nanoseconds: a.ns_since_genesis - b.ns_since_genesis)

template `+`*(a: TimeDiff, b: Duration): TimeDiff =
  TimeDiff(nanoseconds: a.nanoseconds + b.nanoseconds)

const
  # Offsets from the start of the slot to when the corresponding message should
  # be sent
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/validator.md#attesting
  attestationSlotOffset* = TimeDiff(nanoseconds:
    NANOSECONDS_PER_SLOT.int64 div INTERVALS_PER_SLOT)
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/validator.md#broadcast-aggregate
  aggregateSlotOffset* = TimeDiff(nanoseconds:
    NANOSECONDS_PER_SLOT.int64  * 2 div INTERVALS_PER_SLOT)
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/altair/validator.md#prepare-sync-committee-message
  syncCommitteeMessageSlotOffset* = TimeDiff(nanoseconds:
    NANOSECONDS_PER_SLOT.int64  div INTERVALS_PER_SLOT)
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/altair/validator.md#broadcast-sync-committee-contribution
  syncContributionSlotOffset* = TimeDiff(nanoseconds:
    NANOSECONDS_PER_SLOT.int64  * 2 div INTERVALS_PER_SLOT)
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/altair/light-client/p2p-interface.md#sync-committee
  lightClientFinalityUpdateSlotOffset* = TimeDiff(nanoseconds:
    NANOSECONDS_PER_SLOT.int64 div INTERVALS_PER_SLOT)
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/altair/light-client/p2p-interface.md#sync-committee
  lightClientOptimisticUpdateSlotOffset* = TimeDiff(nanoseconds:
    NANOSECONDS_PER_SLOT.int64 div INTERVALS_PER_SLOT)

func toFloatSeconds*(t: TimeDiff): float =
  float(t.nanoseconds) / 1_000_000_000.0

func start_beacon_time*(s: uint64): BeaconTime =
  # The point in time that a slot begins
  const maxSlot = uint64(
    uint64(FAR_FUTURE_BEACON_TIME.ns_since_genesis) div NANOSECONDS_PER_SLOT)
  if s > maxSlot: FAR_FUTURE_BEACON_TIME
  else: BeaconTime(ns_since_genesis: int64(uint64(s) * NANOSECONDS_PER_SLOT))

func block_deadline*(s: uint64): BeaconTime =
  s.start_beacon_time
func attestation_deadline*(s: uint64): BeaconTime =
  s.start_beacon_time + attestationSlotOffset
func aggregate_deadline*(s: uint64): BeaconTime =
  s.start_beacon_time + aggregateSlotOffset
func sync_committee_message_deadline*(s: uint64): BeaconTime =
  s.start_beacon_time + syncCommitteeMessageSlotOffset
func sync_contribution_deadline*(s: uint64): BeaconTime =
  s.start_beacon_time + syncContributionSlotOffset
func light_client_finality_update_time*(s: uint64): BeaconTime =
  s.start_beacon_time + lightClientFinalityUpdateSlotOffset
func light_client_optimistic_update_time*(s: uint64): BeaconTime =
  s.start_beacon_time + lightClientOptimisticUpdateSlotOffset

func slotOrZero*(time: BeaconTime): uint64 =
  let exSlot = time.toSlot
  if exSlot.afterGenesis: exSlot.slot
  else: uint64(0)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#compute_epoch_at_slot
func epoch*(slot: uint64): uint64 = # aka compute_epoch_at_slot
  ## Return the epoch number at ``slot``.
  if slot == (not 0'u64): (not 0'u64)
  else: uint64(slot div SLOTS_PER_EPOCH)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/fork-choice.md#compute_slots_since_epoch_start
func since_epoch_start*(slot: uint64): uint64 = # aka compute_slots_since_epoch_start
  ## How many slots since the beginning of the epoch (`[0..SLOTS_PER_EPOCH-1]`)
  (slot mod SLOTS_PER_EPOCH)

template is_epoch*(slot: uint64): bool =
  slot.since_epoch_start == 0

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#compute_start_slot_at_epoch
func start_slot*(epoch: uint64): uint64 = # aka compute_start_slot_at_epoch
  ## Return the start slot of ``epoch``.
  const maxEpoch = uint64((not 0'u64) div SLOTS_PER_EPOCH)
  if epoch >= maxEpoch: (not 0'u64)
  else: uint64(epoch * SLOTS_PER_EPOCH)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(current_epoch: uint64): uint64 =
  ## Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  if current_epoch == GENESIS_EPOCH:
    current_epoch
  else:
    current_epoch - 1

iterator slots*(epoch: uint64): uint64 =
  let start_slot = start_slot(epoch)
  for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
    yield slot

func proposer_dependent_slot*(epoch: uint64): uint64 =
  if epoch >= 1: epoch.start_slot() - 1 else: uint64(0)

func attester_dependent_slot*(epoch: uint64): uint64 =
  if epoch >= 2: (epoch - 1).start_slot() - 1 else: uint64(0)

func `$`*(t: BeaconTime): string =
  if t.ns_since_genesis >= 0:
    $(timer.nanoseconds(t.ns_since_genesis))
  else:
    "-" & $(timer.nanoseconds(-t.ns_since_genesis))

func `$`*(t: TimeDiff): string =
  if t.nanoseconds >= 0:
    $(timer.nanoseconds(t.nanoseconds))
  else:
    "-" & $(timer.nanoseconds(-t.nanoseconds))

func shortLog*(t: BeaconTime | TimeDiff): string = $t
