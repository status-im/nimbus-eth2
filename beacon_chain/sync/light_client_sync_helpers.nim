# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/typetraits,
  chronos,
  stew/base10,
  eth/p2p/discoveryv5/random2,
  ../spec/[forks_light_client, network],
  ../beacon_clock

func checkLightClientUpdates*(
    updates: openArray[ForkedLightClientUpdate],
    startPeriod: SyncCommitteePeriod,
    count: uint64): Result[void, string] =
  if updates.lenu64 > count:
    return err("Too many values in response" &
      " (" & Base10.toString(updates.lenu64) &
      " > " & Base10.toString(count.uint) & ")")
  let lastPeriod = startPeriod + count - 1
  var expectedPeriod = startPeriod
  for update in updates:
    withForkyUpdate(update):
      when lcDataFork > LightClientDataFork.None:
        let
          attPeriod =
            forkyUpdate.attested_header.beacon.slot.sync_committee_period
          sigPeriod = forkyUpdate.signature_slot.sync_committee_period
        if attPeriod != sigPeriod:
          return err("Conflicting sync committee periods" &
            " (signature: " & Base10.toString(distinctBase(sigPeriod)) &
            " != " & Base10.toString(distinctBase(attPeriod)) & ")")
        if attPeriod < expectedPeriod:
          return err("Unexpected sync committee period" &
            " (" & Base10.toString(distinctBase(attPeriod)) &
            " < " & Base10.toString(distinctBase(expectedPeriod)) & ")")
        if attPeriod > expectedPeriod:
          if attPeriod > lastPeriod:
            return err("Sync committee period too high" &
              " (" & Base10.toString(distinctBase(attPeriod)) &
              " > " & Base10.toString(distinctBase(lastPeriod)) & ")")
          expectedPeriod = attPeriod
        inc expectedPeriod
      else:
        return err("Invalid context bytes")
  ok()

proc isGossipSupported*(
    period: SyncCommitteePeriod,
    finalizedPeriod: SyncCommitteePeriod,
    isNextSyncCommitteeKnown: bool): bool =
  if isNextSyncCommitteeKnown:
    period <= finalizedPeriod + 1
  else:
    period <= finalizedPeriod

type SchedulingMode* {.pure.} = enum
  Soon,
  CurrentPeriod,
  NextPeriod

func nextLightClientFetchTime*(
    rng: ref SecureRngContext,
    wallTime: BeaconTime,
    schedulingMode: SchedulingMode
): BeaconTime =
  let
    remainingTime =
      case schedulingMode:
      of SchedulingMode.Soon:
        chronos.seconds(0)
      of SchedulingMode.CurrentPeriod:
        let
          wallPeriod = wallTime.slotOrZero().sync_committee_period
          deadlineSlot = (wallPeriod + 1).start_slot - 1
          deadline = deadlineSlot.start_beacon_time()
        chronos.nanoseconds((deadline - wallTime).nanoseconds)
      of SchedulingMode.NextPeriod:
        chronos.seconds(
          (SLOTS_PER_SYNC_COMMITTEE_PERIOD * SECONDS_PER_SLOT).int64)
    minDelay = max(remainingTime div 8, chronos.seconds(10))
    jitterSeconds = (minDelay * 2).seconds
    jitterDelay = chronos.seconds(rng[].rand(jitterSeconds).int64)
  return wallTime + minDelay + jitterDelay

type
  LCSyncKind* {.pure.} = enum
    UpdatesByRange
    FinalityUpdate
    OptimisticUpdate

  LCSyncTask* = object
    case kind*: LCSyncKind
    of LCSyncKind.UpdatesByRange:
      startPeriod*: SyncCommitteePeriod
      count*: uint64
    of LCSyncKind.FinalityUpdate, LCSyncKind.OptimisticUpdate:
      discard

func nextLightClientSyncTask*(
    finalized: SyncCommitteePeriod,
    optimistic: SyncCommitteePeriod,
    current: SyncCommitteePeriod,
    isNextSyncCommitteeKnown: bool): LCSyncTask =
  if finalized == optimistic and not isNextSyncCommitteeKnown:
    if finalized >= current:
      LCSyncTask(
        kind: LCSyncKind.UpdatesByRange,
        startPeriod: finalized,
        count: 1)
    else:
      LCSyncTask(
        kind: LCSyncKind.UpdatesByRange,
        startPeriod: finalized,
        count: min(current - finalized, MAX_REQUEST_LIGHT_CLIENT_UPDATES))
  elif finalized + 1 < current:
    LCSyncTask(
      kind: LCSyncKind.UpdatesByRange,
      startPeriod: finalized + 1,
      count: min(current - (finalized + 1), MAX_REQUEST_LIGHT_CLIENT_UPDATES))
  elif finalized != optimistic:
    LCSyncTask(kind: LCSyncKind.FinalityUpdate)
  else:
    LCSyncTask(kind: LCSyncKind.OptimisticUpdate)
