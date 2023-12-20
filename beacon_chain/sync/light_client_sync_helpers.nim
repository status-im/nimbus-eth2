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
    count: uint64,
): Result[void, string] =
  if updates.lenu64 > count:
    return err(
      "Too many values in response" & " (" & Base10.toString(updates.lenu64) & " > " &
        Base10.toString(count.uint) & ")"
    )
  let lastPeriod = startPeriod + count - 1
  var expectedPeriod = startPeriod
  for update in updates:
    withForkyUpdate(update):
      when lcDataFork > LightClientDataFork.None:
        let
          attPeriod = forkyUpdate.attested_header.beacon.slot.sync_committee_period
          sigPeriod = forkyUpdate.signature_slot.sync_committee_period
        if attPeriod != sigPeriod:
          return err(
            "Conflicting sync committee periods" & " (signature: " &
              Base10.toString(distinctBase(sigPeriod)) & " != " &
              Base10.toString(distinctBase(attPeriod)) & ")"
          )
        if attPeriod < expectedPeriod:
          return err(
            "Unexpected sync committee period" & " (" &
              Base10.toString(distinctBase(attPeriod)) & " < " &
              Base10.toString(distinctBase(expectedPeriod)) & ")"
          )
        if attPeriod > expectedPeriod:
          if attPeriod > lastPeriod:
            return err(
              "Sync committee period too high" & " (" &
                Base10.toString(distinctBase(attPeriod)) & " > " &
                Base10.toString(distinctBase(lastPeriod)) & ")"
            )
          expectedPeriod = attPeriod
        inc expectedPeriod
      else:
        return err("Invalid context bytes")
  ok()

func isGossipSupported*(
    period: SyncCommitteePeriod,
    finalizedPeriod: SyncCommitteePeriod,
    isNextSyncCommitteeKnown: bool,
): bool =
  if isNextSyncCommitteeKnown:
    period <= finalizedPeriod + 1
  else:
    period <= finalizedPeriod

type
  LcSyncKind* {.pure.} = enum
    UpdatesByRange
    FinalityUpdate
    OptimisticUpdate

  LcSyncTask* = object
    case kind*: LcSyncKind
    of LcSyncKind.UpdatesByRange:
      startPeriod*: SyncCommitteePeriod
      count*: uint64
    of LcSyncKind.FinalityUpdate, LcSyncKind.OptimisticUpdate:
      discard

func nextLightClientSyncTask*(
    current: SyncCommitteePeriod,
    finalized: SyncCommitteePeriod,
    optimistic: SyncCommitteePeriod,
    isNextSyncCommitteeKnown: bool,
): LcSyncTask =
  if finalized == optimistic and not isNextSyncCommitteeKnown:
    if finalized >= current:
      LcSyncTask(kind: LcSyncKind.UpdatesByRange, startPeriod: finalized, count: 1)
    else:
      LcSyncTask(
        kind: LcSyncKind.UpdatesByRange,
        startPeriod: finalized,
        count: min(current - finalized, MAX_REQUEST_LIGHT_CLIENT_UPDATES),
      )
  elif finalized + 1 < current:
    LcSyncTask(
      kind: LcSyncKind.UpdatesByRange,
      startPeriod: finalized + 1,
      count: min(current - (finalized + 1), MAX_REQUEST_LIGHT_CLIENT_UPDATES),
    )
  elif finalized != optimistic:
    LcSyncTask(kind: LcSyncKind.FinalityUpdate)
  else:
    LcSyncTask(kind: LcSyncKind.OptimisticUpdate)

func computeDelayWithJitter*(rng: ref HmacDrbgContext, duration: Duration): Duration =
  let
    minDelay = max(duration div 8, chronos.seconds(10))
    jitterSeconds = (minDelay * 2).seconds
    jitterDelay = chronos.seconds(rng[].rand(jitterSeconds).int64)
  minDelay + jitterDelay

func nextLcSyncTaskDelay*(
    rng: ref HmacDrbgContext,
    wallTime: BeaconTime,
    finalized: SyncCommitteePeriod,
    optimistic: SyncCommitteePeriod,
    isNextSyncCommitteeKnown: bool,
    didLatestSyncTaskProgress: bool,
): Duration =
  let
    current = wallTime.slotOrZero().sync_committee_period
    remainingDuration =
      if not current.isGossipSupported(finalized, isNextSyncCommitteeKnown):
        if didLatestSyncTaskProgress:
          # Now
          return chronos.seconds(0)
        # Soon
        chronos.seconds(0)
      elif finalized != optimistic:
        # Current sync committee period
        let
          wallPeriod = wallTime.slotOrZero().sync_committee_period
          deadlineSlot = (wallPeriod + 1).start_slot - 1
          deadline = deadlineSlot.start_beacon_time()
        chronos.nanoseconds((deadline - wallTime).nanoseconds)
      else:
        # Next sync committee period
        chronos.seconds((SLOTS_PER_SYNC_COMMITTEE_PERIOD * SECONDS_PER_SLOT).int64)
  rng.computeDelayWithJitter(remainingDuration)
