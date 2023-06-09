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
  ../spec/[forks_light_client, network]

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
