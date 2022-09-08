# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  std/[os, strformat],
  chronicles,
  ./spec/[
    beaconstate, eth2_ssz_serialization, eth2_merkleization, forks, helpers],
  ./spec/datatypes/[phase0, altair]

export
  beaconstate, eth2_ssz_serialization, eth2_merkleization, forks

# Dump errors are generally not fatal where used currently - the code calling
# these functions, like most code, is not exception safe
template logErrors(body: untyped) =
  try:
    body
  except CatchableError as err:
    notice "Failed to write SSZ", dir, msg = err.msg

proc dump*(dir: string, v: AttestationData, validator: ValidatorPubKey) =
  logErrors:
    SSZ.saveFile(dir / &"att-{v.slot}-{v.index}-{shortLog(validator)}.ssz", v)

proc dump*(dir: string, v: ForkyTrustedSignedBeaconBlock) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(v.root)}.ssz", v)

proc dump*(dir: string, v: ForkySignedBeaconBlock) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(v.root)}.ssz", v)

proc dump*(dir: string, v: ForkyHashedBeaconState) =
  mixin saveFile
  logErrors:
    SSZ.saveFile(
      dir / &"state-{v.data.slot}-{shortLog(v.latest_block_root)}-{shortLog(v.root)}.ssz",
      v.data)

proc dump*(dir: string, v: SyncCommitteeMessage, validator: ValidatorPubKey) =
  logErrors:
    SSZ.saveFile(dir / &"sync-committee-msg-{v.slot}-{shortLog(validator)}.ssz", v)

proc dump*(dir: string, v: altair.LightClientBootstrap) =
  logErrors:
    let
      prefix = "bootstrap"
      slot = v.header.slot
      blck = shortLog(v.header.hash_tree_root())
      root = shortLog(v.hash_tree_root())
    SSZ.saveFile(
      dir / &"{prefix}-{slot}-{blck}-{root}.ssz", v)

proc dump*(dir: string, v: SomeLightClientUpdate) =
  logErrors:
    let
      prefix =
        when v is altair.LightClientUpdate:
          "update"
        elif v is altair.LightClientFinalityUpdate:
          "finality-update"
        elif v is altair.LightClientOptimisticUpdate:
          "optimistic-update"
      attestedSlot = v.attested_header.slot
      attestedBlck = shortLog(v.attested_header.hash_tree_root())
      syncCommitteeSuffix =
        when v is SomeLightClientUpdateWithSyncCommittee:
          if v.is_sync_committee_update:
            "s"
          else:
            "x"
        else:
          ""
      finalitySuffix =
        when v is SomeLightClientUpdateWithFinality:
          if v.is_finality_update:
            "f"
          else:
            "x"
        else:
          ""
      suffix = syncCommitteeSuffix & finalitySuffix
      root = shortLog(v.hash_tree_root())
    SSZ.saveFile(
      dir / &"{prefix}-{attestedSlot}-{attestedBlck}-{suffix}-{root}.ssz", v)
