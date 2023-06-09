# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[os, strformat],
  chronicles,
  ./spec/[
    beaconstate, eth2_ssz_serialization, eth2_merkleization, forks, helpers]

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

proc dump*(dir: string, v: ForkyLightClientBootstrap) =
  logErrors:
    let
      prefix = "bootstrap"
      slot = v.header.beacon.slot
      blck = shortLog(v.header.beacon.hash_tree_root())
      root = shortLog(v.hash_tree_root())
    SSZ.saveFile(
      dir / &"{prefix}-{slot}-{blck}-{root}.ssz", v)

proc dump*(dir: string, v: SomeForkyLightClientUpdate) =
  logErrors:
    let
      prefix =
        when v is ForkyLightClientUpdate:
          "update"
        elif v is ForkyLightClientFinalityUpdate:
          "finality-update"
        elif v is ForkyLightClientOptimisticUpdate:
          "optimistic-update"
      attestedSlot = v.attested_header.beacon.slot
      attestedBlck = shortLog(v.attested_header.beacon.hash_tree_root())
      syncCommitteeSuffix =
        when v is SomeForkyLightClientUpdateWithSyncCommittee:
          if v.is_sync_committee_update:
            "s"
          else:
            "x"
        else:
          ""
      finalitySuffix =
        when v is SomeForkyLightClientUpdateWithFinality:
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
