# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[os, strformat],
  chronicles,
  ./spec/[eth2_ssz_serialization, eth2_merkleization, forks],
  ./spec/datatypes/[phase0, altair, merge],
  ./consensus_object_pools/block_pools_types

export
  eth2_ssz_serialization, eth2_merkleization, forks, block_pools_types

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

proc dump*(dir: string, v: phase0.TrustedSignedBeaconBlock) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(v.root)}.ssz", v)

proc dump*(dir: string, v: altair.TrustedSignedBeaconBlock) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(v.root)}.ssz", v)

proc dump*(dir: string, v: phase0.SignedBeaconBlock) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(v.root)}.ssz", v)

proc dump*(dir: string, v: altair.SignedBeaconBlock) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(v.root)}.ssz", v)

proc dump*(dir: string, v: merge.SignedBeaconBlock) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(v.root)}.ssz", v)

proc dump*(dir: string, v: ForkyHashedBeaconState, blck: BlockRef) =
  mixin saveFile
  logErrors:
    SSZ.saveFile(
      dir / &"state-{v.data.slot}-{shortLog(blck.root)}-{shortLog(v.root)}.ssz",
      v.data)

proc dump*(dir: string, v: ForkyHashedBeaconState) =
  mixin saveFile
  logErrors:
    SSZ.saveFile(
      dir / &"state-{v.data.slot}-{shortLog(v.root)}.ssz",
      v.data)

proc dump*(dir: string, v: SyncCommitteeMessage, validator: ValidatorPubKey) =
  logErrors:
    SSZ.saveFile(dir / &"sync-committee-msg-{v.slot}-{shortLog(validator)}.ssz", v)
