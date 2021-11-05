# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, options],
  chronicles,
  stew/bitops2,
  eth/keys,
  ../spec/forks,
  ../spec/datatypes/[phase0, altair, merge],
  ./block_pools_types

export options, block_pools_types

logScope:
  topics = "quarant"

func init*(T: type QuarantineRef, rng: ref BrHmacDrbgContext, taskpool: TaskpoolPtr): T =
  T(rng: rng, taskpool: taskpool)

func checkMissing*(quarantine: QuarantineRef): seq[FetchRecord] =
  ## Return a list of blocks that we should try to resolve from other client -
  ## to be called periodically but not too often (once per slot?)
  var done: seq[Eth2Digest]

  for k, v in quarantine.missing.mpairs():
    if v.tries > 8:
      done.add(k)
    else:
      inc v.tries

  for k in done:
    quarantine.missing.del(k)

  # simple (simplistic?) exponential backoff for retries..
  for k, v in quarantine.missing.pairs():
    if countOnes(v.tries.uint64) == 1:
      result.add(FetchRecord(root: k))

# TODO stew/sequtils2
template anyIt(s, pred: untyped): bool =
  # https://github.com/nim-lang/Nim/blob/version-1-2/lib/pure/collections/sequtils.nim#L682-L704
  # without the items(...)
  var result = false
  for it {.inject.} in s:
    if pred:
      result = true
      break
  result

func containsOrphan*(
    quarantine: QuarantineRef, signedBlock: phase0.SignedBeaconBlock): bool =
  (signedBlock.root, signedBlock.signature) in quarantine.orphansPhase0

func containsOrphan*(
    quarantine: QuarantineRef, signedBlock: altair.SignedBeaconBlock): bool =
  (signedBlock.root, signedBlock.signature) in quarantine.orphansAltair

func containsOrphan*(
    quarantine: QuarantineRef, signedBlock: merge.SignedBeaconBlock): bool =
  (signedBlock.root, signedBlock.signature) in quarantine.orphansMerge

func addMissing*(quarantine: QuarantineRef, root: Eth2Digest) =
  ## Schedule the download a the given block
  # Can only request by root, not by signature, so partial match suffices
  if (not anyIt(quarantine.orphansMerge.keys,  it[0] == root)) and
     (not anyIt(quarantine.orphansAltair.keys, it[0] == root)) and
     (not anyIt(quarantine.orphansPhase0.keys, it[0] == root)):
    # If the block is in orphans, we no longer need it
    discard quarantine.missing.hasKeyOrPut(root, MissingBlock())

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of phase0.SomeSignedBeaconBlock from datatypes/phase0.nim
type SomeSignedPhase0Block =
  phase0.SignedBeaconBlock | phase0.SigVerifiedSignedBeaconBlock |
  phase0.TrustedSignedBeaconBlock
func removeOrphan*(
    quarantine: QuarantineRef, signedBlock: SomeSignedPhase0Block) =
  quarantine.orphansPhase0.del((signedBlock.root, signedBlock.signature))

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of altair.SomeSignedBeaconBlock from datatypes/altair.nim
type SomeSignedAltairBlock =
  altair.SignedBeaconBlock | altair.SigVerifiedSignedBeaconBlock |
  altair.TrustedSignedBeaconBlock
func removeOrphan*(
    quarantine: QuarantineRef, signedBlock: SomeSignedAltairBlock) =
  quarantine.orphansAltair.del((signedBlock.root, signedBlock.signature))

# TODO workaround for https://github.com/nim-lang/Nim/issues/18095
# copy of merge.SomeSignedBeaconBlock from datatypes/merge.nim
type SomeSignedMergeBlock =
  merge.SignedBeaconBlock | merge.SigVerifiedSignedBeaconBlock |
  merge.TrustedSignedBeaconBlock
func removeOrphan*(
    quarantine: QuarantineRef, signedBlock: SomeSignedMergeBlock) =
  quarantine.orphansMerge.del((signedBlock.root, signedBlock.signature))

func isViableOrphan(
    dag: ChainDAGRef, signedBlock: ForkySignedBeaconBlock): bool =
  # The orphan must be newer than the finalization point so that its parent
  # either is the finalized block or more recent
  signedBlock.message.slot > dag.finalizedHead.slot

func removeOldBlocks(quarantine: QuarantineRef, dag: ChainDAGRef) =
  var oldBlocks: seq[(Eth2Digest, ValidatorSig)]

  template removeNonviableOrphans(orphans: untyped) =
    for k, v in orphans.pairs():
      if not isViableOrphan(dag, v):
        oldBlocks.add k

    for k in oldBlocks:
      orphans.del k

  removeNonviableOrphans(quarantine.orphansPhase0)
  removeNonviableOrphans(quarantine.orphansAltair)
  removeNonviableOrphans(quarantine.orphansMerge)

func clearQuarantine*(quarantine: QuarantineRef) =
  quarantine.orphansPhase0.clear()
  quarantine.orphansAltair.clear()
  quarantine.orphansMerge.clear()
  quarantine.missing.clear()

# Typically, blocks will arrive in mostly topological order, with some
# out-of-order block pairs. Therefore, it is unhelpful to use either a
# FIFO or LIFO discpline, and since by definition each block gets used
# either 0 or 1 times it's not a cache either. Instead, stop accepting
# new blocks, and rely on syncing to cache up again if necessary. When
# using forward sync, blocks only arrive in an order not requiring the
# quarantine.
#
# For typical use cases, this need not be large, as they're two or three
# blocks arriving out of order due to variable network delays. As blocks
# for future slots are rejected before reaching quarantine, this usually
# will be a block for the last couple of slots for which the parent is a
# likely imminent arrival.

# Since we start forward sync when about one epoch is missing, that's as
# good a number as any.
const MAX_QUARANTINE_ORPHANS = SLOTS_PER_EPOCH

func add*(quarantine: QuarantineRef, dag: ChainDAGRef,
          signedBlock: phase0.SignedBeaconBlock): bool =
  ## Adds block to quarantine's `orphans` and `missing` lists.
  if not isViableOrphan(dag, signedBlock):
    return false

  quarantine.removeOldBlocks(dag)

  # Even if the quarantine is full, we need to schedule its parent for
  # downloading or we'll never get to the bottom of things
  quarantine.addMissing(signedBlock.message.parent_root)

  if quarantine.orphansPhase0.lenu64 >= MAX_QUARANTINE_ORPHANS:
    return false

  quarantine.orphansPhase0[(signedBlock.root, signedBlock.signature)] =
    signedBlock
  quarantine.missing.del(signedBlock.root)

  true

func add*(quarantine: QuarantineRef, dag: ChainDAGRef,
          signedBlock: altair.SignedBeaconBlock): bool =
  ## Adds block to quarantine's `orphans` and `missing` lists.
  if not isViableOrphan(dag, signedBlock):
    return false

  quarantine.removeOldBlocks(dag)

  # Even if the quarantine is full, we need to schedule its parent for
  # downloading or we'll never get to the bottom of things
  quarantine.addMissing(signedBlock.message.parent_root)

  if quarantine.orphansAltair.lenu64 >= MAX_QUARANTINE_ORPHANS:
    return false

  quarantine.orphansAltair[(signedBlock.root, signedBlock.signature)] =
    signedBlock
  quarantine.missing.del(signedBlock.root)

  true

func add*(quarantine: QuarantineRef, dag: ChainDAGRef,
          signedBlock: merge.SignedBeaconBlock): bool =
  ## Adds block to quarantine's `orphans` and `missing` lists.
  if not isViableOrphan(dag, signedBlock):
    return false

  quarantine.removeOldBlocks(dag)

  # Even if the quarantine is full, we need to schedule its parent for
  # downloading or we'll never get to the bottom of things
  quarantine.addMissing(signedBlock.message.parent_root)

  if quarantine.orphansMerge.lenu64 >= MAX_QUARANTINE_ORPHANS:
    return false

  quarantine.orphansMerge[(signedBlock.root, signedBlock.signature)] =
    signedBlock
  quarantine.missing.del(signedBlock.root)

  true
