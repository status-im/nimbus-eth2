# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles, tables, options,
  stew/bitops2,
  metrics,
  ../spec/[crypto, datatypes, digest],
  block_pools_types

export options, block_pools_types

logScope:
  topics = "quarant"

{.push raises: [Defect].}

func checkMissing*(quarantine: var QuarantineRef): seq[FetchRecord] =
  ## Return a list of blocks that we should try to resolve from other client -
  ## to be called periodically but not too often (once per slot?)
  var done: seq[Eth2Digest]

  for k, v in quarantine.missing.mpairs():
    if v.tries > 8:
      done.add(k)
    else:
      inc v.tries

  for k in done:
    # TODO Need to potentially remove from quarantine.pending - this is currently a
    #      memory leak here!
    quarantine.missing.del(k)

  # simple (simplistic?) exponential backoff for retries..
  for k, v in quarantine.missing.pairs():
    if countOnes(v.tries.uint64) == 1:
      result.add(FetchRecord(root: k))

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
    quarantine: QuarantineRef, signedBlock: SignedBeaconBlock): bool =
  (signedBlock.root, signedBlock.signature) in quarantine.orphans

func addMissing*(quarantine: var QuarantineRef, root: Eth2Digest) =
  ## Schedule the download a the given block
  # Can only request by root, not by signature, so partial match suffices
  if not anyIt(quarantine.orphans.keys, it[0] == root):
    # If the block is in orphans, we no longer need it
    discard quarantine.missing.hasKeyOrPut(root, MissingBlock())

func removeOrphan*(
    quarantine: var QuarantineRef, signedBlock: SignedBeaconBlock) =
  quarantine.orphans.del((signedBlock.root, signedBlock.signature))

func removeOldBlocks(quarantine: var QuarantineRef, dag: ChainDAGRef) =
  var oldBlocks: seq[(Eth2Digest, ValidatorSig)]

  for k, v in quarantine.orphans.pairs():
    if v.message.slot <= dag.finalizedHead.slot:
      oldBlocks.add k

  for k in oldBlocks:
    quarantine.orphans.del k

func clearQuarantine*(quarantine: var QuarantineRef) =
  quarantine.orphans.clear()
  quarantine.missing.clear()

func add*(quarantine: var QuarantineRef, dag: ChainDAGRef,
          signedBlock: SignedBeaconBlock): bool =
  ## Adds block to quarantine's `orphans` and `missing` lists.

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
  const MAX_QUARANTINE_ORPHANS = 10

  quarantine.removeOldBlocks(dag)

  if quarantine.orphans.len >= MAX_QUARANTINE_ORPHANS:
    return false

  quarantine.orphans[(signedBlock.root, signedBlock.signature)] = signedBlock
  quarantine.missing.del(signedBlock.root)

  quarantine.addMissing(signedBlock.message.parent_root)

  true
