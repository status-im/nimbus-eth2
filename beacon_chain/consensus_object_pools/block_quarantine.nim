# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables],
  chronicles,
  stew/bitops2,
  ../spec/forks,
  ./block_pools_types

export tables, forks, block_pools_types

const
  MaxMissingItems = 1024

type
  MissingBlock* = object
    tries*: int

  Quarantine* = object
    ## Keeps track of unvalidated blocks coming from the network
    ## and that cannot yet be added to the chain
    ##
    ## This only stores blocks that cannot be linked to the
    ## ChainDAGRef DAG due to missing ancestor(s).
    ##
    ## Trivially invalid blocks may be dropped before reaching this stage.

    orphans*: Table[(Eth2Digest, ValidatorSig), ForkedSignedBeaconBlock] ##\
    ## Blocks that we don't have a parent for - when we resolve the parent, we
    ## can proceed to resolving the block as well - we index this by root and
    ## signature such that a block with invalid signature won't cause a block
    ## with a valid signature to be dropped

    missing*: Table[Eth2Digest, MissingBlock] ##\
    ## Roots of blocks that we would like to have (either parent_root of
    ## unresolved blocks or block roots of attestations)

logScope:
  topics = "quarant"

func init*(T: type Quarantine): T =
  T()

func checkMissing*(quarantine: var Quarantine): seq[FetchRecord] =
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

func addMissing*(quarantine: var Quarantine, root: Eth2Digest) =
  ## Schedule the download a the given block
  if quarantine.missing.len >= MaxMissingItems:
    return

  # It's not really missing if we're keeping it in the quarantine
  if (not anyIt(quarantine.orphans.keys,  it[0] == root)):
    # If the block is in orphans, we no longer need it
    discard quarantine.missing.hasKeyOrPut(root, MissingBlock())

func removeOrphan*(
    quarantine: var Quarantine, signedBlock: ForkySignedBeaconBlock) =
  quarantine.orphans.del((signedBlock.root, signedBlock.signature))

func isViableOrphan(
    dag: ChainDAGRef, signedBlock: ForkedSignedBeaconBlock): bool =
  # The orphan must be newer than the finalization point so that its parent
  # either is the finalized block or more recent
  let slot = withBlck(signedBlock): blck.message.slot
  slot > dag.finalizedHead.slot

func removeOldBlocks(quarantine: var Quarantine, dag: ChainDAGRef) =
  var oldBlocks: seq[(Eth2Digest, ValidatorSig)]

  template removeNonviableOrphans(orphans: untyped) =
    for k, v in orphans.pairs():
      if not isViableOrphan(dag, v):
        oldBlocks.add k

    for k in oldBlocks:
      orphans.del k

  removeNonviableOrphans(quarantine.orphans)

func clearQuarantine*(quarantine: var Quarantine) =
  quarantine.orphans.clear()
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

func add*(quarantine: var Quarantine, dag: ChainDAGRef,
          signedBlock: ForkedSignedBeaconBlock): bool =
  ## Adds block to quarantine's `orphans` and `missing` lists.
  if not isViableOrphan(dag, signedBlock):
    return false

  quarantine.removeOldBlocks(dag)

  # Even if the quarantine is full, we need to schedule its parent for
  # downloading or we'll never get to the bottom of things
  withBlck(signedBlock): quarantine.addMissing(blck.message.parent_root)

  if quarantine.orphans.lenu64 >= MAX_QUARANTINE_ORPHANS:
    return false

  quarantine.orphans[(signedBlock.root, signedBlock.signature)] =
    signedBlock
  quarantine.missing.del(signedBlock.root)

  true

iterator pop*(quarantine: var Quarantine, root: Eth2Digest):
    ForkedSignedBeaconBlock =
  # Pop orphans whose parent is the block identified by `root`

  var toRemove: seq[(Eth2Digest, ValidatorSig)]
  defer: # Run even if iterator is not carried to termination
    for k in toRemove:
      quarantine.orphans.del k

  for k, v in quarantine.orphans:
    if getForkedBlockField(v, parent_root) == root:
      toRemove.add(k)
      yield v
