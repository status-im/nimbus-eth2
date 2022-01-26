# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables],
  stew/bitops2,
  ../spec/forks

export tables, forks

const
  MaxMissingItems = 1024
    ## Arbitrary
  MaxOrphans = SLOTS_PER_EPOCH * 3
    ## Enough for finalization in an alternative fork
  MaxUnviables = 16 * 1024
    ## About a day of blocks - most likely not needed but it's quite cheap..

type
  MissingBlock* = object
    tries*: int

  FetchRecord* = object
    root*: Eth2Digest

  Quarantine* = object
    ## Keeps track of unvalidated blocks coming from the network
    ## and that cannot yet be added to the chain
    ##
    ## This only stores blocks that cannot be linked to the
    ## ChainDAGRef DAG due to missing ancestor(s).
    ##
    ## Trivially invalid blocks may be dropped before reaching this stage.

    orphans*: Table[(Eth2Digest, ValidatorSig), ForkedSignedBeaconBlock]
      ## Blocks that we don't have a parent for - when we resolve the parent, we
      ## can proceed to resolving the block as well - we index this by root and
      ## signature such that a block with invalid signature won't cause a block
      ## with a valid signature to be dropped

    unviable*: OrderedTable[Eth2Digest, tuple[]]
      ## Unviable blocks are those from a different fork - we keep their hash
      ## around so that we can avoid cluttering the orphans table with their
      ## descendants - an ordered table is used to keep them in FIFO order more
      ## or less..

    missing*: Table[Eth2Digest, MissingBlock]
      ## Roots of blocks that we would like to have (either parent_root of
      ## unresolved blocks or block roots of attestations)

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

  if root in quarantine.unviable:
    # Won't get anywhere with this block
    return

  # It's not really missing if we're keeping it in the quarantine
  if anyIt(quarantine.orphans.keys,  it[0] == root):
    return

  # Add if it's not there, but don't update missing counter
  discard quarantine.missing.hasKeyOrPut(root, MissingBlock())

func removeOrphan*(
    quarantine: var Quarantine, signedBlock: ForkySignedBeaconBlock) =
  quarantine.orphans.del((signedBlock.root, signedBlock.signature))

func isViableOrphan(
    finalizedSlot: Slot, signedBlock: ForkedSignedBeaconBlock): bool =
  # The orphan must be newer than the finalization point so that its parent
  # either is the finalized block or more recent
  let
    slot = getForkedBlockField(signedBlock, slot)
  slot > finalizedSlot

func cleanupUnviable(quarantine: var Quarantine) =
  while quarantine.unviable.len() >= MaxUnviables:
    var toDel: Eth2Digest
    for k in quarantine.unviable.keys():
      toDel = k
      break # Cannot modify while for-looping
    quarantine.unviable.del(toDel)

func addUnviable*(quarantine: var Quarantine, root: Eth2Digest) =
  if root in quarantine.unviable:
    return

  quarantine.cleanupUnviable()

  # Remove the tree of orphans whose ancestor is unviable - they are now also
  # unviable! This helps avoiding junk in the quarantine, because we don't keep
  # unviable parents in the DAG and there's no way to tell an orphan from an
  # unviable block without the parent.
  var
    toRemove: seq[(Eth2Digest, ValidatorSig)] # Can't modify while iterating
    toCheck = @[root]
  while toCheck.len > 0:
    let root = toCheck.pop()
    for k, v in quarantine.orphans.mpairs():
      if getForkedBlockField(v, parent_root) == root:
        toCheck.add(k[0])
        toRemove.add(k)
      elif k[0] == root:
        toRemove.add(k)

    for k in toRemove:
      quarantine.orphans.del k
      quarantine.unviable.add(k[0], ())

    toRemove.setLen(0)

  quarantine.unviable.add(root, ())

func cleanupOrphans(quarantine: var Quarantine, finalizedSlot: Slot) =
  var toDel: seq[(Eth2Digest, ValidatorSig)]

  for k, v in quarantine.orphans.pairs():
    if not isViableOrphan(finalizedSlot, v):
      toDel.add k

  for k in toDel:
    quarantine.addUnviable k[0]

func clearQuarantine*(quarantine: var Quarantine) =
  quarantine = Quarantine()

# Typically, blocks will arrive in mostly topological order, with some
# out-of-order block pairs. Therefore, it is unhelpful to use either a
# FIFO or LIFO discpline, and since by definition each block gets used
# either 0 or 1 times it's not a cache either. Instead, stop accepting
# new blocks, and rely on syncing to cache up again if necessary.
#
# For typical use cases, this need not be large, as they're two or three
# blocks arriving out of order due to variable network delays. As blocks
# for future slots are rejected before reaching quarantine, this usually
# will be a block for the last couple of slots for which the parent is a
# likely imminent arrival.
func addOrphan*(
    quarantine: var Quarantine, finalizedSlot: Slot,
    signedBlock: ForkedSignedBeaconBlock): bool =
  ## Adds block to quarantine's `orphans` and `missing` lists.
  if not isViableOrphan(finalizedSlot, signedBlock):
    quarantine.addUnviable(signedBlock.root)
    return false

  quarantine.cleanupOrphans(finalizedSlot)

  let parent_root = getForkedBlockField(signedBlock, parent_root)

  if parent_root in quarantine.unviable:
    quarantine.unviable.add(signedBlock.root, ())
    return true

  # Even if the quarantine is full, we need to schedule its parent for
  # downloading or we'll never get to the bottom of things
  quarantine.addMissing(parent_root)

  if quarantine.orphans.lenu64 >= MaxOrphans:
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

  for k, v in quarantine.orphans.mpairs():
    if getForkedBlockField(v, parent_root) == root:
      toRemove.add(k)
      yield v
