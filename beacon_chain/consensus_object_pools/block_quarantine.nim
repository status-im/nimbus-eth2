# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  chronicles, chronos,
  ../spec/[block_id, forks, presets]

export tables, forks

const
  MaxRetriesPerMissingItem = 7
    ## Exponential backoff, double interval between each attempt
  MaxMissingItems* = 1024
    ## Arbitrary
  MaxOrphans = SLOTS_PER_EPOCH * 3
    ## Enough for finalization in an alternative fork
  MaxSidecarless = SLOTS_PER_EPOCH * 128
    ## Arbitrary
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

    orphans*: OrderedTable[(Eth2Digest, ValidatorSig), ForkedSignedBeaconBlock]
      ## Blocks that we don't have a parent for - when we resolve the
      ## parent, we can proceed to resolving the block as well - we
      ## index this by root and signature such that a block with
      ## invalid signature won't cause a block with a valid signature
      ## to be dropped. An orphan block may also be "blobless" (see
      ## below) - if so, upon resolving the parent, it should be
      ## added to the blobless table, after verifying its signature.
    orphansEvent*: AsyncEvent
      ## Asynchronous event which will be set, when new block appears in
      ## orphans table.

    sidecarless*: OrderedTable[Eth2Digest, ForkedSignedBeaconBlock]
      ## Blocks that we don't have sidecars (BlobSidecar/DataColumnSidecar) for.
      ## When we have received all sidecars for this block, we can proceed to
      ## resolving the block as well. Block inserted into this table must
      ## have a resolved parent (i.e., it is not an orphan).
    sidecarlessEvent*: AsyncEvent
      ## Asynchronous event which will be set, when new block appears in
      ## sidecarless table.

    unviable*: OrderedTable[Eth2Digest, tuple[]]
      ## Unviable blocks are those that come from a history that does not
      ## include the finalized checkpoint we're currently following, and can
      ## therefore never be included in our canonical chain - we keep their hash
      ## around so that we can avoid cluttering the orphans table with their
      ## descendants - the ChainDAG only keeps track blocks that make up the
      ## valid and canonical history.
      ##
      ## Entries are evicted in FIFO order - recent entries are more likely to
      ## appear again in attestations and blocks - however, the unviable block
      ## table is not a complete directory of all unviable blocks circulating -
      ## only those we have observed, been able to verify as unviable and fit
      ## in this cache.

    last_block_slot*: Opt[BlockId]
      ## Stores the latest sidecarless block root and slot, in order to quickly
      ## fetch the latest info without having to traverse sidecarless
      ## quarantine.
    missing*: Table[Eth2Digest, MissingBlock]
      ## Roots of blocks that we would like to have (either parent_root of
      ## unresolved blocks or block roots of attestations)
    missingEvent*: AsyncEvent
      ## Asynchronous event which will be set, when new block appears in
      ## missing table.

    cfg*: RuntimeConfig

func init*(T: type Quarantine, cfg: RuntimeConfig): T =
  T(
    cfg: cfg,
    sidecarlessEvent: newAsyncEvent(),
    missingEvent: newAsyncEvent(),
    orphansEvent: newAsyncEvent()
  )

func checkMissing*(quarantine: var Quarantine, max: int): seq[FetchRecord] =
  ## Return a list of blocks that we should try to resolve from other client -
  ## to be called periodically but not too often (once per slot?)
  var done: seq[Eth2Digest]

  for k, v in quarantine.missing.mpairs():
    if v.tries > static(1 shl MaxRetriesPerMissingItem):
      done.add(k)

  for k in done:
    quarantine.missing.del(k)

  # simple (simplistic?) exponential backoff for retries..
  for k, v in quarantine.missing.mpairs:
    v.tries += 1
    if countOnes(v.tries.uint64) == 1:
      result.add(FetchRecord(root: k))
      if result.len >= max:
        break

proc addMissing*(quarantine: var Quarantine, root: Eth2Digest) =
  ## Schedule the download a the given block
  if quarantine.missing.len >= MaxMissingItems:
    return

  var r = root
  for i in 0 .. MaxOrphans:  # Blocks are not trusted, avoid endless loops
    if r in quarantine.unviable:
      # Won't get anywhere with this block
      return

    # It's not really missing if we're keeping it in the quarantine.
    # In that case, add the next missing parent root instead
    var found = false
    for k, blck in quarantine.orphans:
      if k[0] == r:
        r = getForkedBlockField(blck, parent_root)
        found = true
        break

    # Add if it's not there, but don't update missing counter
    if not found:
      discard quarantine.missing.hasKeyOrPut(r, MissingBlock())
      quarantine.missingEvent.fire()
      return

func removeOrphan*(
    quarantine: var Quarantine, signedBlock: ForkySignedBeaconBlock) =
  quarantine.orphans.del((signedBlock.root, signedBlock.signature))

func removeSidecarless*(
  quarantine: var Quarantine, signedBlock: ForkySignedBeaconBlock) =
  quarantine.sidecarless.del(signedBlock.root)

func isViable(
    finalizedSlot: Slot, slot: Slot): bool =
  # The orphan must be newer than the finalization point so that its parent
  # either is the finalized block or more recent
  slot > finalizedSlot

func cleanupUnviable(quarantine: var Quarantine) =
  while quarantine.unviable.len() >= MaxUnviables:
    var toDel: Eth2Digest
    for k in quarantine.unviable.keys():
      toDel = k
      break # Cannot modify while for-looping
    quarantine.unviable.del(toDel)

func removeUnviableOrphanTree(
    quarantine: var Quarantine,
    toCheck: var seq[Eth2Digest],
    tbl: var OrderedTable[(Eth2Digest, ValidatorSig), ForkedSignedBeaconBlock]
): seq[Eth2Digest] =
  # Remove the tree of orphans whose ancestor is unviable - they are now also
  # unviable! This helps avoiding junk in the quarantine, because we don't keep
  # unviable parents in the DAG and there's no way to tell an orphan from an
  # unviable block without the parent.
  var
    toRemove: seq[(Eth2Digest, ValidatorSig)] # Can't modify while iterating
    checked: seq[Eth2Digest]
  while toCheck.len > 0:
    let root = toCheck.pop()
    if root notin checked:
      checked.add(root)
    for k, v in tbl.mpairs():
      let blockRoot = getForkedBlockField(v, parent_root)
      if blockRoot == root:
        toCheck.add(k[0])
        toRemove.add(k)
      elif k[0] == root:
        toRemove.add(k)

    for k in toRemove:
      tbl.del k
      quarantine.unviable[k[0]] = ()

    toRemove.setLen(0)

  checked

func removeUnviableSidecarlessTree(
    quarantine: var Quarantine,
    toCheck: var seq[Eth2Digest],
    tbl: var OrderedTable[Eth2Digest, ForkedSignedBeaconBlock]) =
  var
    toRemove: seq[Eth2Digest] # Can't modify while iterating
  while toCheck.len > 0:
    let root = toCheck.pop()
    for k, v in tbl.mpairs():
      let blockRoot =
        withBlck(v):
          forkyBlck.message.parent_root
      if blockRoot == root:
        toCheck.add(k)
        toRemove.add(k)
      elif k == root:
        toRemove.add(k)

    for k in toRemove:
      tbl.del k
      quarantine.unviable[k] = ()

    toRemove.setLen(0)

func addUnviable*(quarantine: var Quarantine, root: Eth2Digest) =
  # Unviable - don't try to download again!
  quarantine.missing.del(root)

  if root in quarantine.unviable:
    return

  quarantine.cleanupUnviable()
  var toCheck = @[root]
  var checked = quarantine.removeUnviableOrphanTree(toCheck, quarantine.orphans)
  quarantine.removeUnviableSidecarlessTree(checked, quarantine.sidecarless)

  quarantine.unviable[root] = ()

func cleanupOrphans(quarantine: var Quarantine, finalizedSlot: Slot) =
  var toDel: seq[(Eth2Digest, ValidatorSig)]

  for k, v in quarantine.orphans:
    if not isViable(finalizedSlot, getForkedBlockField(v, slot)):
      toDel.add k

  for k in toDel:
    quarantine.addUnviable k[0]
    quarantine.orphans.del k

func cleanupSidecarless(quarantine: var Quarantine, finalizedSlot: Slot) =
  var toDel: seq[Eth2Digest]

  for k, v in quarantine.sidecarless:
    withBlck(v):
      if not isViable(finalizedSlot, forkyBlck.message.slot):
        toDel.add k

  for k in toDel:
    quarantine.addUnviable k
    quarantine.sidecarless.del k

func clearAfterReorg*(quarantine: var Quarantine) =
  ## Clear missing and orphans to start with a fresh slate in case of a reorg
  ## Unviables remain unviable and are not cleared.
  quarantine.missing.reset()
  quarantine.orphans.reset()

func pruneAfterFinalization*(
    quarantine: var Quarantine,
    epoch: Epoch,
    needsBackfill: bool
) =
  let
    startEpoch =
      if needsBackfill:
        # Because Quarantine could be used as temporary storage for blocks which
        # do not have sidecars yet, we should not prune blocks which are behind
        # `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` epoch. Otherwise we will not
        # be able to backfill these blocks properly.
        if epoch < quarantine.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS:
          Epoch(0)
        else:
          epoch - quarantine.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS
      else:
        epoch
    slot = startEpoch.start_slot()

  quarantine.cleanupSidecarless(slot)

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
proc addOrphan*(
    quarantine: var Quarantine,
    finalizedSlot: Slot,
    signedBlock: ForkedSignedBeaconBlock
): Result[void, cstring] =
  ## Adds block to quarantine's `orphans` and `missing` lists.

  if not isViable(finalizedSlot, getForkedBlockField(signedBlock, slot)):
    quarantine.addUnviable(signedBlock.root) # will remove from missing
    return err("block unviable")

  quarantine.cleanupOrphans(finalizedSlot)

  let parent_root = getForkedBlockField(signedBlock, parent_root)

  if parent_root in quarantine.unviable:
    quarantine.addUnviable(signedBlock.root)
    return err("block parent unviable")

  # It's no longer missing if we downloaded it - remove before adding to make
  # sure parent chains get downloaded even if missing list is full (works as
  # long as the orphan was in the missing list, which is likely)
  quarantine.missing.del(signedBlock.root)

  # Even if the quarantine is full, we need to schedule its parent for
  # downloading or we'll never get to the bottom of things
  quarantine.addMissing(parent_root)

  if quarantine.orphans.lenu64 >= MaxOrphans:
    # Evict based on FIFO
    var oldest_orphan_key: (Eth2Digest, ValidatorSig)
    for k in quarantine.orphans.keys:
      oldest_orphan_key = k
      break
    quarantine.orphans.del oldest_orphan_key
    quarantine.sidecarless.del oldest_orphan_key[0]

  quarantine.orphans[(signedBlock.root, signedBlock.signature)] = signedBlock
  quarantine.orphansEvent.fire()

  ok()

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

proc addSidecarless(
    quarantine: var Quarantine, finalizedSlot: Opt[Slot],
    signedBlock: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
                 fulu.SignedBeaconBlock | gloas.SignedBeaconBlock
): bool =
  if finalizedSlot.isSome():
    if not isViable(finalizedSlot.get(), signedBlock.message.slot):
      quarantine.addUnviable(signedBlock.root)
      return false

  if quarantine.sidecarless.lenu64 >= MaxSidecarless:
    var oldestKey: Eth2Digest
    for k in quarantine.sidecarless.keys:
      oldestKey = k
      break
    quarantine.sidecarless.del(oldestKey)

  debug "Block without sidecars has been added to the quarantine",
        block_root = shortLog(signedBlock.root)
  quarantine.sidecarless[signedBlock.root] =
    ForkedSignedBeaconBlock.init(signedBlock)
  quarantine.last_block_slot =
    Opt.some(BlockId(slot: signedBlock.message.slot, root: signedBlock.root))
  quarantine.missing.del(signedBlock.root)
  quarantine.sidecarlessEvent.fire()
  true

proc addSidecarless*(
  quarantine: var Quarantine, finalizedSlot: Slot,
  signedBlock: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
               fulu.SignedBeaconBlock | gloas.SignedBeaconBlock
): bool =
  quarantine.addSidecarless(Opt.some(finalizedSlot), signedBlock)

proc addSidecarless*(
  quarantine: var Quarantine,
  signedBlock: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
               fulu.SignedBeaconBlock | gloas.SignedBeaconBlock
) =
  discard quarantine.addSidecarless(Opt.none(Slot), signedBlock)

proc addColumnless*(
    quarantine: var Quarantine, finalizedSlot: Slot,
    signedBlock: fulu.SignedBeaconBlock | gloas.SignedBeaconBlock
): bool {.deprecated.} =
  quarantine.addSidecarless(finalizedSlot, signedBlock)

func popSidecarless*(
    quarantine: var Quarantine,
    root: Eth2Digest
): Opt[ForkedSignedBeaconBlock] =
  var blck: ForkedSignedBeaconBlock
  if quarantine.sidecarless.pop(root, blck):
    Opt.some(blck)
  else:
    Opt.none(ForkedSignedBeaconBlock)

func popColumnless*(
    quarantine: var Quarantine,
    root: Eth2Digest
): Opt[ForkedSignedBeaconBlock] {.deprecated.} =
  quarantine.popSidecarless(root)

func getColumnless*(
    quarantine: var Quarantine,
    root: Eth2Digest): Opt[ForkedSignedBeaconBlock] =
  try:
    Opt.some(quarantine.sidecarless[root])
  except KeyError:
    Opt.none(ForkedSignedBeaconBlock)

iterator peekSidecarless*(
    quarantine: var Quarantine
): ForkedSignedBeaconBlock =
  for k, v in quarantine.sidecarless.mpairs():
    yield v
