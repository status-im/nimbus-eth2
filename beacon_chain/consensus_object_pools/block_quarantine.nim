# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/tables, minilru, chronicles, ../spec/[block_id, forks, presets]

export tables, minilru, forks

const
  MaxRetriesPerMissingItem = 7
    ## Exponential backoff, double interval between each attempt
  MaxMissingItems* = 1024
    ## Arbitrary
  MaxOrphans = int(SLOTS_PER_EPOCH * 3)
    ## Enough for finalization in an alternative fork
  MaxSidecarless = int(SLOTS_PER_EPOCH * 128)
    ## Arbitrary
  MaxUnviables = 16 * 1024
    ## About a day of blocks - most likely not needed but it's quite cheap..
  MaxRecentSidecarSignatures = 128
    ## Cache recent valid sidecar signatures to avoid re-verification

type
  MissingBlock* = object
    tries*: int

  FetchRecord* = object
    root*: Eth2Digest

  UnviableKind* {.pure.} = enum
    UnviableFork
    Invalid

  OrphanLru = LruCache[(Eth2Digest, ValidatorSig), ForkedSignedBeaconBlock]
  SidecarlessLru = LruCache[Eth2Digest, ForkedSignedBeaconBlock]
  UnviableLru = LruCache[Eth2Digest, UnviableKind]
  RecentSidecarSignatureLru* = LruCache[(Eth2Digest, ValidatorSig), tuple[]]
    ## Cache of (block_root, signature) pairs that have been verified
    ## The value is an empty tuple since we only care about presence

  Quarantine* = object
    ## Keeps track of unvalidated blocks coming from the network
    ## and that cannot yet be added to the chain
    ##
    ## This only stores blocks that cannot be linked to the
    ## ChainDAGRef DAG due to missing ancestor(s).
    ##
    ## Trivially invalid blocks may be dropped before reaching this stage.
    orphans*: OrphanLru
      ## Blocks that we don't have a parent for - when we resolve the
      ## parent, we can proceed to resolving the block as well - we
      ## index this by root and signature such that a block with
      ## invalid signature won't cause a block with a valid signature
      ## to be dropped. An orphan block may also be "blobless" (see
      ## below) - if so, upon resolving the parent, it should be
      ## added to the blobless table, after verifying its signature.

    sidecarless*: SidecarlessLru
      ## Blocks that we don't have sidecars (BlobSidecar/DataColumnSidecar) for.
      ## When we have received all sidecars for this block, we can proceed to
      ## resolving the block as well. Block inserted into this table must
      ## have a resolved parent (i.e., it is not an orphan).

    unviable*: UnviableLru
      ## Unviable blocks are those that can no longer be included in the
      ## canonical chain either because the fork they were on became unviable
      ## due to finalization or because they were invalid.
      ##
      ## We keep their hash around so that we can avoid cluttering the orphans
      ## table with their descendants - the ChainDAG only keeps track blocks
      ## that make up the valid and canonical history.
      ##
      ## Entries are evicted in FIFO order - recent entries are more likely to
      ## appear again in attestations and blocks - however, the unviable block
      ## table is not a complete directory of all unviable blocks circulating -
      ## only those we have observed, been able to verify as unviable and fit
      ## in this cache.

    missing*: Table[Eth2Digest, MissingBlock]
      ## Roots of blocks that we would like to have (either parent_root of
      ## unresolved blocks or block roots of attestations)

    processing: Eth2Digest
      ## This block is currently being processed and should therefore not be
      ## added to the quarantine

    latest_sidecar_signatures*: RecentSidecarSignatureLru
      ## This caches recently verified sidecar signatures (block_root, signature),
      ## so as to skip expensive cryptographic verification if the same block root
      ## and signature combination arrives multiple times over gossip

    cfg*: RuntimeConfig

func init*(T: type Quarantine, cfg: RuntimeConfig): T =
  T(
    cfg: cfg,
    orphans: OrphanLru.init(MaxOrphans),
    sidecarless: SidecarlessLru.init(MaxSidecarless),
    unviable: UnviableLru.init(MaxUnviables),
    latest_sidecar_signatures: RecentSidecarSignatureLru.init(MaxRecentSidecarSignatures),
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

proc addMissing*(quarantine: var Quarantine, root: Eth2Digest): Result[void, UnviableKind] =
  ## Schedule the download a given block or its ancestor, if we're keeping
  ## track of it as an orphan

  # If the block is unviable, tell the caller
  quarantine.unviable.get(root).isErrOr:
    return err(value)

  if quarantine.missing.len >= MaxMissingItems:
    # The block might still be viable, but we don't have space to investigate
    return ok()

  if root == quarantine.processing:
    # It's not in flight if we're in the middle of processing it
    return ok()

  var r = root
  for i in 0 .. MaxOrphans:  # Blocks are not trusted, avoid endless loops
    # It's not really missing if we're keeping it in the quarantine.
    # In that case, add the next missing parent root instead
    var found = false
    for k, blck in quarantine.orphans:
      if k[0] == r:
        r = blck.parent_root
        found = true
        break

    # Add if it's not there, but don't update missing counter
    if not found:
      discard quarantine.missing.hasKeyOrPut(r, MissingBlock())
      break

  ok()

func remove*(quarantine: var Quarantine, signedBlock: ForkySignedBeaconBlock) =
  quarantine.orphans.del((signedBlock.root, signedBlock.signature))
  quarantine.sidecarless.del(signedBlock.root)
  quarantine.missing.del(signedBlock.root)

func startProcessing*(quarantine: var Quarantine, signedBlock: ForkySignedBeaconBlock) =
  quarantine.remove(signedBlock)
  quarantine.processing = signedBlock.root

func clearProcessing*(quarantine: var Quarantine) =
  quarantine.processing.reset()

func isUnviableFork(blck: ForkyBeaconBlock, finalizedSlot: Slot): bool =
  # Block is from a fork that for certain will not be included in the canonical
  # chain - notably, the block may still turn out to be unviable when its
  # ancestors have been processed and one of _them_ is unviable.
  blck.slot <= finalizedSlot

func removeUnviableOrphanTree(
    quarantine: var Quarantine, toCheck: var seq[Eth2Digest], kind: UnviableKind
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
    for k, v in quarantine.orphans.mpairs():
      if v.parent_root == root:
        toCheck.add(k[0])
        toRemove.add(k)
      elif k[0] == root:
        toRemove.add(k)

    for k in toRemove:
      quarantine.orphans.del k
      quarantine.unviable.put(k[0], kind)

    toRemove.setLen(0)

  checked

func removeUnviableSidecarlessTree(
    quarantine: var Quarantine, toCheck: var seq[Eth2Digest], kind: UnviableKind
) =
  var toRemove: seq[Eth2Digest] # Can't modify while iterating
  while toCheck.len > 0:
    let root = toCheck.pop()
    for k, v in quarantine.sidecarless.mpairs():
      let blockRoot = withBlck(v):
        forkyBlck.message.parent_root
      if blockRoot == root:
        toCheck.add(k)
        toRemove.add(k)
      elif k == root:
        toRemove.add(k)

    for k in toRemove:
      quarantine.sidecarless.del k
      quarantine.unviable.put(k, kind)

    toRemove.setLen(0)

func addUnviable*(quarantine: var Quarantine, root: Eth2Digest, kind: UnviableKind): UnviableKind =
  # Unviable - don't try to download again!
  quarantine.missing.del(root)

  quarantine.unviable.get(root).isErrOr:
    # If the block was already in unviable, don't downgrade `Invalid` to `UnviableFork`
    if kind == UnviableKind.Invalid and value == UnviableKind.UnviableFork:
      # Previously "UnviableFork", now "invalid" - this can potentially happen when
      # an `UnviableFork` blob races with an `Invalid` block.
      quarantine.unviable.put(root, kind)
      return kind
    return value

  var toCheck = @[root]
  var checked = quarantine.removeUnviableOrphanTree(toCheck, kind)
  quarantine.removeUnviableSidecarlessTree(checked, kind)

  quarantine.unviable.put(root, kind)
  kind

func cleanupOrphans(quarantine: var Quarantine, finalizedSlot: Slot) =
  var toDel: seq[(Eth2Digest, ValidatorSig)]

  for k, v in quarantine.orphans:
    if withBlck(v, forkyBlck.message.isUnviableFork(finalizedSlot)):
      toDel.add k

  for k in toDel:
    discard quarantine.addUnviable(k[0], UnviableKind.UnviableFork)
    quarantine.orphans.del k

func cleanupSidecarless(quarantine: var Quarantine, finalizedSlot: Slot) =
  var toDel: seq[Eth2Digest]

  for k, v in quarantine.sidecarless:
    if withBlck(v, forkyBlck.message.isUnviableFork(finalizedSlot)):
      toDel.add k

  for k in toDel:
    discard quarantine.addUnviable(k, UnviableKind.UnviableFork)
    quarantine.sidecarless.del k

func clearAfterReorg*(quarantine: var Quarantine) =
  ## Clear missing and orphans to start with a fresh slate in case of a reorg
  ## Unviables remain unviable and are not cleared.
  quarantine.missing.reset()
  quarantine.orphans.reset()

func pruneAfterFinalization*(
    quarantine: var Quarantine, epoch: Epoch, needsBackfill: bool
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
    signedBlock: ForkySignedBeaconBlock
): Result[void, UnviableKind] =
  ## Adds block to quarantine's `orphans` and `missing` lists assuming the
  ## parent isn't unviable
  quarantine.cleanupOrphans(finalizedSlot)

  let parent_root = signedBlock.message.parent_root
  quarantine.unviable.get(parent_root).isErrOr:
    # Inherit unviable kind from parent
    return err(quarantine.addUnviable(signedBlock.root, value))

  if signedBlock.message.isUnviableFork(finalizedSlot):
    # will remove from missing
    return err(quarantine.addUnviable(signedBlock.root, UnviableKind.UnviableFork))

  if signedBlock.root == quarantine.processing:
    return ok()

  # It's no longer missing if we downloaded it - remove before adding to make
  # sure parent chains get downloaded even if missing list is full (works as
  # long as the orphan was in the missing list, which is likely)
  quarantine.missing.del(signedBlock.root)

  # Even if the quarantine is full, we need to schedule its parent for
  # downloading or we'll never get to the bottom of things
  discard quarantine.addMissing(parent_root)

  for (evicted, key, _) in quarantine.orphans.putWithEvicted(
    (signedBlock.root, signedBlock.signature), ForkedSignedBeaconBlock.init(signedBlock)
  ):
    if evicted:
      # When an orphan gets evicted, also evict the sidecars
      quarantine.sidecarless.del key[0]

  ok()

iterator pop*(quarantine: var Quarantine, root: Eth2Digest): ForkedSignedBeaconBlock =
  # Pop orphans whose parent is the block identified by `root`

  var toRemove: seq[(Eth2Digest, ValidatorSig)]
  defer: # Run even if iterator is not carried to termination
    for k in toRemove:
      quarantine.orphans.del k

  for k, v in quarantine.orphans.mpairs():
    if v.parent_root == root:
      toRemove.add(k)
      yield v

proc addSidecarless(
    quarantine: var Quarantine, finalizedSlot: Opt[Slot],
    signedBlock: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
                 fulu.SignedBeaconBlock | gloas.SignedBeaconBlock |
                 heze.SignedBeaconBlock
): bool =
  if finalizedSlot.isSome():
    if signedBlock.message.isUnviableFork(finalizedSlot.get()):
      discard quarantine.addUnviable(signedBlock.root, UnviableKind.UnviableFork)
      return false

  debug "Block without sidecars has been added to the quarantine",
    block_root = shortLog(signedBlock.root)
  quarantine.sidecarless.put(
    signedBlock.root, ForkedSignedBeaconBlock.init(signedBlock)
  )
  quarantine.missing.del(signedBlock.root)
  true

proc addSidecarless*(
  quarantine: var Quarantine, finalizedSlot: Slot,
  signedBlock: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
               fulu.SignedBeaconBlock | gloas.SignedBeaconBlock |
               heze.SignedBeaconBlock
): bool =
  quarantine.addSidecarless(Opt.some(finalizedSlot), signedBlock)

proc addSidecarless*(
  quarantine: var Quarantine,
  signedBlock: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
               fulu.SignedBeaconBlock | gloas.SignedBeaconBlock |
               heze.SignedBeaconBlock
) =
  discard quarantine.addSidecarless(Opt.none(Slot), signedBlock)

func popSidecarless*(
    quarantine: var Quarantine, root: Eth2Digest
): Opt[ForkedSignedBeaconBlock] =
  quarantine.sidecarless.pop(root)

func getColumnless*(
    quarantine: var Quarantine, root: Eth2Digest
): Opt[ForkedSignedBeaconBlock] =
  quarantine.sidecarless.peek(root)

iterator peekSidecarless*(quarantine: Quarantine): ForkedSignedBeaconBlock =
  for k, v in quarantine.sidecarless.pairs():
    yield v
