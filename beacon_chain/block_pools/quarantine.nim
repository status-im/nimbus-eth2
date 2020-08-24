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
  ../spec/[datatypes, digest],
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

func addMissing*(quarantine: var QuarantineRef, root: Eth2Digest) =
  ## Schedule the download a the given block
  if root notin quarantine.orphans:
    # If the block is in orphans, we no longer need it
    discard quarantine.missing.hasKeyOrPut(root, MissingBlock())

func add*(quarantine: var QuarantineRef, dag: ChainDAGRef,
          signedBlock: SignedBeaconBlock) =
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
  const MAX_QUARANTINE_ORPHANS = 16
  if quarantine.orphans.len >= MAX_QUARANTINE_ORPHANS:
    return

  quarantine.orphans[signedBlock.root] = signedBlock
  quarantine.missing.del(signedBlock.root)

  quarantine.addMissing(signedBlock.message.parent_root)
