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
  ../ssz/merkleization,
  block_pools_types

export options

logScope: topics = "quarant"
{.push raises: [Defect].}

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
    # TODO Need to potentially remove from quarantine.pending - this is currently a
    #      memory leak here!
    quarantine.missing.del(k)

  # simple (simplistic?) exponential backoff for retries..
  for k, v in quarantine.missing.pairs():
    if countOnes(v.tries.uint64) == 1:
      result.add(FetchRecord(root: k))

func addMissing*(quarantine: var Quarantine, broot: Eth2Digest) {.inline.} =
  discard quarantine.missing.hasKeyOrPut(broot, MissingBlock())

func add*(quarantine: var Quarantine, dag: CandidateChains,
          sblck: SignedBeaconBlock,
          broot: Option[Eth2Digest] = none[Eth2Digest]()) =
  ## Adds block to quarantine's `orphans` and `missing` lists.
  let blockRoot = if broot.isSome():
      broot.get()
    else:
      hash_tree_root(sblck.message)

  quarantine.orphans[blockRoot] = sblck

  let parentRoot = sblck.message.parent_root
  quarantine.addMissing(parentRoot)
