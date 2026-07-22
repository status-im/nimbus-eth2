# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sets,
  unittest2,
  ../beacon_chain/spec/datatypes/base

# These tests cover the column-reconstruction backfiller's cursor *movement* —
# which slot it reconstructs next and how the servable run grows/shrinks across
# head extensions, reorgs, pruning and blocked slots.
#
# Reconstruction itself is mocked (no DAG, no KZG): a `DummyBeaconChain` decides
# each slot's outcome and records which slots were visited. The cursor logic
# below mirrors `consensus_object_pools/column_reconstruction_backfiller`'s
# `step`/`reconcileHead`; keep the two in sync.

type
  SlotRecon {.pure.} = enum
    Unknown   ## Recoverable failure; retry on a later pass.
    TooFew    ## Block has blobs but <64 columns present — cannot recover yet.
    Servable  ## Full matrix present (or no blobs) — nothing to do.

  BackfillCursors = object
    ## The established, fully-servable run is `[runBottom..runTop]`; `frontier`
    ## is the slot worked next. `FAR_FUTURE_SLOT` means empty/idle.
    runBottom, runTop, frontier: Slot
    frontierBlocked: bool
    lastHeadRoot: Eth2Digest

  DummyBeaconChain = object
    ## Synthetic chain the cursors are driven against.
    head, finalized, retentionStart: Slot
    headRoot: Eth2Digest
    extension: bool          ## head extends the previous head (not a reorg)
    tooFew: HashSet[Slot]    ## slots that cannot (yet) be reconstructed
    probed: seq[Slot]        ## slots the cursors asked us to reconstruct

func root(n: byte): Eth2Digest =
  ## A distinct head root per chain version.
  var res: Eth2Digest
  res.data[0] = n
  res

func init(T: type BackfillCursors): BackfillCursors =
  BackfillCursors(
    runBottom: FAR_FUTURE_SLOT,
    runTop: FAR_FUTURE_SLOT,
    frontier: FAR_FUTURE_SLOT)

func reconcileHead(
    c: var BackfillCursors,
    head, finalized: Slot, headRoot: Eth2Digest, extension: bool) =
  if headRoot == c.lastHeadRoot:
    return
  c.lastHeadRoot = headRoot
  c.frontierBlocked = false
  if not extension and c.runTop != FAR_FUTURE_SLOT and c.runTop > finalized:
    c.runTop = finalized
    if c.runBottom != FAR_FUTURE_SLOT and c.runBottom > c.runTop:
      c.runBottom = FAR_FUTURE_SLOT
      c.runTop = FAR_FUTURE_SLOT
  c.frontier = head

func nextFrontier(
    c: var BackfillCursors, head, finalized, retentionStart: Slot): Opt[Slot] =
  if c.runBottom != FAR_FUTURE_SLOT and c.runBottom < retentionStart:
    c.runBottom = retentionStart
  if c.frontier != FAR_FUTURE_SLOT and c.frontier < retentionStart:
    c.frontier = FAR_FUTURE_SLOT
    c.frontierBlocked = false

  if c.frontier == FAR_FUTURE_SLOT or c.frontierBlocked:
    return Opt.none(Slot)

  if c.runTop != FAR_FUTURE_SLOT and c.runBottom != FAR_FUTURE_SLOT and
      c.frontier >= c.runBottom and c.frontier <= c.runTop:
    c.runTop = head
    c.frontier =
      if c.runBottom <= retentionStart: FAR_FUTURE_SLOT
      else: c.runBottom - 1
    if c.frontier == FAR_FUTURE_SLOT:
      return Opt.none(Slot)

  Opt.some(c.frontier)

func recordResult(
    c: var BackfillCursors, head, retentionStart: Slot, state: SlotRecon) =
  case state
  of SlotRecon.TooFew:
    c.frontierBlocked = true
  of SlotRecon.Unknown:
    discard
  of SlotRecon.Servable:
    if c.runTop == FAR_FUTURE_SLOT:
      c.runTop = head
      c.runBottom = c.frontier
    elif c.frontier > c.runTop:
      discard
    else:
      c.runBottom = c.frontier
    c.frontier =
      if c.frontier <= retentionStart: FAR_FUTURE_SLOT
      else: c.frontier - 1

func onColumnsStored(c: var BackfillCursors, slot: Slot) =
  if c.frontierBlocked and slot == c.frontier:
    c.frontierBlocked = false

func servableBottom(c: BackfillCursors, head: Slot): Slot =
  ## Earliest slot advertisable as servable-from-head (drives `dag.eaSlot`).
  if c.runTop == FAR_FUTURE_SLOT:
    head + 1
  elif c.runTop >= head:
    c.runBottom
  else:
    c.frontier + 1

func outcome(chain: DummyBeaconChain, slot: Slot): SlotRecon =
  if slot in chain.tooFew: SlotRecon.TooFew else: SlotRecon.Servable

proc tick(c: var BackfillCursors, chain: var DummyBeaconChain): bool =
  ## One pass, mirroring the service's `step`: reconcile the head, pick the next
  ## frontier, "reconstruct" it synthetically, fold the outcome back. Returns
  ## false when the cursors are idle (nothing to do).
  c.reconcileHead(chain.head, chain.finalized, chain.headRoot, chain.extension)
  let target = c.nextFrontier(chain.head, chain.finalized, chain.retentionStart).valueOr:
    return false
  chain.probed.add target
  c.recordResult(chain.head, chain.retentionStart, chain.outcome(target))
  true

proc runToIdle(c: var BackfillCursors, chain: var DummyBeaconChain) =
  var ticks = 0
  while c.tick(chain):
    inc ticks
    doAssert ticks < 100_000, "cursors did not settle"

suite "Column reconstruction backfiller cursors":
  test "fresh backfill descends from head to the retention floor":
    var c = BackfillCursors.init()
    var chain = DummyBeaconChain(
      head: Slot(200), finalized: Slot(150), retentionStart: Slot(100),
      headRoot: root(1))
    runToIdle(c, chain)
    check:
      c.runTop == Slot(200)
      c.runBottom == Slot(100)
      c.frontier == FAR_FUTURE_SLOT
      chain.probed.len == 101          # 200..100 inclusive, each visited once

  test "a TooFew slot blocks the trail until its columns arrive":
    var c = BackfillCursors.init()
    var chain = DummyBeaconChain(
      head: Slot(200), finalized: Slot(150), retentionStart: Slot(100),
      headRoot: root(1))
    chain.tooFew.incl Slot(150)
    runToIdle(c, chain)
    check:
      c.runBottom == Slot(151)         # stalled just above the gap
      c.frontier == Slot(150)
      c.frontierBlocked

    # Columns for 150 land and it becomes reconstructable.
    chain.tooFew.clear()
    c.onColumnsStored(Slot(150))
    runToIdle(c, chain)
    check:
      not c.frontierBlocked
      c.runBottom == Slot(100)
      c.frontier == FAR_FUTURE_SLOT

  test "a head extension reconstructs only the new slot, not the whole run":
    var c = BackfillCursors.init()
    var chain = DummyBeaconChain(
      head: Slot(200), finalized: Slot(150), retentionStart: Slot(100),
      headRoot: root(1))
    runToIdle(c, chain)

    chain.head = Slot(201)
    chain.headRoot = root(2)
    chain.extension = true
    chain.probed.setLen(0)
    runToIdle(c, chain)
    check:
      c.runTop == Slot(201)
      c.runBottom == Slot(100)         # history is left untouched
      chain.probed == @[Slot(201)]     # only the new head slot is (re)processed

  test "a reorg refills only the post-finalized window":
    var c = BackfillCursors.init()
    var chain = DummyBeaconChain(
      head: Slot(200), finalized: Slot(150), retentionStart: Slot(100),
      headRoot: root(1))
    runToIdle(c, chain)

    # Reorg onto a different chain, same finalized checkpoint.
    chain.head = Slot(205)
    chain.headRoot = root(3)
    chain.extension = false
    chain.probed.setLen(0)
    runToIdle(c, chain)
    check:
      c.runTop == Slot(205)
      c.runBottom == Slot(100)         # finalized segment preserved
      Slot(205) in chain.probed        # post-finalized window refilled
      Slot(151) in chain.probed
      Slot(150) notin chain.probed     # finalized segment NOT re-probed
      Slot(100) notin chain.probed

  test "a reorg whose run is entirely post-finalized resets it":
    var c = BackfillCursors.init()
    var chain = DummyBeaconChain(
      head: Slot(200), finalized: Slot(150), retentionStart: Slot(100),
      headRoot: root(1))
    # stall the run with its bottom above finalized
    chain.tooFew.incl Slot(160)
    runToIdle(c, chain)
    check:
      c.runBottom == Slot(161)
      c.runTop == Slot(200)

    # The whole established run is post-finalized, so the reorg invalidates it.
    chain.tooFew.clear()
    chain.head = Slot(205)
    chain.headRoot = root(3)
    chain.extension = false
    runToIdle(c, chain)
    check:
      c.runTop == Slot(205)
      c.runBottom == Slot(100)  # re-established from the new head to floor

  test "a reorg retracts the advertised slot, then re-extends it":
    var c = BackfillCursors.init()
    var chain = DummyBeaconChain(
      head: Slot(200), finalized: Slot(150), retentionStart: Slot(100),
      headRoot: root(1))
    runToIdle(c, chain)
    check c.servableBottom(chain.head) == Slot(100)  # caught up: full run

    # Reorg: the post-finalized window must be refilled before we can serve it.
    chain.head = Slot(205)
    chain.headRoot = root(3)
    chain.extension = false
    c.reconcileHead(chain.head, chain.finalized, chain.headRoot, chain.extension)
    check c.servableBottom(chain.head) == Slot(206)  # retracted to head + 1

    runToIdle(c, chain)
    check c.servableBottom(chain.head) == Slot(100)  # refilled back to floor

  test "an advancing retention floor lifts runBottom":
    var c = BackfillCursors.init()
    var chain = DummyBeaconChain(
      head: Slot(200), finalized: Slot(150), retentionStart: Slot(100),
      headRoot: root(1))
    runToIdle(c, chain)
    check c.runBottom == Slot(100)

    # The retention window slides forward (pruning).
    chain.retentionStart = Slot(130)
    discard c.tick(chain)              # one pass applies the new floor
    check c.runBottom == Slot(130)
