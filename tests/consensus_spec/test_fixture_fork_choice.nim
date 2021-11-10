# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[strformat, tables, options, json, os, strutils],
  # Status libraries
  stew/[results, endians2], snappy, chronicles,
  eth/keys, taskpools,
  # Internals
  ../../beacon_chain/spec/[helpers, forks],
  ../../beacon_chain/spec/datatypes/[
    base,
    phase0, altair, merge],
  ../../beacon_chain/fork_choice/[fork_choice, fork_choice_types],
  ../../beacon_chain/beacon_chain_db,
  ../../beacon_chain/consensus_object_pools/[
    blockchain_dag, block_quarantine, block_clearance, spec_cache],
  # Third-party
  yaml,
  # Test
  ../testutil,
  ./fixtures_utils

# Test format described at https://github.com/ethereum/consensus-specs/tree/v1.1.0/tests/formats/fork_choice
# Note that our implementation has been optimized with "ProtoArray"
# instead of following the spec (in particular the "store").

type
  OpKind = enum
    opOnTick
    opOnAttestation
    opOnBlock
    opOnMergeBlock
    opChecks

  Operation = object
    valid: bool
    # variant specific fields
    case kind*: OpKind
    of opOnTick:
      tick: int
    of opOnAttestation:
      att: Attestation
    of opOnBlock:
      blk: ForkedSignedBeaconBlock
    of opOnMergeBlock:
      powBlock: PowBlock
    of opChecks:
      checks: JsonNode

proc initialLoad(
       path: string, db: BeaconChainDB,
       StateType, BlockType: typedesc): tuple[
       dag: ChainDagRef, fkChoice: ref ForkChoice
    ] =

   # TODO: support more than phase 0 genesis

  let state = newClone(parseTest(
    path/"anchor_state.ssz_snappy",
    SSZ, StateType
  ))

  let forkedState = newClone(ForkedHashedBeaconState.init(
    phase0.HashedBeaconState(
      data: state[],
      root: hash_tree_root(state[])
    )
  ))

  let blk = parseTest(
    path/"anchor_block.ssz_snappy",
    SSZ, BlockType
  )


  let signedBlock = ForkedSignedBeaconBlock.init(phase0.SignedBeaconBlock(
        message: blk,
        # signature: - unused as it's trusted
        root: hashTreeRoot(blk)
      ))

  ChainDagRef.preInit(
    db,
    forkedState[], forkedState[],
    asTrusted(signedBlock)
  )
  let dag = ChainDAGRef.init(
    defaultRuntimeConfig,
    db,
    updateFlags = {}
  )
  let fkChoice = newClone(ForkChoice.init(
    dag.getFinalizedEpochRef(),
    dag.finalizedHead.blck
  ))

  (dag, fkChoice)

proc loadOps(path: string, fork: BeaconBlockFork): seq[Operation] =
  let stepsYAML = readFile(path/"steps.yaml")
  let steps = yaml.loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    if step.hasKey"tick":
      result.add Operation(kind: opOnTick, tick: step["tick"].getInt())
    elif step.hasKey"block":
      let filename = step["block"].getStr()
      case fork
      of BeaconBlockFork.Phase0:
        let blk = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, phase0.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blk: ForkedSignedBeaconBlock.init(blk))
      of BeaconBlockFork.Altair:  
        let blk = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, altair.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blk: ForkedSignedBeaconBlock.init(blk))
      of BeaconBlockFork.Merge:
        let blk = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, merge.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blk: ForkedSignedBeaconBlock.init(blk))
    elif step.hasKey"attestation":
      let filename = step["attestation"].getStr()
      let att = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, Attestation
      )
      result.add Operation(kind: opOnAttestation,
        att: att)
    elif step.hasKey"checks":
      result.add Operation(kind: opChecks,
        checks: step["checks"])
    else:
      doAssert false, "Unreachable: " & $step

    if step.hasKey"valid":
      doAssert step.len == 2
      result[^1].valid = step["valid"].getBool()
    elif not step.hasKey"checks":
      doAssert step.len == 1
      result[^1].valid = true

proc stepOnBlock(
       dag: ChainDagRef,
       fkChoice: ref ForkChoice,
       quarantine: QuarantineRef,
       state: var StateData,
       stateCache: var StateCache,
       signedBlock: phase0.SignedBeaconBlock | altair.SignedBeaconBlock | merge.SignedBeaconBlock,
       time: Slot): Result[BlockRef, (ValidationResult, BlockError)] =
  # 1. Move state to proper slot.
  dag.updateStateData(
    state,
    dag.head.atSlot(time),
    save = false,
    stateCache
  )

  # 2. Add block to DAG
  when signedBlock is phase0.SignedBeaconBlock:
    type TrustedBlock = phase0.TrustedSignedBeaconBlock
  elif signedBlock is altair.SignedBeaconBlock:
    type TrustedBlock = altair.TrustedSignedBeaconBlock
  else:
    type TrustedBlock = merge.TrustedSignedBeaconBlock

  let blockAdded = dag.addRawBlock(quarantine, signedBlock) do (
      blckRef: BlockRef, signedBlock: TrustedBlock, epochRef: EpochRef
    ):

    # 3. Update fork choice if valid
    let status = fkChoice[].process_block(
      dag,
      epochRef,
      blckRef,
      signedBlock.message,
      time
    )
    doAssert status.isOk()
  
  return blockAdded 

proc stepOnAttestation(
       dag: ChainDagRef,
       fkChoice: ref ForkChoice,
       att: Attestation,
       time: Slot): FcResult[void] =

  let epochRef = dag.getEpochRef(dag.head, time.compute_epoch_at_slot())
  let attesters = epochRef.get_attesting_indices(att.data, att.aggregation_bits)
  
  let status = fkChoice[].on_attestation(
    dag,
    att.data.slot, att.data.beacon_block_root, attesters,
    time
  )

  status

proc stepChecks(
       checks: JsonNode,
       dag: ChainDagRef,
       fkChoice: ref ForkChoice,
       time: Slot  
     ) =
  doAssert checks.len >= 1, "No checks found"
  for check, val in checks:
    if check == "time":
      doAssert time == Slot(val.getInt())
      doAssert fkChoice.checkpoints.time == time
    elif check == "head":
      let headRoot = fkChoice[].get_head(dag, time).get()
      let headRef = dag.getRef(headRoot)
      doAssert headRef.slot == Slot(val["slot"].getInt())
      doAssert headRef.root == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "justified_checkpoint":
      let checkpointRoot = fkChoice.checkpoints.justified.checkpoint.root
      let checkpointEpoch = fkChoice.checkpoints.justified.checkpoint.epoch
      doAssert checkpointEpoch == Epoch(val["epoch"].getInt())
      doAssert checkpointRoot == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "justified_checkpoint_root": # undocumented check
      let checkpointRoot = fkChoice.checkpoints.justified.checkpoint.root
      doAssert checkpointRoot == Eth2Digest.fromHex(val.getStr())
    elif check == "finalized_checkpoint":
      let checkpointRoot = fkChoice.checkpoints.finalized.root
      let checkpointEpoch = fkChoice.checkpoints.finalized.epoch
      doAssert checkpointEpoch == Epoch(val["epoch"].getInt())
      doAssert checkpointRoot == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "best_justified_checkpoint":
      let checkpointRoot = fkChoice.checkpoints.best_justified.root
      let checkpointEpoch = fkChoice.checkpoints.best_justified.epoch
      doAssert checkpointEpoch == Epoch(val["epoch"].getInt())
      doAssert checkpointRoot == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "genesis_time":
      # The fork choice is pruned regularly
      # and does not store the genesis time,
      # hence we check the DAG
      doAssert dag.genesis.slot == Slot(val.getInt())
    else:
      doAssert false, "Unsupported check '" & $check & "'"

proc runTest(path: string, fork: BeaconBlockFork) =
  let db = BeaconChainDB.new("", inMemory = true)
  defer:
    db.close()

  var stores = case fork
    of BeaconBlockFork.Phase0:
      initialLoad(
        path, db,
        phase0.BeaconState, phase0.BeaconBlock
      )
    else:
      doAssert false, "Unsupported fork: " & $fork
      (ChainDAGRef(), (ref ForkChoice)())
    # of BeaconBlockFork.Altair:
    #   initialLoad(
    #     path, db,
    #     # The tests always use phase 0 block for anchor - https://github.com/ethereum/eth2.0-specs/pull/2323
    #     # TODO: support altair genesis state
    #     altair.BeaconState, phase0.BeaconBlock
    #   )
    # of BeaconBlockFork.Merge:
    #   initialLoad(
    #     path, db,
    #     # The tests always use phase 0 block for anchor - https://github.com/ethereum/eth2.0-specs/pull/2323
    #     # TODO: support merge genesis state
    #     merge.BeaconState, phase0.BeaconBlock
    #   )

  let taskpool = Taskpool.new(numThreads = 1)
  let quarantine = QuarantineRef.init(keys.newRng(), taskpool)

  let steps = loadOps(path, fork)
  var time = stores.fkChoice.checkpoints.time

  let state = newClone(stores.dag.headState)
  var stateCache = StateCache()

  for step in steps:
    case step.kind
    of opOnTick:
      time = Slot(step.tick)
    of opOnBlock:
      withBlck(step.blk):
        let status = stepOnBlock(
          stores.dag, stores.fkChoice,
          quarantine,
          state[], stateCache,
          blck,
          time)
        doAssert status.isOk == step.valid
    of opOnAttestation:
      let status = stepOnAttestation(
        stores.dag, stores.fkChoice,
        step.att, time)
      doAssert status.isOk == step.valid
    of opChecks:
      stepChecks(step.checks, stores.dag, stores.fkChoice, time)
    else:
      doAssert false, "Unsupported"

suite "Ethereum Foundation - ForkChoice" & preset():
  const SKIP = [
    # protoArray can handle blocks in the future gracefully
    # spec: https://github.com/ethereum/consensus-specs/blame/v1.1.3/specs/phase0/fork-choice.md#L349
    # test: tests/fork_choice/scenarios/no_votes.nim
    #       "Ensure the head is still 4 whilst the justified epoch is 0."
    "on_block_future_block",
  ]

  for fork in [BeaconBlockFork.Phase0]: # TODO: init ChainDAG from Merge/Altair
    let forkStr = toLowerAscii($fork)
    for testKind in ["get_head", "on_block"]:
      let basePath = SszTestsDir/const_preset/forkStr/"fork_choice"/testKind/"pyspec_tests"
      for kind, path in walkDir(basePath, relative = true, checkDir = true):
        test "ForkChoice - " & const_preset/forkStr/"fork_choice"/testKind/"pyspec_tests"/path:
          if const_preset == "minimal":
            # TODO: Minimal tests have long paths issues on Windows
            # and some are testing implementation details:
            # - assertion that input block is not in the future
            # - block slot is later than finalized slot
            # - ...
            # that ProtoArray handles gracefully
            skip()
          elif path in SKIP:
            skip()
          else:
            runTest(basePath/path, fork)


