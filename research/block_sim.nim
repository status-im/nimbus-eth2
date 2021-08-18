# beacon_chain
# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# `block_sim` is a block and attestation simulator similar to `state_sim` whose
# task is to run the beacon chain without considering the network or the
# wall clock. Functionally, it achieves the same as the distributed beacon chain
# by producing blocks and attestations as if they were created by separate
# nodes, just like a set of `beacon_node` instances would.
#
# Similar to `state_sim`, but uses the block and attestation pools along with
# a database, as if a real node was running.

import
  math, stats, times, strformat,
  options, random, tables, os,
  confutils, chronicles, eth/db/kvstore_sqlite3,
  eth/keys,
  ../tests/testblockutil,
  ../beacon_chain/spec/[
    beaconstate, forks, helpers, signatures, state_transition],
  ../beacon_chain/spec/datatypes/[phase0, altair],
  ../beacon_chain/[beacon_node_types, beacon_chain_db],
  ../beacon_chain/eth1/eth1_monitor,
  ../beacon_chain/validators/validator_pool,
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_quarantine,
                                          block_clearance, attestation_pool],
  ./simutils

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tSignBlock = "Sign block"
  tAttest = "Have committee attest to block"
  tReplay = "Replay all produced blocks"

func gauss(r: var Rand; mu = 0.0; sigma = 1.0): float =
  # TODO This is present in Nim 1.4
  const K = sqrt(2 / E)
  var
    a = 0.0
    b = 0.0
  while true:
    a = rand(r, 1.0)
    b = (2.0 * rand(r, 1.0) - 1.0) * K
    if  b * b <= -4.0 * a * a * ln(a): break
  mu + sigma * (b / a)

# TODO confutils is an impenetrable black box. how can a help text be added here?
cli do(slots = SLOTS_PER_EPOCH * 6,
       validators = SLOTS_PER_EPOCH * 400, # One per shard is minimum
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.82,
       blockRatio {.desc: "ratio of slots with blocks"} = 1.0,
       replay = true):
  let
    (state, depositContractSnapshot) = loadGenesis(validators, false)
    genesisBlock = get_initial_beacon_block(state[].data)
    genesisTime = float state[].data.genesis_time

  var cfg = defaultRuntimeConfig

  cfg.ALTAIR_FORK_EPOCH = 96.Slot.epoch

  echo "Starting simulation..."

  let db = BeaconChainDB.new("block_sim_db")
  defer: db.close()

  ChainDAGRef.preInit(db, state[].data, state[].data, genesisBlock)
  putInitialDepositContractSnapshot(db, depositContractSnapshot)

  var
    dag = ChainDAGRef.init(cfg, db, {})
    eth1Chain = Eth1Chain.init(cfg, db)
    merkleizer = depositContractSnapshot.createMerkleizer
    quarantine = QuarantineRef.init(keys.newRng())
    attPool = AttestationPool.init(dag, quarantine)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r = initRand(1)
    tmpState = assignClone(dag.headState)

  eth1Chain.addBlock Eth1Block(
    number: Eth1BlockNumber 1,
    timestamp: Eth1BlockTimestamp genesisTime,
    voteData: Eth1Data(
      deposit_root: merkleizer.getDepositsRoot,
      deposit_count: merkleizer.getChunkCount))

  let replayState = assignClone(dag.headState)

  proc handleAttestations(slot: Slot) =
    let
      attestationHead = dag.head.atSlot(slot)

    dag.withState(tmpState[], attestationHead):
      let committees_per_slot =
        get_committee_count_per_slot(stateData.data, slot.epoch, cache)

      for committee_index in 0'u64..<committees_per_slot:
        let committee = get_beacon_committee(
          stateData.data, slot, committee_index.CommitteeIndex, cache)

        for index_in_committee, validatorIdx in committee:
          if rand(r, 1.0) <= attesterRatio:
            let
              data = makeAttestationData(
                stateData.data, slot, committee_index.CommitteeIndex, blck.root)
              sig =
                get_attestation_signature(getStateField(stateData.data, fork),
                  getStateField(stateData.data, genesis_validators_root),
                  data, hackPrivKey(
                    getStateField(stateData.data, validators)[validatorIdx]))
            var aggregation_bits = CommitteeValidatorsBits.init(committee.len)
            aggregation_bits.setBit index_in_committee

            attPool.addAttestation(
              Attestation(
                data: data,
                aggregation_bits: aggregation_bits,
                signature: sig.toValidatorSig()
              ), [validatorIdx], sig, data.slot)

  proc getNewBlock[T](
      stateData: var StateData, slot: Slot, cache: var StateCache): T =
    let
      finalizedEpochRef = dag.getFinalizedEpochRef()
      proposerIdx = get_beacon_proposer_index(
        stateData.data, cache, getStateField(stateData.data, slot)).get()
      privKey = hackPrivKey(
        getStateField(stateData.data, validators)[proposerIdx])
      eth1ProposalData = eth1Chain.getBlockProposalData(
        stateData.data,
        finalizedEpochRef.eth1_data,
        finalizedEpochRef.eth1_deposit_index)
      hashedState =
        when T is phase0.SignedBeaconBlock:
          addr stateData.data.hbsPhase0
        elif T is altair.SignedBeaconBlock:
          addr stateData.data.hbsAltair
        else:
          static: doAssert false
      message = makeBeaconBlock(
        cfg,
        hashedState[],
        proposerIdx,
        dag.head.root,
        privKey.genRandaoReveal(
          getStateField(stateData.data, fork),
          getStateField(stateData.data, genesis_validators_root),
          slot).toValidatorSig(),
        eth1ProposalData.vote,
        default(GraffitiBytes),
        attPool.getAttestationsForTestBlock(stateData, cache),
        eth1ProposalData.deposits,
        @[],
        @[],
        @[],
        ExecutionPayload(),
        noRollback,
        cache)

    var
      newBlock = T(
        message: message.get()
      )

    let blockRoot = withTimerRet(timers[tHashBlock]):
      hash_tree_root(newBlock.message)
    newBlock.root = blockRoot
    # Careful, state no longer valid after here because of the await..
    newBlock.signature = withTimerRet(timers[tSignBlock]):
      get_block_signature(
        getStateField(stateData.data, fork),
        getStateField(stateData.data, genesis_validators_root),
        newBlock.message.slot,
        blockRoot, privKey).toValidatorSig()

    newBlock

  proc proposePhase0Block(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withState(tmpState[], dag.head.atSlot(slot)):
      let
        newBlock = getNewBlock[phase0.SignedBeaconBlock](stateData, slot, cache)
        added = dag.addRawBlock(quarantine, newBlock) do (
            blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
            epochRef: EpochRef):
          # Callback add to fork choice if valid
          attPool.addForkChoice(
            epochRef, blckRef, signedBlock.message, blckRef.slot)

      blck() = added[]
      dag.updateHead(added[], quarantine)
      if dag.needStateCachesAndForkChoicePruning():
        dag.pruneStateCachesDAG()
        attPool.prune()

  proc proposeAltairBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withState(tmpState[], dag.head.atSlot(slot)):
      let
        newBlock = getNewBlock[altair.SignedBeaconBlock](stateData, slot, cache)
        added = dag.addRawBlock(quarantine, newBlock) do (
            blckRef: BlockRef, signedBlock: altair.TrustedSignedBeaconBlock,
            epochRef: EpochRef):
          # Callback add to fork choice if valid
          attPool.addForkChoice(
            epochRef, blckRef, signedBlock.message, blckRef.slot)

      blck() = added[]
      dag.updateHead(added[], quarantine)
      if dag.needStateCachesAndForkChoicePruning():
        dag.pruneStateCachesDAG()
        attPool.prune()

  var
    lastEth1BlockAt = genesisTime
    eth1BlockNum = 1000

  for i in 0..<slots:
    let
      slot = Slot(i + 1)
      t =
        if slot.isEpoch: tEpoch
        else: tBlock
      now = genesisTime + float(slot * SECONDS_PER_SLOT)

    while true:
      let nextBlockTime = lastEth1BlockAt +
                          max(1.0, gauss(r, float defaultRuntimeConfig.SECONDS_PER_ETH1_BLOCK, 3.0))
      if nextBlockTime > now:
        break

      inc eth1BlockNum
      var eth1Block = Eth1Block(
        number: Eth1BlockNumber eth1BlockNum,
        timestamp: Eth1BlockTimestamp nextBlockTime,
        voteData: Eth1Data(
          block_hash: makeFakeHash(eth1BlockNum)))

      let newDeposits = int clamp(gauss(r, 5.0, 8.0), 0.0, 1000.0)
      for i in 0 ..< newDeposits:
        let d = makeDeposit(merkleizer.getChunkCount.int, {skipBLSValidation})
        eth1Block.deposits.add d
        merkleizer.addChunk hash_tree_root(d).data

      eth1Block.voteData.deposit_root = merkleizer.getDepositsRoot
      eth1Block.voteData.deposit_count = merkleizer.getChunkCount

      eth1Chain.addBlock eth1Block
      lastEth1BlockAt = nextBlockTime

    if blockRatio > 0.0:
      withTimer(timers[t]):
        if slot.epoch < dag.cfg.ALTAIR_FORK_EPOCH:
          proposePhase0Block(slot)
        else:
          proposeAltairBlock(slot)
    if attesterRatio > 0.0:
      withTimer(timers[tAttest]):
        handleAttestations(slot)

    # TODO if attestation pool was smarter, it would include older attestations
    #      too!
    verifyConsensus(dag.headState.data, attesterRatio * blockRatio)

    if t == tEpoch:
      echo &". slot: {shortLog(slot)} ",
        &"epoch: {shortLog(slot.compute_epoch_at_slot)}"
    else:
      write(stdout, ".")
      flushFile(stdout)

  if replay:
    withTimer(timers[tReplay]):
      var cache = StateCache()
      dag.updateStateData(
        replayState[], dag.head.atSlot(Slot(slots)), false, cache)

  echo "Done!"

  printTimers(dag.headState.data, attesters, true, timers)
