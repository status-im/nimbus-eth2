# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos,
  std/sequtils,
  unittest2,
  taskpools,
  kzg4844 as kzg,
  kzg4844/kzg_abi,
  ../beacon_chain/conf,
  ../beacon_chain/spec/[beaconstate, forks, helpers,
    peerdas_helpers, state_transition],
  ../beacon_chain/gossip_processing/block_processor,
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, blockchain_dag, blob_quarantine, block_quarantine,
    block_clearance, consensus_manager, envelope_quarantine,
    partial_column_quarantine,
  ],
  ../beacon_chain/el/el_manager,
  ./[testblockutil, testdbutil, testutil]

from chronos/unittest2/asynctests import asyncTest
from ../beacon_chain/spec/eth2_apis/dynamic_fee_recipients import
  DynamicFeeRecipientsStore, init
from ../beacon_chain/validators/action_tracker import ActionTracker
from ../beacon_chain/validators/keystore_management import KeymanagerHost

from std/strutils import rsplit

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert kzg.loadTrustedSetup(
    sourceDir &
      "/../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt", 0).isOk

# Helper to create valid KZG blobs
func createValidKzgBlob(): kzg.KzgBlob =
  # Create a blob with valid field elements
  # Each field element must be < BLS modulus (top byte must be <= 114)
  const MAX_TOP_BYTE = 114
  var blob: array[kzg_abi.BYTES_PER_BLOB, byte]
  for i in 0 ..< kzg_abi.BYTES_PER_BLOB:
    if i mod kzg_abi.BYTES_PER_FIELD_ELEMENT == 0:  # First byte of each field element
      blob[i] = MAX_TOP_BYTE  # Safe value
    else:
      blob[i] = byte(i mod 256)
  kzg.KzgBlob(bytes: blob)

proc pruneAtFinalization(dag: ChainDAGRef) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()

suite "Block processor" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
        res.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
        res.CAPELLA_FORK_EPOCH = Epoch(1)
        res.DENEB_FORK_EPOCH = Epoch(2)
        res.ELECTRA_FORK_EPOCH = Epoch(3)
        res.FULU_FORK_EPOCH = Epoch(4)
        res
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      quarantine = newClone(Quarantine.init(cfg))
      blobQuarantine = newClone(BlobQuarantine())
      dataColumnQuarantine = newClone(ColumnQuarantine())
      gloasColumnQuarantine = newClone(GloasColumnQuarantine())
      envelopeQuarantine = newClone(EnvelopeQuarantine())
      attestationPool = newClone(AttestationPool.init(dag, quarantine))
      elManager = new ELManager # TODO: initialise this properly
      actionTracker = default(ActionTracker)
      consensusManager = ConsensusManager.new(
        dag,
        attestationPool,
        quarantine,
        elManager,
        actionTracker,
        newClone(DynamicFeeRecipientsStore.init()),
        "",
        Opt.some default(Eth1Address),
        defaultGasLimit,
      )
      state = newClone(dag.headState)
      getTimeFn = proc(): BeaconTime =
        state[].slot.start_beacon_time(cfg.timeParams)
      batchVerifier = BatchVerifier.new(rng, taskpool)
    var
      cache: StateCache
      info: ForkedEpochInfo

    cfg.process_slots(state[], cfg.lastPremergeSlotInTestCfg, cache, info, {}).expect(
      "OK"
    )

  asyncTest "Reverse order block add & get" & preset():
    let
      processor = BlockProcessor.new(
        false, "", "", batchVerifier, consensusManager, validatorMonitor,
        blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
        envelopeQuarantine, getTimeFn,
      )
      b1 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      b2 = addTestBlock(state[], cache, cfg = cfg).bellatrixData

      missing = await processor.addBlock(MsgSource.gossip, b2, noSidecars)

    check:
      missing.error == VerifierError.MissingParent
      not dag.containsForkBlock(b2.root) # Unresolved, shouldn't show up

      FetchRecord(root: b1.root) in quarantine[].checkMissing(32)

    let
      status = await processor.addBlock(MsgSource.gossip, b1, noSidecars)
      b1Get = dag.getBlockRef(b1.root)

    check:
      status.isOk
      b1Get.isSome()
      dag.containsForkBlock(b1.root)
      not dag.containsForkBlock(b2.root) # Async pipeline must still run

    while processor[].hasBlocks():
      poll()

    let b2Get = dag.getBlockRef(b2.root)

    check:
      b2Get.isSome()

      b2Get.get().parent == b1Get.get()

    dag.updateHead(b2Get.get(), quarantine[], [])
    dag.pruneAtFinalization()

    # The heads structure should have been updated to contain only the new
    # b2 head
    check:
      dag.heads.mapIt(it) == @[b2Get.get()]

    # check that init also reloads block graph
    var
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})

    check:
      # ensure we loaded the correct head state
      dag2.head.root == b2.root
      dag2.headState.root == b2.message.state_root
      dag2.getBlockRef(b1.root).isSome()
      dag2.getBlockRef(b2.root).isSome()
      dag2.heads.len == 1
      dag2.heads[0].root == b2.root

  asyncTest "Invalidate block root" & preset():
    let
      b1 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      b2 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      processor = BlockProcessor.new(
        false, "", "", batchVerifier, consensusManager,
        validatorMonitor, blobQuarantine, dataColumnQuarantine,
        gloasColumnQuarantine, envelopeQuarantine, getTimeFn,
        invalidBlockRoots = @[b2.root])

    block:
      let res = await processor.addBlock(MsgSource.gossip, b2, noSidecars)
      check:
        res.isErr
        not dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)

    block:
      let res = await processor.addBlock(MsgSource.gossip, b1, noSidecars)
      check:
        res.isOk
        dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)
      while processor[].hasBlocks():
        poll()
      check:
        dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)

    block:
      let res = await processor.addBlock(MsgSource.gossip, b2, noSidecars)
      check:
        res == Result[void, VerifierError].err VerifierError.Invalid
        dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)

  asyncTest "Process a block from each fork (without blobs)" & preset():
    let processor = BlockProcessor.new(
      false, "", "", batchVerifier, consensusManager, validatorMonitor,
      blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getTimeFn,
    )

    debugGloasComment "TODO testing"
    for consensusFork in ConsensusFork.Bellatrix .. ConsensusFork.Fulu:
      process_slots(
        cfg,
        state[],
        max(
          state[].slot + 1,
          cfg.consensusForkEpoch(consensusFork).start_slot,
        ),
        cache,
        info,
        {},
      )
      .expect("OK")

      withState(state[]):
        let b0 = addTestEngineBlock(cfg, consensusFork, forkyState, cache)
        discard await processor.addBlock(
          MsgSource.gossip, b0.blck, b0.blobsBundle.toSidecarsOpt(consensusFork)
        )

  asyncTest "Process Deneb block with blob sidecars" & preset():
    # Advance to Deneb fork
    process_slots(
      cfg, state[], start_slot(cfg.DENEB_FORK_EPOCH),
      cache, info, {}
    ).expect("OK")

    let processor = BlockProcessor.new(
      false, "", "", batchVerifier, consensusManager, validatorMonitor,
      blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getTimeFn
    )

    withState(state[]):
      when consensusFork == ConsensusFork.Deneb:
        # Create valid blobs and KZG data
        let kzgBlob = createValidKzgBlob()
        let commitment = kzg.blobToKzgCommitment(kzgBlob).valueOr:
          raiseAssert "Failed to create commitment"
        let proof = kzg.computeBlobKzgProof(kzgBlob, commitment).valueOr:
          raiseAssert "Failed to create proof"

        # Build BlobsBundle using testblockutil's type
        var blobsBundle = testblockutil.BlobsBundle(
          commitments: @[commitment],
          proofs: @[proof],
          blobs: @[kzgBlob.bytes]
        )

        # Create block with blobs
        let engineBlock = addTestEngineBlockWithBlobs(
          cfg, ConsensusFork.Deneb, forkyState, blobsBundle, cache = cache
        )

        # Create blob sidecars from the block
        var blobs: deneb.Blobs
        var kzg_proofs: deneb.KzgProofs
        doAssert blobs.add(kzgBlob.bytes)
        doAssert kzg_proofs.add(proof)

        let blobSidecars = create_blob_sidecars(
          engineBlock.blck, kzg_proofs, blobs
        )
        let bscarRef = blobSidecars.mapIt(newClone(it))

        # Process the block with blob sidecars
        let res = await processor.addBlock(
          MsgSource.gossip,
          engineBlock.blck,
          Opt.some(bscarRef)
        )

        check:
          res.isOk
          dag.containsForkBlock(engineBlock.blck.root)

  asyncTest "Process Deneb block without blob sidecars" & preset():
    # Advance to Deneb fork
    process_slots(
      cfg, state[], start_slot(cfg.DENEB_FORK_EPOCH),
      cache, info, {}
    ).expect("OK")

    let processor = BlockProcessor.new(
      false, "", "", batchVerifier, consensusManager, validatorMonitor,
      blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getTimeFn
    )

    withState(state[]):
      when consensusFork == ConsensusFork.Deneb:
        # Create block without blobs (default behavior)
        let engineBlock = addTestEngineBlock(cfg, ConsensusFork.Deneb, forkyState, cache)

        # Verify block has no blob commitments
        check:
          engineBlock.blck.message.body.blob_kzg_commitments.len == 0

        # Process should succeed (empty commitments is valid)
        let res = await processor.addBlock(
          MsgSource.gossip,
          engineBlock.blck,
          Opt.none(deneb.BlobSidecars)
        )

        check:
          res.isOk
          dag.containsForkBlock(engineBlock.blck.root)

  asyncTest "Process Fulu block with data column sidecars" & preset():
    # Advance to Fulu fork
    process_slots(
      cfg, state[], start_slot(cfg.FULU_FORK_EPOCH),
      cache, info, {}
    ).expect("OK")

    let processor = BlockProcessor.new(
      false, "", "", batchVerifier, consensusManager, validatorMonitor,
      blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getTimeFn
    )

    withState(state[]):
      when consensusFork == ConsensusFork.Fulu:
        # Create valid blobs and compute cells/proofs
        let kzgBlob = createValidKzgBlob()
        let commitment = kzg.blobToKzgCommitment(kzgBlob).valueOr:
          raiseAssert "Failed to create commitment"

        let cellsAndProofs = kzg.computeCellsAndKzgProofs(kzgBlob).valueOr:
          raiseAssert "Failed to compute cells and proofs"

        # Build BlobsBundle
        var blobsBundle = testblockutil.BlobsBundle(
          commitments: @[commitment],
          proofs: cellsAndProofs.proofs.mapIt(kzg.KzgProof(it)),
          blobs: @[kzgBlob.bytes]
        )

        # Create block with blobs
        let engineBlock = addTestEngineBlockWithBlobs(
          cfg, ConsensusFork.Fulu, forkyState, blobsBundle, cache = cache
        )

        # Assemble data column sidecars
        let dataColumnSidecars = assemble_data_column_sidecars(
          engineBlock.blck, @[kzgBlob], cellsAndProofs.proofs.mapIt(kzg.KzgProof(it))
        )
        let dsRef = dataColumnSidecars.mapIt(newClone(it))

        # Process the block with data columns
        let res = await processor.addBlock(
          MsgSource.gossip,
          engineBlock.blck,
          Opt.some(dsRef)
        )

        check:
          res.isOk
          dag.containsForkBlock(engineBlock.blck.root)

  asyncTest "Process Fulu block without data column sidecars" & preset():
    # Advance to Fulu fork
    process_slots(
      cfg, state[], start_slot(cfg.FULU_FORK_EPOCH),
      cache, info, {}
    ).expect("OK")

    let processor = BlockProcessor.new(
      false, "", "", batchVerifier, consensusManager, validatorMonitor,
      blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getTimeFn
    )

    withState(state[]):
      when consensusFork == ConsensusFork.Fulu:
        # Create block without blobs
        let engineBlock = addTestEngineBlock(cfg, ConsensusFork.Fulu, forkyState, cache)

        # Verify block has no blob commitments
        check:
          engineBlock.blck.message.body.blob_kzg_commitments.len == 0

        # Process should succeed (empty commitments is valid)
        let res = await processor.addBlock(
          MsgSource.gossip,
          engineBlock.blck,
          Opt.none(fulu.DataColumnSidecars)
        )

        check:
          res.isOk
          dag.containsForkBlock(engineBlock.blck.root)

  asyncTest "Assemble partial data column sidecars from Fulu block" & preset():
    # Advance to Fulu fork
    process_slots(
      cfg, state[], start_slot(cfg.FULU_FORK_EPOCH),
      cache, info, {}
    ).expect("OK")

    withState(state[]):
      when consensusFork == ConsensusFork.Fulu:
        let kzgBlob = createValidKzgBlob()
        let commitment = kzg.blobToKzgCommitment(kzgBlob).valueOr:
          raiseAssert "Failed to create commitment"

        let cellsAndProofs = kzg.computeCellsAndKzgProofs(kzgBlob).valueOr:
          raiseAssert "Failed to compute cells and proofs"

        var blobsBundle = testblockutil.BlobsBundle(
          commitments: @[commitment],
          proofs: cellsAndProofs.proofs.mapIt(kzg.KzgProof(it)),
          blobs: @[kzgBlob.bytes]
        )

        let engineBlock = addTestEngineBlockWithBlobs(
          cfg, ConsensusFork.Fulu, forkyState, blobsBundle, cache = cache
        )

        # Wrap cell proofs as Opt.some (proposer has all proofs)
        let optProofs = cellsAndProofs.proofs.mapIt(Opt.some(kzg.KzgProof(it)))
        let partialSidecars = assemble_partial_data_column_sidecars(
          engineBlock.blck, @[kzgBlob], optProofs)

        check:
          # One partial sidecar per column (CELLS_PER_EXT_BLOB columns)
          partialSidecars.len > 0
          # Each sidecar should have 1 cell (1 blob)
          partialSidecars[0].partial_columns.len == 1
          partialSidecars[0].kzg_proofs.len == 1
          # Bitmap should have bit 0 set (blob index 0)
          partialSidecars[0].cells_present_bitmap[0] == true

  asyncTest "Partial column quarantine round-trip assembly" & preset():
    # Advance to Fulu fork
    process_slots(
      cfg, state[], start_slot(cfg.FULU_FORK_EPOCH),
      cache, info, {}
    ).expect("OK")

    withState(state[]):
      when consensusFork == ConsensusFork.Fulu:
        let kzgBlob = createValidKzgBlob()
        let commitment = kzg.blobToKzgCommitment(kzgBlob).valueOr:
          raiseAssert "Failed to create commitment"

        let cellsAndProofs = kzg.computeCellsAndKzgProofs(kzgBlob).valueOr:
          raiseAssert "Failed to compute cells and proofs"

        var blobsBundle = testblockutil.BlobsBundle(
          commitments: @[commitment],
          proofs: cellsAndProofs.proofs.mapIt(kzg.KzgProof(it)),
          blobs: @[kzgBlob.bytes]
        )

        let engineBlock = addTestEngineBlockWithBlobs(
          cfg, ConsensusFork.Fulu, forkyState, blobsBundle, cache = cache
        )

        let blockRoot = engineBlock.blck.root
        let numBlobs = engineBlock.blck.message.body.blob_kzg_commitments.len

        # Assemble full data column sidecars (reference)
        let fullSidecars = assemble_data_column_sidecars(
          engineBlock.blck, @[kzgBlob],
          cellsAndProofs.proofs.mapIt(kzg.KzgProof(it)))

        # Assemble partial data column sidecars
        let optProofs = cellsAndProofs.proofs.mapIt(Opt.some(kzg.KzgProof(it)))
        let partialSidecars = assemble_partial_data_column_sidecars(
          engineBlock.blck, @[kzgBlob], optProofs)

        # Build header from block
        let
          beacon_block_header = BeaconBlockHeader(
            slot: engineBlock.blck.message.slot,
            proposer_index: engineBlock.blck.message.proposer_index,
            parent_root: engineBlock.blck.message.parent_root,
            state_root: engineBlock.blck.message.state_root,
            body_root: hash_tree_root(engineBlock.blck.message.body))
          signed_beacon_block_header = SignedBeaconBlockHeader(
            message: beacon_block_header,
            signature: engineBlock.blck.signature)
        var pHeader = fulu.PartialDataColumnHeader(
          kzg_commitments: engineBlock.blck.message.body.blob_kzg_commitments,
          signed_block_header: signed_beacon_block_header)
        engineBlock.blck.message.body.build_proof(
          KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex,
          pHeader.kzg_commitments_inclusion_proof).expect("Valid gindex")

        # Use quarantine to ingest partials and reassemble
        var pcq = PartialColumnQuarantine.init()
        pcq.putPartialHeader(blockRoot, pHeader)

        # Pick column index 0 for the round-trip test
        let colIdx = ColumnIndex(0)
        discard pcq.getOrCreateEntry(blockRoot, colIdx, numBlobs)
        pcq.addCells(blockRoot, colIdx, partialSidecars[0])

        check:
          pcq.isComplete(blockRoot, colIdx)

        let assembled = pcq.assembleDataColumnSidecar(blockRoot, colIdx)
        check:
          assembled.isSome()
          # The assembled sidecar should match the directly-assembled full sidecar
          assembled.get().index == fullSidecars[0].index
          assembled.get().column.len == fullSidecars[0].column.len
          assembled.get().kzg_proofs.len == fullSidecars[0].kzg_proofs.len
          assembled.get().kzg_commitments == fullSidecars[0].kzg_commitments

  asyncTest "Process Fulu block via partial-assembled data columns" & preset():
    # Advance to Fulu fork
    process_slots(
      cfg, state[], start_slot(cfg.FULU_FORK_EPOCH),
      cache, info, {}
    ).expect("OK")

    let processor = BlockProcessor.new(
      false, "", "", batchVerifier, consensusManager, validatorMonitor,
      blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getTimeFn
    )

    withState(state[]):
      when consensusFork == ConsensusFork.Fulu:
        let kzgBlob = createValidKzgBlob()
        let commitment = kzg.blobToKzgCommitment(kzgBlob).valueOr:
          raiseAssert "Failed to create commitment"

        let cellsAndProofs = kzg.computeCellsAndKzgProofs(kzgBlob).valueOr:
          raiseAssert "Failed to compute cells and proofs"

        var blobsBundle = testblockutil.BlobsBundle(
          commitments: @[commitment],
          proofs: cellsAndProofs.proofs.mapIt(kzg.KzgProof(it)),
          blobs: @[kzgBlob.bytes]
        )

        let engineBlock = addTestEngineBlockWithBlobs(
          cfg, ConsensusFork.Fulu, forkyState, blobsBundle, cache = cache
        )

        let blockRoot = engineBlock.blck.root
        let numBlobs = engineBlock.blck.message.body.blob_kzg_commitments.len

        # Assemble partial sidecars
        let optProofs = cellsAndProofs.proofs.mapIt(Opt.some(kzg.KzgProof(it)))
        let partialSidecars = assemble_partial_data_column_sidecars(
          engineBlock.blck, @[kzgBlob], optProofs)

        # Build header
        let
          beacon_block_header = BeaconBlockHeader(
            slot: engineBlock.blck.message.slot,
            proposer_index: engineBlock.blck.message.proposer_index,
            parent_root: engineBlock.blck.message.parent_root,
            state_root: engineBlock.blck.message.state_root,
            body_root: hash_tree_root(engineBlock.blck.message.body))
          signed_beacon_block_header = SignedBeaconBlockHeader(
            message: beacon_block_header,
            signature: engineBlock.blck.signature)
        var pHeader = fulu.PartialDataColumnHeader(
          kzg_commitments: engineBlock.blck.message.body.blob_kzg_commitments,
          signed_block_header: signed_beacon_block_header)
        engineBlock.blck.message.body.build_proof(
          KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex,
          pHeader.kzg_commitments_inclusion_proof).expect("Valid gindex")

        # Use quarantine to reassemble all columns from partials
        var pcq = PartialColumnQuarantine.init()
        pcq.putPartialHeader(blockRoot, pHeader)

        var reassembled: seq[fulu.DataColumnSidecar]
        for i in 0 ..< partialSidecars.len:
          let colIdx = ColumnIndex(i)
          discard pcq.getOrCreateEntry(blockRoot, colIdx, numBlobs)
          pcq.addCells(blockRoot, colIdx, partialSidecars[i])
          let assembled = pcq.assembleDataColumnSidecar(blockRoot, colIdx)
          check assembled.isSome()
          reassembled.add(assembled.get())

        let dsRef = reassembled.mapIt(newClone(it))

        # Process the block with reassembled data columns
        let res = await processor.addBlock(
          MsgSource.gossip,
          engineBlock.blck,
          Opt.some(dsRef)
        )

        check:
          res.isOk
          dag.containsForkBlock(engineBlock.blck.root)

# Clean up KZG trusted setup at the end of all tests
doAssert kzg.freeTrustedSetup().isOk
