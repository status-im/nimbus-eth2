# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/shims/hashes,
  ./[block_pools_types, block_quarantine],
  ../spec/[digest, forks]

type
  ExecPayloadUniqKey = object
    root: Eth2Digest
    builderIdx: uint64

  ExecPayloadEnvelopeStatus {.pure.} = enum
    None = 0,
    Valid

  ExecPayloadEnvelopeProgress {.pure.} = enum
    None = 0,
    Processing,
    Processed

  ExecPayloadEnvelopeDetail = object
    envelope: SignedExecutionPayloadEnvelope
    status: ExecPayloadEnvelopeStatus
    progress: ExecPayloadEnvelopeProgress

  BeaconBlockDetail = object
    executionEnabled: bool

  FullBlockPool* = object
    ## An experimental pool for keeping track of execution payload envelope and
    ## beacon block for constructing a full beacon block.

    blocks: Table[Eth2Digest, BeaconBlockDetail]
      ## Blocks that received from the network.
    envelopes: OrderedTable[ExecPayloadUniqKey, ExecPayloadEnvelopeDetail]
      ## Execution payload envelopes that received from the network.
      # TODO: persistent storage for valid envelope for the retention period

func hash*(x: ExecPayloadUniqKey): Hash =
  hashAllFields(x)

func toExecPayloadUniqKey(
    envelope: SignedExecutionPayloadEnvelope): ExecPayloadUniqKey =
  ExecPayloadUniqKey(
    root: envelope.message.beacon_block_root,
    builderIdx: envelope.message.builder_index)

func toExecPayloadUniqKey(
    blck: gloas.SignedBeaconBlock): ExecPayloadUniqKey =
  template bid: untyped = blck.message.body.signed_execution_payload_bid
  ExecPayloadUniqKey(
    root: blck.root,
    builderIdx: bid.message.builder_index)

func init*(
    T: type FullBlockPool):
    FullBlockPool =
  debugGloasComment("")
  T()

func pruneData*(pool: var FullBlockPool) =
  debugGloasComment("")

func addEnvelope*(
    pool: var FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope) =
  pool.envelopes[envelope.toExecPayloadUniqKey()] =
    ExecPayloadEnvelopeDetail(envelope: envelope)

func addBlock*(
    pool: var FullBlockPool,
    blck: ForkySignedBeaconBlock) =
  pool.blocks[blck.root] = BeaconBlockDetail()

func checkEnvelopeStatus(
    pool: FullBlockPool,
    key: ExecPayloadUniqKey,
    status: ExecPayloadEnvelopeStatus): bool =
  try:
    pool.envelopes[key].status == status
  except KeyError:
    false

func checkEnvelopeProgress(
    pool: FullBlockPool,
    key: ExecPayloadUniqKey,
    progress: ExecPayloadEnvelopeProgress): bool =
  try:
    pool.envelopes[key].progress == progress
  except KeyError:
    false

func isEnvelopeSeen*(
    pool: FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope): bool =
  envelope.toExecPayloadUniqKey() in pool.envelopes

func isEnvelopeValid*(
    pool: FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope): bool =
  pool.checkEnvelopeStatus(envelope.toExecPayloadUniqKey(),
    ExecPayloadEnvelopeStatus.Valid)

func isEnvelopeProcessing*(
    pool: FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope): bool =
  pool.checkEnvelopeProgress(envelope.toExecPayloadUniqKey(),
    ExecPayloadEnvelopeProgress.Processing)

func isEnvelopeProcessed*(
    pool: FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope): bool =
  pool.checkEnvelopeProgress(envelope.toExecPayloadUniqKey(),
    ExecPayloadEnvelopeProgress.Processed)

func isBlockExecutionEnabled*(
    pool: FullBlockPool,
    blck: ForkySignedBeaconBlock): bool =
  try:
    pool.blocks[blck.root].executionEnabled
  except KeyError:
    false

func isBlockSeen*(
    pool: FullBlockPool,
    blockRoot: Eth2Digest): bool =
  blockRoot in pool.blocks

func isBlockSeen*(
    pool: FullBlockPool,
    blck: ForkySignedBeaconBlock): bool =
  pool.isBlockSeen(blck.root)

func getEnvelope(
    pool: FullBlockPool,
    key: ExecPayloadUniqKey):
    Opt[SignedExecutionPayloadEnvelope] =
  try:
    Opt.some(pool.envelopes[key].envelope)
  except KeyError:
    Opt.none(SignedExecutionPayloadEnvelope)

func getEnvelope*(
    pool: FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope):
    Opt[SignedExecutionPayloadEnvelope] =
  pool.getEnvelope(envelope.toExecPayloadUniqKey())

func getEnvelope*(
    pool: FullBlockPool,
    blck: ForkySignedBeaconBlock):
    Opt[SignedExecutionPayloadEnvelope] =
  withBlck(blck):
    when consensusFork >= Gloas:
      pool.getEnvelope(forkyBlck.toExecPayloadUniqKey())
    else:
      Opt.none(SignedExecutionPayloadEnvelope)

func setEnvelopeStatus(
    pool: var FullBlockPool,
    key: ExecPayloadUniqKey,
    status: ExecPayloadEnvelopeStatus) =
  if key notin pool.envelopes:
    return
  try:
    pool.envelopes[key].status = status
  except KeyError:
    return

func setEnvelopeProgress(
    pool: var FullBlockPool,
    key: ExecPayloadUniqKey,
    progress: ExecPayloadEnvelopeProgress) =
  if key notin pool.envelopes:
    return
  try:
    pool.envelopes[key].progress = progress
  except KeyError:
    return

func markEnvelopeValid*(
    pool: var FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope) =
  pool.setEnvelopeStatus(envelope.toExecPayloadUniqKey(),
    ExecPayloadEnvelopeStatus.Valid)

func markEnvelopeProcessing*(
    pool: var FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope) =
  pool.setEnvelopeProgress(envelope.toExecPayloadUniqKey(),
    ExecPayloadEnvelopeProgress.Processing)

func markEnvelopeProcessed*(
    pool: var FullBlockPool,
    envelope: SignedExecutionPayloadEnvelope) =
  pool.setEnvelopeProgress(envelope.toExecPayloadUniqKey(),
    ExecPayloadEnvelopeProgress.Processed)

func markBlockExecutionEnabled*(
    pool: var FullBlockPool,
    blck: ForkySignedBeaconBlock) =
  if blck.root notin pool.blocks:
    return
  try:
    pool.blocks[blck.root].executionEnabled = true
  except KeyError:
    return
