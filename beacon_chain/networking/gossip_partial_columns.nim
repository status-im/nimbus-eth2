# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## Partial columns for Cell Dissemination
## https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/fulu/p2p-interface.md#partial-columns-for-cell-dissemination
##
## Gossipsub's Partial Message Extension enables exchanging selective parts of
## a message rather than the whole. This module implements the application-level
## glue between nim-libp2p's gossipsub Partial Message Extension and
## nimbus-eth2's data column types.
##
## It provides:
## - `DataColumnPartialMessage`: a concrete `PartialMessage` subclass wrapping
##   `PartialDataColumnSidecar`
## - `PartialMessageExtensionConfig` factory for use when initializing GossipSub
## - Encoding/decoding helpers for `PartialDataColumnPartsMetadata`

import
  results,
  chronicles,
  libp2p/peerid,
  libp2p/protocols/pubsub/gossipsub/partial_message,
  libp2p/protocols/pubsub/gossipsub/extensions,
  libp2p/protocols/pubsub/rpc/messages,
  ../spec/datatypes/[fulu, base],
  ../spec/[eth2_ssz_serialization, digest, network],
  ../spec/datatypes/deneb

export partial_message, extensions

logScope:
  topics = "gossip_partial_columns"

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/fulu/p2p-interface.md#partial-message-group-id
# When sending a partial message, the gossipsub group ID MUST be the block
# root prefixed by a single byte used for versioning. The version byte MUST
# be zero. Other versions may be defined later.
const
  PartialGroupIdVersion*: byte = 0x00
  PartialGroupIdLen* = 1 + 32  # version byte + Eth2Digest

type
  DataColumnPartialMessage* = ref object of PartialMessage
    ## Concrete PartialMessage for a single data column's partial cells.
    ## Wraps a PartialDataColumnSidecar and its associated block root +
    ## column index.
    blockRoot: Eth2Digest
    columnIndex: ColumnIndex
    sidecar: fulu.PartialDataColumnSidecar

  OnPartialColumnRPCCallback* = proc(
    peer: PeerId, rpc: PartialMessageExtensionRPC
  ) {.gcsafe, raises: [].}

# -----------------------------------------------------------------------------
# GroupId: version_byte(0x00) ++ block_root (33 bytes total)
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/fulu/p2p-interface.md#partial-message-group-id
# -----------------------------------------------------------------------------

func makeGroupId*(blockRoot: Eth2Digest): GroupId =
  var id = newSeqOfCap[byte](PartialGroupIdLen)
  id.add(PartialGroupIdVersion)
  id.add(blockRoot.data)
  id

func parseGroupId*(groupId: GroupId): Result[Eth2Digest, string] =
  if groupId.len != PartialGroupIdLen:
    return err("invalid groupId length: " & $groupId.len)
  if groupId[0] != PartialGroupIdVersion:
    return err("unsupported groupId version: " & $groupId[0])
  var root: Eth2Digest
  for i in 0 ..< 32:
    root.data[i] = groupId[1 + i]
  ok(root)

# -----------------------------------------------------------------------------
# PartsMetadata: SSZ-encoded PartialDataColumnPartsMetadata
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/fulu/p2p-interface.md#parts-metadata
# The parts metadata is encoded with the PartialDataColumnPartsMetadata
# container.
# -----------------------------------------------------------------------------

func encodePartsMetadata*(metadata: fulu.PartialDataColumnPartsMetadata): PartsMetadata =
  SSZ.encode(metadata)

func decodePartsMetadata*(data: PartsMetadata): Result[fulu.PartialDataColumnPartsMetadata, string] =
  try:
    ok(SSZ.decode(data, fulu.PartialDataColumnPartsMetadata))
  except SerializationError as e:
    err("failed to decode PartialDataColumnPartsMetadata: " & e.msg)

func unionPartsMetadata*(
    a, b: PartsMetadata
): Result[PartsMetadata, string] =
  ## Creates a union of two PartialDataColumnPartsMetadata:
  ## - available bits are OR'd together
  ## - requests bits are OR'd together, then any bits already available
  ##   are cleared
  let
    metaA = ? decodePartsMetadata(a)
    metaB = ? decodePartsMetadata(b)

  var merged: fulu.PartialDataColumnPartsMetadata
  for i in 0.Natural ..< MAX_BLOB_COMMITMENTS_PER_BLOCK.Natural:
    merged.available[i] = metaA.available[i] or metaB.available[i]
    # Union of requests, but clear bits that are now available
    let wantsBit = metaA.requests[i] or metaB.requests[i]
    merged.requests[i] = wantsBit and not merged.available[i]

  ok(encodePartsMetadata(merged))

# -----------------------------------------------------------------------------
# DataColumnPartialMessage: concrete PartialMessage
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/fulu/p2p-interface.md#encoding-and-decoding-responses
# All responses MUST be encoded and decoded with the
# PartialDataColumnSidecar container.
# -----------------------------------------------------------------------------

func newDataColumnPartialMessage*(
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex,
    sidecar: fulu.PartialDataColumnSidecar
): DataColumnPartialMessage =
  DataColumnPartialMessage(
    blockRoot: blockRoot,
    columnIndex: columnIndex,
    sidecar: sidecar,
  )

proc groupId*(m: DataColumnPartialMessage): GroupId =
  makeGroupId(m.blockRoot)

proc partsMetadata*(m: DataColumnPartialMessage): PartsMetadata =
  ## Returns metadata indicating which cells are available in this partial
  ## message.
  var metadata: fulu.PartialDataColumnPartsMetadata
  # cells_present_bitmap is a variable-length BitList; copy the present bits
  # into the fixed-width metadata bitmap.
  for i in 0 ..< m.sidecar.cells_present_bitmap.len:
    if m.sidecar.cells_present_bitmap[Natural(i)]:
      metadata.available[i] = true
  # We don't set requests here -- this describes what we *have*
  encodePartsMetadata(metadata)

proc materializeParts*(
    m: DataColumnPartialMessage, metadata: PartsMetadata
): Result[PartsData, string] =
  ## Given metadata describing what a peer wants/has, produce a
  ## PartialDataColumnSidecar containing the cells the peer is missing
  ## that we have available.
  ##
  ## If metadata is empty, return all available parts.

  if metadata.len == 0:
    # Return all available parts
    return ok(PartsData(SSZ.encode(m.sidecar)))

  let peerMeta = ? decodePartsMetadata(metadata)

  # Determine which cells the peer needs (they request) that we have
  var
    bitmap = CellsPresentBits.init(m.sidecar.cells_present_bitmap.len)
    cells = newSeqOfCap[KzgCell](m.sidecar.partial_column.len)
    proofs = newSeqOfCap[KzgProof](m.sidecar.kzg_proofs.len)
    ourIdx = 0  # index into our sparse arrays

  for i in 0 ..< m.sidecar.cells_present_bitmap.len:
    if m.sidecar.cells_present_bitmap[Natural(i)]:
      # We have this cell
      let peerWants = peerMeta.requests[i]
      let peerDoesntHave = not peerMeta.available[i]
      if peerWants or peerDoesntHave:
        # Peer needs this cell -- include it
        bitmap[Natural(i)] = true
        cells.add(m.sidecar.partial_column[ourIdx])
        proofs.add(m.sidecar.kzg_proofs[ourIdx])
      ourIdx.inc

  if cells.len == 0:
    return ok(PartsData(@[]))

  let response = fulu.PartialDataColumnSidecar(
    cells_present_bitmap: bitmap,
    partial_column: DataColumn.init(cells),
    kzg_proofs: deneb.KzgProofs.init(proofs),
    # Don't include header in materialized parts -- it's sent separately
  )
  ok(PartsData(SSZ.encode(response)))

# -----------------------------------------------------------------------------
# Validation
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/fulu/p2p-interface.md#partial-message-group-id
# -----------------------------------------------------------------------------

func validatePartialMessageRPC*(
    rpc: PartialMessageExtensionRPC
): Result[void, string] =
  ## Basic sanity checks on incoming PartialMessageExtensionRPC.
  ## Validates the group ID format per spec: version byte must be zero,
  ## total length must be 33 bytes (1 version + 32 block root).
  if rpc.groupID.len != PartialGroupIdLen:
    return err("invalid groupId length: " & $rpc.groupID.len)
  if rpc.groupID[0] != PartialGroupIdVersion:
    return err("unsupported groupId version: " & $rpc.groupID[0])
  # partsMetadata can be empty (no metadata update, just data)
  # partialMessage can be empty (metadata-only update)
  ok()

# -----------------------------------------------------------------------------
# Config factory
# -----------------------------------------------------------------------------

proc makePartialMessageExtensionConfig*(
    onIncomingRPC: OnPartialColumnRPCCallback
): PartialMessageExtensionConfig =
  ## Creates a PartialMessageExtensionConfig with nimbus-eth2 data column
  ## semantics. The caller provides the `onIncomingRPC` callback which
  ## handles incoming partial cell data (feeding into quarantine, etc).
  ##
  ## The `sendRPC`, `publishToPeers`, `nodeTopicOpts`, and `isSupported`
  ## callbacks are left nil here -- GossipSub fills them with defaults in
  ## `createExtensionsState`.
  PartialMessageExtensionConfig(
    unionPartsMetadata: unionPartsMetadata,
    validateRPC: validatePartialMessageRPC,
    onIncomingRPC: onIncomingRPC,
    heartbeatsTillEviction: 6,
      # Retain group state for ~6 heartbeats (~4.2s at 700ms interval).
      # This covers a full slot (12s is ~17 heartbeats) generously.
  )
