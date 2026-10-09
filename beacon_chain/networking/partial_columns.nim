# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md

import
  std/hashes,
  minilru, results,
  kzg4844/kzg_abi,
  ssz_serialization/bitseqs,
  libp2p/protocols/pubsub/gossipsub/partial_message,
  libp2p/protocols/pubsub/rpc/messages,
  ../spec/[eth2_ssz_serialization, forks, network]

export partial_message

const
  MaxPublishedColumns = 2 * int(NUMBER_OF_COLUMNS)
    ## Enough room for all columns of the last two blocks this node sent out.

type
  PublishedColumnKey = object
    beacon_block_root: Eth2Digest
    index: ColumnIndex

  PublishedColumns* = LruCache[PublishedColumnKey, ref gloas.DataColumnSidecar]
    ## Full columns this node sent out. Peers using partial messages don't get
    ## full columns, so we keep them here to send those peers the cells they ask
    ## for, even for columns we don't custody.

func hash(key: PublishedColumnKey): Hash =
  var h: Hash = 0
  h = h !& hash(key.beacon_block_root)
  h = h !& hash(uint64(key.index))
  !$h

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md#modified-partialdatacolumnpartsmetadata
func encodePartsMetadata(available, requests: BitSeq): PartsMetadata =
  SSZ.encode(gloas.PartialDataColumnPartsMetadata(
    available: available, requests: requests))

func decodePartsMetadata(
    data: openArray[byte]
): Result[gloas.PartialDataColumnPartsMetadata, string] =
  let metadata =
    try:
      SSZ.decode(data, gloas.PartialDataColumnPartsMetadata)
    except SerializationError as exc:
      return err(exc.msg)
  if metadata.available.len != metadata.requests.len:
    return err("PartialDataColumnPartsMetadata: bitlist lengths differ")
  ok(metadata)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.2/specs/gloas/partial-columns/p2p-interface.md#new-compute_max_partial_data_column_sidecar_size
func compute_max_partial_data_column_sidecar_size*(cfg: RuntimeConfig): uint64 =
  ## Serialized size of a `PartialDataColumnSidecar` carrying every cell for
  ## the largest `max_blobs_per_block` in the blob schedule.
  var max_blobs = cfg.MAX_BLOBS_PER_BLOCK_ELECTRA
  for entry in cfg.BLOB_SCHEDULE:
    max_blobs = max(max_blobs, entry.MAX_BLOBS_PER_BLOCK)

  let sidecar = gloas.PartialDataColumnSidecar(
    cells_present_bitmap: gloas.CellsPresentBits.init(int(max_blobs)),
    partial_column: newSeq[KzgCell](int(max_blobs)),
    kzg_proofs: newSeq[KzgProof](int(max_blobs)))
  uint64(SSZ.encode(sidecar).len)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md#modified-partialdatacolumnsidecar
func decodePartialDataColumnSidecar*(
    data: openArray[byte]): Result[gloas.PartialDataColumnSidecar, string] =
  ## `validatePartialRPC` has already bounded the size of `data`.
  try:
    ok(SSZ.decode(data, gloas.PartialDataColumnSidecar))
  except SerializationError as exc:
    err(exc.msg)

func unionPartsMetadata*(
    a, b: PartsMetadata): Result[PartsMetadata, string] =
  let
    x = ? decodePartsMetadata(a)
    y = ? decodePartsMetadata(b)
  if x.available.len != y.available.len:
    return err("PartialDataColumnPartsMetadata: bitlist lengths differ")
  var
    available = x.available
    requests = x.requests
  for i in 0 ..< available.len:
    if y.available[i]:
      available.setBit(i)
    if y.requests[i]:
      requests.setBit(i)
  ok(encodePartsMetadata(available, requests))

func validatePartialRPC*(
    rpc: PartialMessageExtensionRPC,
    maxSidecarSize: uint64): Result[void, string] =
  decodePartialDataColumnGroupId(rpc.groupID.get(@[])).isOkOr:
    return err($error)
  if rpc.partsMetadata.isSome():
    discard ? decodePartsMetadata(rpc.partsMetadata.get())
  if rpc.partialMessage.isSome() and
      uint64(rpc.partialMessage.get().len) > maxSidecarSize:
    return err("PartialDataColumnSidecar: too large")
  ok()

func partsMetadata*(available: BitSeq): PartsMetadata =
  ## Advertise the cells in `available` and request all others.
  var requests = BitSeq.init(available.len)
  for i in 0 ..< available.len:
    if not available[i]:
      requests.setBit(i)
  encodePartsMetadata(available, requests)

func materializeParts*(
    available: BitSeq, cells: openArray[KzgCell], proofs: openArray[KzgProof],
    metadata: PartsMetadata
): Result[PartsData, string] =
  ## `cells` and `proofs` are indexed by blob index. Empty `metadata` asks for
  ## every available cell.
  var wanted = BitSeq.init(available.len)
  if metadata.len == 0:
    wanted = available
  else:
    let peer = ? decodePartsMetadata(metadata)
    if peer.available.len != available.len:
      return err("PartialDataColumnPartsMetadata: unexpected bitlist length")
    for i in 0 ..< available.len:
      if available[i] and peer.requests[i] and not peer.available[i]:
        wanted.setBit(i)

  var
    bitmap = gloas.CellsPresentBits.init(available.len)
    partCells: seq[KzgCell]
    partProofs: seq[KzgProof]
  for i in 0 ..< available.len:
    if wanted[i]:
      bitmap.setBit(i)
      partCells.add cells[i]
      partProofs.add proofs[i]

  if partCells.len == 0:
    return ok(default(PartsData))
  ok(SSZ.encode(gloas.PartialDataColumnSidecar(
    cells_present_bitmap: bitmap, partial_column: partCells,
    kzg_proofs: partProofs)))

func allCells(numBlobs: int): BitSeq =
  var cells = BitSeq.init(numBlobs)
  for i in 0 ..< numBlobs:
    cells.setBit(i)
  cells

func completePartsMetadata*(numBlobs: int): PartsMetadata =
  ## Says we have every cell and need none.
  encodePartsMetadata(allCells(numBlobs), BitSeq.init(numBlobs))

func materializeParts*(
    sidecar: gloas.DataColumnSidecar, metadata: PartsMetadata
): Result[PartsData, string] =
  ## Picks the cells a peer asked for from a full column.
  materializeParts(
    allCells(sidecar.column.len), sidecar.column, sidecar.kzg_proofs, metadata)

func initPublishedColumns*(): PublishedColumns =
  PublishedColumns.init(MaxPublishedColumns)

func addColumn*(
    columns: var PublishedColumns, sidecar: ref gloas.DataColumnSidecar) =
  columns.put(
    PublishedColumnKey(
      beacon_block_root: sidecar[].beacon_block_root, index: sidecar[].index),
    sidecar)

func getColumn*(
    columns: var PublishedColumns, beacon_block_root: Eth2Digest,
    index: ColumnIndex): Opt[ref gloas.DataColumnSidecar] =
  columns.get(
    PublishedColumnKey(beacon_block_root: beacon_block_root, index: index))
