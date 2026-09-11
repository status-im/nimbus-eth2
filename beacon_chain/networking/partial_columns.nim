# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md

import
  results,
  kzg4844/kzg_abi,
  ssz_serialization/bitseqs,
  libp2p/protocols/pubsub/gossipsub/partial_message,
  libp2p/protocols/pubsub/rpc/messages,
  ../spec/[eth2_ssz_serialization, forks, network]

export partial_message

type
  PartialColumnMessage* = ref object of PartialMessage
    groupId: GroupId
    available: BitSeq
    cells: seq[KzgCell]
    proofs: seq[KzgProof]

func init*(
    T: type PartialColumnMessage, groupId: gloas.PartialDataColumnGroupID,
    available: BitSeq, cells: openArray[KzgCell],
    proofs: openArray[KzgProof]): T =
  ## `cells` and `proofs` are indexed by blob index.
  T(groupId: encodePartialDataColumnGroupId(groupId), available: available,
    cells: @cells, proofs: @proofs)

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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md#modified-partialdatacolumnsidecar
func decodePartialDataColumnSidecar*(
    data: openArray[byte]): Result[gloas.PartialDataColumnSidecar, string] =
  if uint64(data.len) > MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE:
    return err("PartialDataColumnSidecar: too large")
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
    rpc: PartialMessageExtensionRPC): Result[void, string] =
  decodePartialDataColumnGroupId(rpc.groupID.get(@[])).isOkOr:
    return err($error)
  if rpc.partsMetadata.isSome():
    discard ? decodePartsMetadata(rpc.partsMetadata.get())
  if rpc.partialMessage.isSome() and
      uint64(rpc.partialMessage.get().len) > MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE:
    return err("PartialDataColumnSidecar: too large")
  ok()

method groupId*(m: PartialColumnMessage): GroupId =
  m.groupId

method partsMetadata*(m: PartialColumnMessage): PartsMetadata =
  var requests = BitSeq.init(m.available.len)
  for i in 0 ..< m.available.len:
    if not m.available[i]:
      requests.setBit(i)
  encodePartsMetadata(m.available, requests)

method materializeParts*(
    m: PartialColumnMessage, metadata: PartsMetadata
): Result[PartsData, string] =
  var wanted = BitSeq.init(m.available.len)
  if metadata.len == 0:
    wanted = m.available
  else:
    let peer = ? decodePartsMetadata(metadata)
    if peer.available.len != m.available.len:
      return err("PartialDataColumnPartsMetadata: unexpected bitlist length")
    for i in 0 ..< m.available.len:
      if m.available[i] and peer.requests[i] and not peer.available[i]:
        wanted.setBit(i)

  var
    bitmap = gloas.CellsPresentBits.init(m.available.len)
    cells: seq[KzgCell]
    proofs: seq[KzgProof]
  for i in 0 ..< m.available.len:
    if wanted[i]:
      bitmap[Natural(i)] = true
      cells.add m.cells[i]
      proofs.add m.proofs[i]

  if cells.len == 0:
    return ok(default(PartsData))
  ok(SSZ.encode(gloas.PartialDataColumnSidecar(
    cells_present_bitmap: bitmap, partial_column: cells, kzg_proofs: proofs)))
