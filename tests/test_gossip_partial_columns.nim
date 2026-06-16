# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  stew/endians2,
  unittest2,
  results,
  kzg4844/kzg_abi,
  ssz_serialization/[types as sszTypes, bitseqs],
  libp2p/protocols/pubsub/rpc/messages,
  ../beacon_chain/spec/datatypes/[fulu, deneb],
  ../beacon_chain/spec/[eth2_ssz_serialization, presets],
  ../beacon_chain/networking/gossip_partial_columns

func genDigest(index: int): Eth2Digest =
  let tmp = uint64(index).toBytesLE()
  copyMem(addr result.data[0], unsafeAddr tmp[0], sizeof(uint64))

func gen[T](index: int): T =
  let tmp = uint64(index).toBytesLE()
  copyMem(addr result.bytes[0], unsafeAddr tmp[0], sizeof(uint64))

func genSidecar(
    blobIndices: openArray[int], startCellId: int = 0
): fulu.PartialDataColumnSidecar =
  var
    bitmap = fulu.CellsPresentBits.init(int(MAX_BLOB_COMMITMENTS_PER_BLOCK))
    cells = newSeqOfCap[KzgCell](blobIndices.len)
    proofs = newSeqOfCap[KzgProof](blobIndices.len)
  for i, blobIdx in blobIndices:
    bitmap[Natural(blobIdx)] = true
    cells.add(gen[KzgCell](startCellId + i))
    proofs.add(gen[KzgProof](startCellId + i))
  fulu.PartialDataColumnSidecar(
    cells_present_bitmap: bitmap,
    partial_column: DataColumn.init(cells),
    kzg_proofs: deneb.KzgProofs.init(proofs))

func metaWith(
    availableBits, requestsBits: openArray[int]
): fulu.PartialDataColumnPartsMetadata =
  for b in availableBits:
    result.available[Natural(b)] = true
  for b in requestsBits:
    result.requests[Natural(b)] = true

suite "Gossip partial columns":
  # --- GroupId encode/decode ---

  test "makeGroupId produces version byte + block root":
    let
      root = genDigest(42)
      gid = makeGroupId(root)
    check:
      gid.len == PartialGroupIdLen
      gid[0] == PartialGroupIdVersion
      gid[1 .. 32] == @(root.data)

  test "parseGroupId round-trips makeGroupId":
    let
      root = genDigest(7)
      parsed = parseGroupId(makeGroupId(root))
    check:
      parsed.isOk
      parsed.get() == root

  test "parseGroupId rejects wrong length":
    let short: GroupId = @[byte 0]
    let long: GroupId = newSeq[byte](PartialGroupIdLen + 1)
    check:
      parseGroupId(short).isErr
      parseGroupId(long).isErr

  test "parseGroupId rejects unsupported version byte":
    var gid: GroupId = makeGroupId(genDigest(1))
    gid[0] = 0x01  # version 1 is not defined
    check parseGroupId(gid).isErr

  # --- PartsMetadata SSZ encode/decode round-trip ---

  test "encodePartsMetadata / decodePartsMetadata round-trip":
    let meta = metaWith(availableBits = [0, 3, 7], requestsBits = [1, 2])
    let decoded = decodePartsMetadata(encodePartsMetadata(meta))
    check decoded.isOk
    let r = decoded.get()
    for i in 0.Natural ..< MAX_BLOB_COMMITMENTS_PER_BLOCK.Natural:
      check:
        r.available[i] == meta.available[i]
        r.requests[i] == meta.requests[i]

  test "decodePartsMetadata rejects malformed bytes":
    # Truncated payload -- SSZ decode should raise SerializationError,
    # which decodePartsMetadata maps to an err.
    let bogus: PartsMetadata = @[byte 0xff, 0xff]
    check decodePartsMetadata(bogus).isErr

  # --- unionPartsMetadata semantics ---

  test "unionPartsMetadata ORs available bits":
    let
      a = encodePartsMetadata(metaWith([0, 2], []))
      b = encodePartsMetadata(metaWith([1, 2], []))
      merged = unionPartsMetadata(a, b)
    check merged.isOk
    let decoded = decodePartsMetadata(merged.get()).get()
    check:
      decoded.available[Natural(0)]
      decoded.available[Natural(1)]
      decoded.available[Natural(2)]
      not decoded.available[Natural(3)]

  test "unionPartsMetadata ORs requests bits when not available":
    let
      a = encodePartsMetadata(metaWith([], [4]))
      b = encodePartsMetadata(metaWith([], [5]))
      merged = unionPartsMetadata(a, b).get()
      decoded = decodePartsMetadata(merged).get()
    check:
      decoded.requests[Natural(4)]
      decoded.requests[Natural(5)]
      not decoded.requests[Natural(0)]

  test "unionPartsMetadata clears requests for bits that became available":
    # `a` requests blob 3; `b` reports blob 3 available.
    # The merged request bit for blob 3 should be cleared.
    let
      a = encodePartsMetadata(metaWith([], [3, 6]))
      b = encodePartsMetadata(metaWith([3], []))
      merged = unionPartsMetadata(a, b).get()
      decoded = decodePartsMetadata(merged).get()
    check:
      decoded.available[Natural(3)]
      not decoded.requests[Natural(3)]
      decoded.requests[Natural(6)]

  test "unionPartsMetadata is idempotent":
    let
      a = encodePartsMetadata(metaWith([0, 1], [2]))
      once = unionPartsMetadata(a, a).get()
      twice = unionPartsMetadata(once, a).get()
      d1 = decodePartsMetadata(once).get()
      d2 = decodePartsMetadata(twice).get()
    for i in 0.Natural ..< MAX_BLOB_COMMITMENTS_PER_BLOCK.Natural:
      check:
        d1.available[i] == d2.available[i]
        d1.requests[i] == d2.requests[i]

  test "unionPartsMetadata fails on malformed input":
    let
      good = encodePartsMetadata(metaWith([0], []))
      bogus: PartsMetadata = @[byte 0xff]
    check:
      unionPartsMetadata(bogus, good).isErr
      unionPartsMetadata(good, bogus).isErr

  # --- DataColumnPartialMessage / groupId / partsMetadata ---

  test "newDataColumnPartialMessage exposes groupId from blockRoot":
    let
      root = genDigest(13)
      sidecar = genSidecar([0, 1])
      m = newDataColumnPartialMessage(root, ColumnIndex(2), sidecar)
    check m.groupId() == makeGroupId(root)

  test "partsMetadata reflects the sidecar's cells_present_bitmap":
    let
      root = genDigest(1)
      sidecar = genSidecar([1, 5, 8])
      m = newDataColumnPartialMessage(root, ColumnIndex(0), sidecar)
      decoded = decodePartsMetadata(m.partsMetadata()).get()
    for i in 0.Natural ..< MAX_BLOB_COMMITMENTS_PER_BLOCK.Natural:
      check decoded.available[i] == sidecar.cells_present_bitmap[i]
      # `partsMetadata` describes only what we have; no request bits set
      check not decoded.requests[i]

  # --- materializeParts ---

  test "materializeParts with empty metadata returns the full sidecar":
    let
      sidecar = genSidecar([0, 2], startCellId = 100)
      m = newDataColumnPartialMessage(
        genDigest(1), ColumnIndex(0), sidecar)
      parts = m.materializeParts(@[]).get()
      roundTrip = SSZ.decode(seq[byte](parts), fulu.PartialDataColumnSidecar)
    for i in 0.Natural ..< MAX_BLOB_COMMITMENTS_PER_BLOCK.Natural:
      check roundTrip.cells_present_bitmap[i] == sidecar.cells_present_bitmap[i]
    check:
      roundTrip.partial_column.len == sidecar.partial_column.len
      roundTrip.kzg_proofs.len == sidecar.kzg_proofs.len

  test "materializeParts returns only cells the peer needs":
    # We hold blobs 0, 1, 2. Peer says it has blob 0, requests blob 2.
    # Expect: response carries blob 2 only.
    let
      sidecar = genSidecar([0, 1, 2], startCellId = 10)
      m = newDataColumnPartialMessage(
        genDigest(1), ColumnIndex(0), sidecar)
      peerMeta = encodePartsMetadata(metaWith(
        availableBits = [0], requestsBits = [2]))
      parts = m.materializeParts(peerMeta).get()
      decoded = SSZ.decode(seq[byte](parts), fulu.PartialDataColumnSidecar)
    check:
      decoded.cells_present_bitmap[Natural(2)]
      not decoded.cells_present_bitmap[Natural(0)]
      # Blob 1 is sent too: peer didn't say it had it (no available bit)
      # and the implementation includes any cell the peer doesn't have.
      decoded.cells_present_bitmap[Natural(1)]
      decoded.partial_column.len == 2

  test "materializeParts returns empty PartsData when peer has everything":
    let
      sidecar = genSidecar([0, 1], startCellId = 1)
      m = newDataColumnPartialMessage(
        genDigest(1), ColumnIndex(0), sidecar)
      # Peer claims to have both blobs and asks for nothing
      peerMeta = encodePartsMetadata(metaWith(
        availableBits = [0, 1], requestsBits = []))
      parts = m.materializeParts(peerMeta).get()
    check seq[byte](parts).len == 0

  test "materializeParts response omits header":
    let
      sidecar = genSidecar([0], startCellId = 5)
      m = newDataColumnPartialMessage(
        genDigest(1), ColumnIndex(0), sidecar)
      parts = m.materializeParts(@[]).get()
      decoded = SSZ.decode(seq[byte](parts), fulu.PartialDataColumnSidecar)
    check decoded.header.len == 0

  test "materializeParts forwards decode errors":
    let
      sidecar = genSidecar([0], startCellId = 1)
      m = newDataColumnPartialMessage(
        genDigest(1), ColumnIndex(0), sidecar)
      bogus: PartsMetadata = @[byte 0xff]
    check m.materializeParts(bogus).isErr

  # --- validatePartialMessageRPC ---

  test "validatePartialMessageRPC accepts a well-formed RPC":
    let rpc = PartialMessageExtensionRPC(
      topicID: "/eth2/abcdef00/data_column_sidecar_3/ssz_snappy",
      groupID: makeGroupId(genDigest(1)),
      partialMessage: @[byte 0x00],
      partsMetadata: @[])
    check validatePartialMessageRPC(rpc).isOk

  test "validatePartialMessageRPC rejects wrong groupID length":
    let rpc = PartialMessageExtensionRPC(
      topicID: "/eth2/abcdef00/data_column_sidecar_3/ssz_snappy",
      groupID: @[byte 0x00, 0x01],
      partialMessage: @[],
      partsMetadata: @[])
    check validatePartialMessageRPC(rpc).isErr

  test "validatePartialMessageRPC rejects unsupported groupID version":
    var gid = makeGroupId(genDigest(1))
    gid[0] = 0x05
    let rpc = PartialMessageExtensionRPC(
      topicID: "/eth2/abcdef00/data_column_sidecar_3/ssz_snappy",
      groupID: gid,
      partialMessage: @[],
      partsMetadata: @[])
    check validatePartialMessageRPC(rpc).isErr

  test "validatePartialMessageRPC accepts metadata-only RPC":
    # Empty partialMessage is allowed: caller must treat it as metadata-only
    let rpc = PartialMessageExtensionRPC(
      topicID: "/eth2/abcdef00/data_column_sidecar_3/ssz_snappy",
      groupID: makeGroupId(genDigest(2)),
      partialMessage: @[],
      partsMetadata: encodePartsMetadata(metaWith([0], [])))
    check validatePartialMessageRPC(rpc).isOk
