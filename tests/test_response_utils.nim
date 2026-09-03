# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import unittest2
import ../beacon_chain/sync/[sync_range, response_utils],
       ../beacon_chain/spec/[forks, column_map]


type
  GloasBlockChainItem =
    tuple[fork: ConsensusFork, slot, root, parentRoot, commitments: int]

  GloasBlockChainResultItem =
    tuple[fork: ConsensusFork, slot, root, parentRoot, commitments, env: int]

  GloasEnvelopeChainItem =
    tuple[slot, root, parentRoot: int]

func init(t: typedesc[SyncRange], srange: Slice[Slot]): SyncRange =
  SyncRange(slot: srange.a, count: uint64(len(srange)))

func createDigest(data: int): Eth2Digest =
  var res = Eth2Digest()
  let tmp = uint64(data).toBytesBE()
  copyMem(addr res.data[0], addr tmp[0], 8)
  res

func genKzgCommitment(index: int): KzgCommitment =
  var res: KzgCommitment
  let tmp = uint64(index).toBytesLE()
  copyMem(addr res.bytes[0], addr tmp[0], sizeof(uint64))
  res

func genGloasKzgCommitments(count: int): gloas.KzgCommitments =
  var res: seq[KzgCommitment]
  for i in 0 ..< count:
    res.add(genKzgCommitment(i))
  gloas.KzgCommitments(res)

func genDenebKzgCommitments(count: int): deneb.KzgCommitments =
  var res: seq[KzgCommitment]
  for i in 0 ..< count:
    res.add(genKzgCommitment(i))
  deneb.KzgCommitments(res)

func createFuluDataColumnSidecar(
    slot: Slot,
    index: ColumnIndex
): ref fulu.DataColumnSidecar =
  newClone fulu.DataColumnSidecar(
    index: index,
    signed_block_header: SignedBeaconBlockHeader(
      message: BeaconBlockHeader(
        slot: slot
      )
    )
  )

func createGloasDataColumnSidecar(
    slot: Slot,
    index: ColumnIndex,
    root: Eth2Digest
): ref gloas.DataColumnSidecar =
  newClone gloas.DataColumnSidecar(
    index: index,
    slot: slot,
    beacon_block_root: root
  )

func createFuluColumnSidecarResponseRecordList(
    slot: Slot,
    root: Eth2Digest,
    map: ColumnMap
): seq[FuluColumnSidecarResponseRecord] =
  var res: seq[FuluColumnSidecarResponseRecord]
  for index in map:
    let record = FuluColumnSidecarResponseRecord(
      block_root: root,
      sidecar: createFuluDataColumnSidecar(slot, index))
    res.add(record)
  res

func createGloasColumnSidecarResponseRecordList(
    slot: Slot,
    root: Eth2Digest,
    map: ColumnMap
): seq[GloasColumnSidecarResponseRecord] =
  var res: seq[GloasColumnSidecarResponseRecord]
  for index in map:
    let record = GloasColumnSidecarResponseRecord(
      block_root: root,
      sidecar: createGloasDataColumnSidecar(slot, index, root))
    res.add(record)
  res

func createFuluDataColumnsByRootIdentifier(
    slot: Slot,
    map: ColumnMap,
): tuple[ident: DataColumnsByRootIdentifier,
         list: seq[ref fulu.DataColumnSidecar]] =
    var
      res1: DataColumnsByRootIdentifier
      res2: seq[ref fulu.DataColumnSidecar]
      res3: seq[ColumnIndex]
    for index in map:
      let sidecar = createFuluDataColumnSidecar(slot, index)
      if res1.block_root.isZero():
        res1.block_root = hash_tree_root(sidecar[].signed_block_header.message)
      res3.add(sidecar[].index)
      res2.add(sidecar)
    res1.indices = List[ColumnIndex, Limit(NUMBER_OF_COLUMNS)](res3)
    (res1, res2)

func createGloasDataColumnsByRootIdentifier(
    slot: Slot,
    map: ColumnMap,
): tuple[ident: DataColumnsByRootIdentifier,
         list: seq[ref gloas.DataColumnSidecar]] =
  var
    res1: DataColumnsByRootIdentifier
    res2: seq[ref gloas.DataColumnSidecar]
    res3: seq[ColumnIndex]
  let blockRoot = createDigest(int(slot))
  for index in map:
    let sidecar = createGloasDataColumnSidecar(slot, index, blockRoot)
    if res1.block_root.isZero():
      res1.block_root = blockRoot
    res3.add(sidecar[].index)
    res2.add(sidecar)
  res1.indices = List[ColumnIndex, Limit(NUMBER_OF_COLUMNS)](res3)
  (res1, res2)

func createFuluDataColumnSidecarList(
    sslice: Slice[Slot],
    map: ColumnMap
): seq[ref fulu.DataColumnSidecar] =
  var res: seq[ref fulu.DataColumnSidecar]
  for slot in sslice:
    for index in map:
      res.add(createFuluDataColumnSidecar(slot, index))
  res

func createGloasDataColumnSidecarList(
    sslice: Slice[Slot],
    map: ColumnMap
): seq[ref gloas.DataColumnSidecar] =
  var res: seq[ref gloas.DataColumnSidecar]
  for slot in sslice:
    for index in map:
      res.add(createGloasDataColumnSidecar(
        slot, index, createDigest(int(slot))))
  res

func createFuluBlock(
    slot: Slot,
    root: Eth2Digest,
    parentRoot: Eth2Digest,
    commitmentsLength: int
): ref ForkedSignedBeaconBlock =
  newClone ForkedSignedBeaconBlock(
    kind: ConsensusFork.Fulu,
    fuluData: fulu.SignedBeaconBlock(
      message: fulu.BeaconBlock(
        slot: slot,
        parent_root: parentRoot,
        body: fulu.BeaconBlockBody(
          blob_kzg_commitments: genDenebKzgCommitments(commitmentsLength))),
      root: root))

func createGloasBlock(
    slot: Slot,
    root: Eth2Digest,
    parentRoot: Eth2Digest,
    commitmentsLength: int
): ref ForkedSignedBeaconBlock =
  newClone ForkedSignedBeaconBlock(
    kind: ConsensusFork.Gloas,
    gloasData: gloas.SignedBeaconBlock(
      message: gloas.BeaconBlock(
        slot: slot,
        parent_root: parentRoot,
        body: gloas.BeaconBlockBody(
          signed_execution_payload_bid: gloas.SignedExecutionPayloadBid(
            message: gloas.ExecutionPayloadBid(
              blob_kzg_commitments: genGloasKzgCommitments(commitmentsLength))))),
      root: root))

func createGloasEnvelope(
    slot: Slot,
    root: Eth2Digest,
    parentRoot: Eth2Digest
): ref gloas.SignedExecutionPayloadEnvelope =
  newClone gloas.SignedExecutionPayloadEnvelope(
    message: gloas.ExecutionPayloadEnvelope(
      beacon_block_root: root,
      parent_beacon_block_root: parentRoot,
      payload: gloas.ExecutionPayload(slot_number: slot)))

func createFuluItem(
    slot: Slot,
    root: Eth2Digest,
    parentRoot: Eth2Digest,
    commitmentsLength: int,
): SyncResponseItem =
  SyncResponseItem.init(
    createFuluBlock(slot, root, parentRoot, commitmentsLength))

func createGloasItem(
    slot: Slot,
    root: Eth2Digest,
    parentRoot: Eth2Digest,
    commitmentsLength: int,
    env: int
): SyncResponseItem =
  let
    blck = createGloasBlock(slot, root, parentRoot, commitmentsLength)
    envelope =
      if env == 0:
        nil
      else:
        createGloasEnvelope(slot, root, parentRoot)
  SyncResponseItem.init(blck, envelope)

func createGloasItemChain(
    items: openArray[GloasBlockChainResultItem]
): seq[SyncResponseItem] =
  var res: seq[SyncResponseItem]
  for item in items:
    let
      blockRoot = createDigest(item.root)
      blockParentRoot = createDigest(item.parentRoot)
    res.add(
      createGloasItem(
        Slot(item.slot), blockRoot, blockParentRoot, item.commitments,
        item.env))
  res

func createForkedBlock(
    fork: ConsensusFork,
    slot: Slot,
    root: Eth2Digest,
    parentRoot: Eth2Digest
): ref ForkedSignedBeaconBlock =
  withConsensusFork(fork):
    newClone ForkedSignedBeaconBlock.init(
      SignedBeaconBlock(consensusFork)(
        message: BeaconBlock(consensusFork)(
          slot: slot, parent_root: parentRoot),
        root: root))

func createGloasBlockChain(
    items: openArray[GloasBlockChainItem]
): seq[ref ForkedSignedBeaconBlock] =
  var res: seq[ref ForkedSignedBeaconBlock]
  for item in items:
    let
      blockRoot = createDigest(item.root)
      blockParentRoot = createDigest(item.parentRoot)

    if item.fork == ConsensusFork.Gloas:
      res.add(createGloasBlock(
        Slot(item.slot), blockRoot, blockParentRoot, item.commitments))
    else:
      res.add(createForkedBlock(
        item.fork, Slot(item.slot), blockRoot, blockParentRoot))
  res

func createGloasEnvelopeChain(
    items: openArray[GloasEnvelopeChainItem]
): seq[ref gloas.SignedExecutionPayloadEnvelope] =
  var res: seq[ref gloas.SignedExecutionPayloadEnvelope]
  for item in items:
    let
      blockRoot = createDigest(item.root)
      blockParentRoot = createDigest(item.parentRoot)
    res.add(createGloasEnvelope(Slot(item.slot), blockRoot, blockParentRoot))
  res

func createBlockChain(
    slots: openArray[Slot]
): seq[ref ForkedSignedBeaconBlock] =
  var
    res: seq[ref ForkedSignedBeaconBlock]
    root = 0

  for slot in slots:
    let item = newClone ForkedSignedBeaconBlock(kind: ConsensusFork.Fulu)
    item[].fuluData.message.slot = slot
    if root == 0:
      item[].fuluData.root = createDigest(1)
      item[].fuluData.message.parent_root = createDigest(0)
      inc(root)
    else:
      let prev_root = root
      inc(root)
      item[].fuluData.root = createDigest(root)
      item[].fuluData.message.parent_root = createDigest(prev_root)
    res.add(item)
  res

func compareBlock(a, b: ref ForkedSignedBeaconBlock): bool =
  if isNil(a) and isNil(b):
    return true
  if isNil(a) and not(isNil(b)) or (isNil(b) and not(isNil(a))):
    return false
  let
    abid = a[].toBlockHid()
    bbid = b[].toBlockHid()
  if a[].kind != b[].kind:
    return false
  if abid.slot != bbid.slot:
    return false
  if abid.root != bbid.root:
    return false
  true

func compareEnvelope(a, b: ref gloas.SignedExecutionPayloadEnvelope): bool =
  if isNil(a) and isNil(b):
    return true
  if isNil(a) and not(isNil(b)) or (isNil(b) and not(isNil(a))):
    return false
  let
    abid = a[].toEnvelopeHid()
    bbid = b[].toEnvelopeHid()
  if abid.slot != bbid.slot:
    return false
  if abid.root != bbid.root:
    return false
  true

func compareResponseItem(a, b: openArray[SyncResponseItem]): bool =
  if len(a) != len(b):
    return false
  if len(a) == 0:
    return true
  for index, value in a.pairs():
    if not(compareBlock(value.signedBlock, b[index].signedBlock)):
      return false
    if not(compareEnvelope(value.signedEnvelope, b[index].signedEnvelope)):
      return false
  true

suite "Response utilities test suite":

  test "checkResponse(SyncRange, ForkedSignedBeaconBlock) test":
    let
      r1 = SyncRange.init(Slot(11), 1'u64)
      r2 = SyncRange.init(Slot(11), 2'u64)
      r3 = SyncRange.init(Slot(11), 3'u64)
      r4 = SyncRange.init(Slot(11), 4'u64)
      fork = ConsensusFork.Fulu

    check:
      checkResponse(r1, fork,
        createBlockChain([Slot(11)])).isOk() == true
      checkResponse(r1, fork,
        createBlockChain(@[])).isOk() == true
      checkResponse(r1, fork,
        createBlockChain(@[Slot(11), Slot(11)])).isOk() == false
      checkResponse(r1, fork,
        createBlockChain([Slot(10)])).isOk() == false
      checkResponse(r1, fork,
        createBlockChain([Slot(12)])).isOk() == false

      checkResponse(r2, fork,
        createBlockChain([Slot(11)])).isOk() == true
      checkResponse(r2, fork,
        createBlockChain([Slot(12)])).isOk() == true
      checkResponse(r2, fork,
        createBlockChain(@[])).isOk() == true
      checkResponse(r2, fork,
        createBlockChain([Slot(11), Slot(12)])).isOk() == true
      checkResponse(r2, fork,
        createBlockChain([Slot(12)])).isOk() == true
      checkResponse(r2, fork,
        createBlockChain([Slot(11), Slot(12), Slot(13)])).isOk() == false
      checkResponse(r2, fork,
        createBlockChain([Slot(10), Slot(11)])).isOk() == false
      checkResponse(r2, fork,
        createBlockChain([Slot(10)])).isOk() == false
      checkResponse(r2, fork,
        createBlockChain([Slot(12), Slot(11)])).isOk() == false
      checkResponse(r2, fork,
        createBlockChain([Slot(12), Slot(13)])).isOk() == false
      checkResponse(r2, fork,
        createBlockChain([Slot(13)])).isOk() == false

      checkResponse(r2, fork,
        createBlockChain([Slot(11), Slot(11)])).isOk() == false
      checkResponse(r2, fork,
        createBlockChain([Slot(12), Slot(12)])).isOk() == false

      checkResponse(r3, fork,
        createBlockChain(@[Slot(11)])).isOk() == true
      checkResponse(r3, fork,
        createBlockChain(@[Slot(12)])).isOk() == true
      checkResponse(r3, fork,
        createBlockChain(@[Slot(13)])).isOk() == true
      checkResponse(r3, fork,
        createBlockChain(@[Slot(11), Slot(12)])).isOk() == true
      checkResponse(r3, fork,
        createBlockChain(@[Slot(11), Slot(13)])).isOk() == true
      checkResponse(r3, fork,
        createBlockChain(@[Slot(12), Slot(13)])).isOk() == true
      checkResponse(r3, fork,
        createBlockChain(@[Slot(11), Slot(13), Slot(12)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(12), Slot(13), Slot(11)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(13), Slot(12), Slot(11)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(13), Slot(11)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(13), Slot(12)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(12), Slot(11)])).isOk() == false

      checkResponse(r3, fork,
        createBlockChain(@[Slot(11), Slot(11), Slot(11)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(11), Slot(12), Slot(12)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(11), Slot(13), Slot(13)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(12), Slot(13), Slot(13)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(12), Slot(12), Slot(12)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(13), Slot(13), Slot(13)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(11), Slot(11)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(12), Slot(12)])).isOk() == false
      checkResponse(r3, fork,
        createBlockChain(@[Slot(13), Slot(13)])).isOk() == false

    var
      chain1 = createBlockChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])
      chain2 = createBlockChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])
      chain3 = createBlockChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])
      chain4 = createBlockChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])

    withBlck(chain2[1][]):
      forkyBlck.message.parent_root = Eth2Digest()
    withBlck(chain3[2][]):
      forkyBlck.message.parent_root = Eth2Digest()
    withBlck(chain4[3][]):
      forkyBlck.message.parent_root = Eth2Digest()

    check:
      checkResponse(r4, fork, chain1).isOk() == true
      checkResponse(r4, fork, chain2).isOk() == false
      checkResponse(r4, fork, chain3).isOk() == false
      checkResponse(r4, fork, chain4).isOk() == false

  const
    TestMaps = [ColumnMap.init([ColumnIndex(13), 51, 98, 110]), supernodeMap]

  for columnMap in TestMaps:
    let testName =
      if len(columnMap) == NUMBER_OF_COLUMNS:
        "[supernode]"
      else:
        "[node]"

    test "groupSidecars(SyncRange, ColumnMap, fulu.DataColumnSidecar) " & testName & " test":
      let chain =
        createFuluDataColumnSidecarList(Slot(99)..Slot(131), columnMap)

      block:
        let res = groupSidecars(
          SyncRange.init(Slot(100)..Slot(131)),
          columnMap, chain)
        check:
          res.isErr() == true
          res.error == "Invalid data column sidecar slot"

      if len(columnMap) != NUMBER_OF_COLUMNS:
        let tmp = chain[0].index
        defer:
          chain[0].index = tmp

        chain[0].index = ColumnIndex(127)

        let res = groupSidecars(
          SyncRange.init(Slot(99)..Slot(131)),
          columnMap, chain)
        check:
          res.isErr() == true
          res.error == "Invalid data column index"

      block:
        let res = groupSidecars(
          SyncRange.init(Slot(99)..Slot(131)),
          columnMap, chain)
        check:
          res.isErr() == true
          res.error == "DataColumnSidecar: Inclusion proof is invalid"

    test "groupSidecars(SyncRange, ColumnMap, gloas.DataColumnSidecar) " & testName & " test":
      let chain =
        createGloasDataColumnSidecarList(Slot(99)..Slot(131), columnMap)

      block:
        let res = groupSidecars(
          SyncRange.init(Slot(100)..Slot(131)),
          columnMap, chain)
        check:
          res.isErr() == true
          res.error == "Invalid data column sidecar slot"

      if len(columnMap) != NUMBER_OF_COLUMNS:
        let tmp = chain[0].index
        defer:
          chain[0].index = tmp

        chain[0].index = ColumnIndex(127)

        let res = groupSidecars(
          SyncRange.init(Slot(99)..Slot(131)),
          columnMap, chain)
        check:
          res.isErr() == true
          res.error == "Invalid data column index"

      block:
        let tmp = chain[0].index
        chain[0][].index = chain[1][].index
        chain[1][].index = tmp

        defer:
          chain[1][].index = chain[0][].index
          chain[0][].index = tmp

        let res = groupSidecars(
          SyncRange.init(Slot(99)..Slot(131)),
          columnMap, chain)
        check:
          res.isErr() == true
          res.error == "Invalid order or duplicate data column sidecars found"

      block:
        let res = groupSidecars(
          SyncRange.init(Slot(99)..Slot(131)),
          columnMap, chain)
        check:
          res.isOk() == true

    test "groupSidecars(DataColumnsByRootIdentifier, fulu.DataColumnSidecar) " & testName & " test":
      let
        s0 = createFuluDataColumnsByRootIdentifier(Slot(100), columnMap)
        s1 = createFuluDataColumnsByRootIdentifier(Slot(101), columnMap)
        s2 = createFuluDataColumnsByRootIdentifier(Slot(102), columnMap)

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s0.list.asSeq() & s1.list.asSeq() & s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars) - 1, sidecars)
        check:
          res.isErr() == true
          res.error == "Number of data columns received is greater than number of requested"

      block:
        let
          idents = [s0.ident, s1.ident]
          sidecars = s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check:
          res.isErr() == true
          res.error == "Received data column outside the request"

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s0.list.asSeq() & s1.list.asSeq() & s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check:
          res.isErr() == true
          res.error == "DataColumnSidecar: Inclusion proof is invalid"

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s1.list.asSeq() & s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check:
          res.isErr() == true
          res.error == "DataColumnSidecar: Inclusion proof is invalid"

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check:
          res.isErr() == true
          res.error == "DataColumnSidecar: Inclusion proof is invalid"

    test "groupSidecars(DataColumnsByRootIdentifier, gloas.DataColumnSidecar) " & testName & " test":
      let
        s0 = createGloasDataColumnsByRootIdentifier(Slot(100), columnMap)
        s1 = createGloasDataColumnsByRootIdentifier(Slot(101), columnMap)
        s2 = createGloasDataColumnsByRootIdentifier(Slot(102), columnMap)

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s0.list.asSeq() & s1.list.asSeq() & s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars) - 1, sidecars)
        check:
          res.isErr() == true
          res.error == "Number of data columns received is greater than number of requested"

      block:
        let
          idents = [s0.ident, s1.ident]
          sidecars = s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check:
          res.isErr() == true
          res.error == "Received data column outside the request"

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s0.list.asSeq() & s1.list.asSeq() & s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check res.isOk() == true

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s0.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check res.isOk() == true

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s1.list.asSeq() & s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check res.isOk() == true

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s1.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check res.isOk() == true

      block:
        let
          idents = [s0.ident, s1.ident, s2.ident]
          sidecars = s2.list.asSeq()
          res = groupSidecars(idents, len(sidecars), sidecars)
        check res.isOk() == true

    test "validateBlocks(SyncRange, SyncResponseItem, FuluColumnSidecarResponseRecord) " & testName & " test":
      let
        i1 = createFuluItem(Slot(100), createDigest(100), createDigest(0), 5)
        i2 = createFuluItem(Slot(101), createDigest(101), createDigest(100), 5)
        i3 = createFuluItem(Slot(102), createDigest(102), createDigest(101), 0)
        i4 = createFuluItem(Slot(103), createDigest(103), createDigest(102), 5)
        c1 = createFuluColumnSidecarResponseRecordList(Slot(100), createDigest(100), columnMap)
        c2 = createFuluColumnSidecarResponseRecordList(Slot(101), createDigest(101), columnMap)
        c3 = createFuluColumnSidecarResponseRecordList(Slot(102), createDigest(102), columnMap)
        c4 = createFuluColumnSidecarResponseRecordList(Slot(103), createDigest(103), columnMap)

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i3, i4], c1 & c2 & c4)
        check res.isOk() == true

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i3, i4], c1 & c2 & c3 & c4)
        check res.isOk() == true

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i2, i3, i4], c1 & c2 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Blocks

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i3, i4], c1 & c2 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Blocks

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i4], c2 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Sidecars

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i4], c1 & c2)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Sidecars

    test "validateBlocks(SyncRange, SyncResponseItem, GloasColumnSidecarResponseRecord) " & testName & " test":
      let
        i1 = createGloasItem(Slot(100), createDigest(100), createDigest(0), 5, 1)
        i2 = createGloasItem(Slot(101), createDigest(101), createDigest(100), 5, 1)
        i3 = createGloasItem(Slot(102), createDigest(102), createDigest(101), 0, 0)
        i4 = createGloasItem(Slot(103), createDigest(103), createDigest(102), 5, 1)
        i5 = createGloasItem(Slot(104), createDigest(104), createDigest(103), 5, 0)
        c1 = createGloasColumnSidecarResponseRecordList(Slot(100), createDigest(100), columnMap)
        c2 = createGloasColumnSidecarResponseRecordList(Slot(101), createDigest(101), columnMap)
        c3 = createGloasColumnSidecarResponseRecordList(Slot(102), createDigest(102), columnMap)
        c4 = createGloasColumnSidecarResponseRecordList(Slot(103), createDigest(103), columnMap)

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i3, i4], c1 & c2 & c4)
        check res.isOk() == true

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i3, i4], c1 & c2 & c3 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Envelopes

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i2, i3, i4], c1 & c2 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Blocks

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i3, i4], c1 & c2 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Blocks

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i4], c2 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Sidecars

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i1, i2, i4], c1 & c2)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Sidecars

      block:
        let res = validateBlocks(
          SyncRange.init(Slot(102)..Slot(104)), [i3, i4, i5], c4)
        check:
          res.isOk() == true

      block:
        var i5 = i1
        i5.signedEnvelope = nil
        let res = validateBlocks(
          SyncRange.init(Slot(100)..Slot(103)), [i5, i2, i3, i4], c1 & c2 & c4)
        check:
          res.isErr() == true
          res.error == MissingErrorKind.Envelopes

  test "checkResponse(SyncRange, ForkedSignedBeaconBlock) failures test":
    let
      b1 = createGloasBlock(Slot(100), createDigest(100), createDigest(99), 1)
      b2 = createGloasBlock(Slot(101), createDigest(101), createDigest(100), 2)
      b3 = createGloasBlock(Slot(102), createDigest(102), createDigest(101), 3)
      b4 = createGloasBlock(Slot(103), createDigest(103), createDigest(102), 4)
      b5 = createGloasBlock(Slot(104), createDigest(104), createDigest(103), 5)

    check:
      checkResponse(
        SyncRange.init(Slot(100)..Slot(104)),
        ConsensusFork.Gloas,
        default(seq[ref ForkedSignedBeaconBlock])).isOk() == true
      checkResponse(
        SyncRange.init(Slot(100)..Slot(104)),
        ConsensusFork.Gloas,
        [b1, b2, b3, b4, b5]).isOk() == true

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, ConsensusFork.Gloas,
          [b1, b2, b3, b4, b5])
      check:
        res.isErr() == true
        res.error == "Number of received blocks greater than number of requested"

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(100))
        res = checkResponse(srange, ConsensusFork.Fulu, [b1])
      check:
        res.isErr() == true
        res.error == "Some of the blocks from incorrect fork"

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, ConsensusFork.Gloas, [b1, b2, b3, b5])
      check:
        res.isErr() == true
        res.error == "Some of the blocks are outside the requested range"

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, ConsensusFork.Gloas, [b1, b2, b2, b4])
      check:
        res.isErr() == true
        res.error == "Incorrect order or duplicate blocks found"

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, ConsensusFork.Gloas, [b1, b3, b2, b4])
      check:
        res.isErr() == true
        res.error == "Incorrect order or chain of blocks, invalid parent_root"

  test "checkResponse(SyncRange, SignedExecutionPayloadEnvelope) test":
    let
      e1 = createGloasEnvelope(Slot(100), createDigest(100), createDigest(99))
      e2 = createGloasEnvelope(Slot(101), createDigest(101), createDigest(100))
      e3 = createGloasEnvelope(Slot(102), createDigest(102), createDigest(101))
      e4 = createGloasEnvelope(Slot(103), createDigest(103), createDigest(102))
      e5 = createGloasEnvelope(Slot(104), createDigest(104), createDigest(103))

    block:
      check:
        checkResponse(
          SyncRange.init(Slot(100)..Slot(104)),
          default(seq[ref SignedExecutionPayloadEnvelope])).isOk() == true
        checkResponse(
          SyncRange.init(Slot(100)..Slot(104)),
          [e1, e2, e3, e4, e5]).isOk() == true

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, [e1, e2, e3, e4, e5])
      check:
        res.isErr() == true
        res.error == "Number of received envelopes greater than number of requested"

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, [e1, e2, e3, e5])
      check:
        res.isErr() == true
        res.error == "Some of the envelopes are outside the requested range"

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, [e1, e2, e2, e4])
      check:
        res.isErr() == true
        res.error == "Incorrect order or duplicate envelopes found"

    block:
      let
        srange = SyncRange.init(Slot(100)..Slot(103))
        res = checkResponse(srange, [e1, e3, e2, e4])
      check:
        res.isErr() == true
        res.error == "Incorrect order or duplicate envelopes found"

  test "checkResponse(roots, ForkedSignedBeaconBlock) test":
    let
      b1 = createGloasBlock(Slot(100), createDigest(100), createDigest(99), 0)
      b2 = createGloasBlock(Slot(101), createDigest(101), createDigest(100), 0)
      b3 = createGloasBlock(Slot(102), createDigest(102), createDigest(101), 0)
      b4 = createGloasBlock(Slot(103), createDigest(103), createDigest(102), 0)
      b5 = createGloasBlock(Slot(104), createDigest(104), createDigest(103), 0)

    block:
      let roots = [
        createDigest(100), createDigest(101), createDigest(102),
        createDigest(103), createDigest(104)
      ]
      check:
        checkResponse(roots, [b1, b2, b3, b4, b5]).isOk()
        checkResponse(roots, [b2, b1, b5, b3, b4]).isOk()
        checkResponse(roots, [b1]).isOk()
        checkResponse(roots, [b3]).isOk()
        checkResponse(roots, [b5]).isOk()
        checkResponse(roots, default(seq[ref ForkedSignedBeaconBlock])).isOk()

    block:
      let roots = [
        createDigest(100), createDigest(101), createDigest(102),
        createDigest(103)
      ]
      check:
        checkResponse(roots, [b1, b2, b3, b4]).isOk()
      let res1 = checkResponse(roots, [b1, b2, b3, b4, b5])
      check:
        res1.isErr() == true
        res1.error == "Number of received blocks greater than number of requested"
      let res2 = checkResponse(roots, [b2, b3, b4, b5])
      check:
        res2.isErr() == true
        res2.error == "Unexpected block root encountered"
      let res3 = checkResponse(roots, [b2, b2, b3, b3])
      check:
        res3.isErr() == true
        res3.error == "Unexpected block root encountered"

  test "checkResponse(roots, SignedExecutionPayloadEnvelope) test":
    let
      e1 = createGloasEnvelope(Slot(100), createDigest(100), createDigest(99))
      e2 = createGloasEnvelope(Slot(101), createDigest(101), createDigest(100))
      e3 = createGloasEnvelope(Slot(102), createDigest(102), createDigest(101))
      e4 = createGloasEnvelope(Slot(103), createDigest(103), createDigest(102))
      e5 = createGloasEnvelope(Slot(104), createDigest(104), createDigest(103))

    block:
      let roots = [
        createDigest(100), createDigest(101), createDigest(102),
        createDigest(103), createDigest(104)
      ]
      check:
        checkResponse(roots, [e1, e2, e3, e4, e5]).isOk()
        checkResponse(roots, [e2, e1, e5, e3, e4]).isOk()
        checkResponse(roots, [e1]).isOk()
        checkResponse(roots, [e3]).isOk()
        checkResponse(roots, [e5]).isOk()
        checkResponse(roots, default(seq[ref SignedExecutionPayloadEnvelope])).isOk()

    block:
      let roots = [
        createDigest(100), createDigest(101), createDigest(102),
        createDigest(103)
      ]
      check:
        checkResponse(roots, [e1, e2, e3, e4]).isOk()
      let res1 = checkResponse(roots, [e1, e2, e3, e4, e5])
      check:
        res1.isErr() == true
        res1.error == "Number of received envelopes greater than number of requested"
      let res2 = checkResponse(roots, [e2, e3, e4, e5])
      check:
        res2.isErr() == true
        res2.error == "Unexpected beacon block root encountered"
      let res3 = checkResponse(roots, [e2, e2, e3, e3])
      check:
        res3.isErr() == true
        res3.error == "Unexpected beacon block root encountered"

  test "combineResponse() test":
    let TestVectors = [
      (
        Slot(31)..Slot(36),
        default(seq[GloasBlockChainItem]),
        default(seq[GloasEnvelopeChainItem]),
         Result[seq[GloasBlockChainResultItem], string].ok(default(seq[GloasBlockChainResultItem]))
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 31, 31, 0, 0),
          (ConsensusFork.Gloas, 32, 32, 31, 0),
          (ConsensusFork.Gloas, 33, 33, 32, 0)
        ],
        @[(31, 31, 0), (32, 32, 31), (36, 36, 32)],
         Result[seq[GloasBlockChainResultItem], string].err("Some blocks are missing in range")
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 32, 32, 31, 0),
          (ConsensusFork.Gloas, 33, 33, 32, 0)
        ],
        @[(31, 31, 0), (32, 32, 31), (36, 36, 32)],
         Result[seq[GloasBlockChainResultItem], string].err("Some blocks are missing in range")
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 31, 31, 0, 0),
          (ConsensusFork.Gloas, 33, 33, 32, 0)
        ],
        @[(31, 31, 0), (32, 32, 31), (36, 36, 32)],
         Result[seq[GloasBlockChainResultItem], string].err("Some blocks are missing in range")
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 31, 31, 0, 0),
          (ConsensusFork.Fulu, 32, 32, 31, 1)
        ],
        @[(31, 31, 0), (32, 32, 31)],
         Result[seq[GloasBlockChainResultItem], string].err("Received block from incorrect fork")
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 31, 31, 0, 0),
          (ConsensusFork.Gloas, 32, 32, 31, 1)
        ],
        @[(31, 31, 0), (32, 33, 31)],
         Result[seq[GloasBlockChainResultItem], string].err("The root of the block and the root of the envelope do not match")
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 31, 31, 0, 0),
          (ConsensusFork.Gloas, 32, 32, 31, 1)
        ],
        @[(31, 31, 0), (32, 32, 30)],
         Result[seq[GloasBlockChainResultItem], string].err("The parent root of the envelope and the root of the parent envelope do not match")
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 33, 33, 0, 0),
          (ConsensusFork.Gloas, 34, 34, 33, 0)
        ],
        @[(33, 33, 0), (34, 34, 33)],
         Result[seq[GloasBlockChainResultItem], string].ok(
          @[
            (ConsensusFork.Gloas, 33, 33, 0, 0, 1),
            (ConsensusFork.Gloas, 34, 34, 33, 0, 1)
          ])
      ),
      (
        Slot(31)..Slot(36),
        @[
          (ConsensusFork.Gloas, 31, 31, 0, 1),
          (ConsensusFork.Gloas, 32, 32, 31, 0),
          (ConsensusFork.Gloas, 33, 33, 32, 0),
          (ConsensusFork.Gloas, 34, 34, 33, 1),
          (ConsensusFork.Gloas, 35, 35, 34, 0),
          (ConsensusFork.Gloas, 36, 36, 35, 0)
        ],
        @[(31, 31, 0), (34, 34, 33)],
         Result[seq[GloasBlockChainResultItem], string].ok(
          @[
            (ConsensusFork.Gloas, 31, 31, 0, 1, 1),
            (ConsensusFork.Gloas, 32, 32, 31, 0, 0),
            (ConsensusFork.Gloas, 33, 33, 32, 0, 0),
            (ConsensusFork.Gloas, 34, 34, 33, 1, 1),
            (ConsensusFork.Gloas, 35, 35, 34, 0, 0),
            (ConsensusFork.Gloas, 36, 36, 35, 0, 0)
          ])
      ),

    ]

    for vector in TestVectors:
      let res = combineResponse(
        SyncRange.init(vector[0]),
        createGloasBlockChain(vector[1]),
        createGloasEnvelopeChain(vector[2]))
      if res.isOk():
        check vector[3].isOk()
        let chain = createGloasItemChain(vector[3].get())
        check compareResponseItem(chain, res.get())
      else:
        check:
          vector[3].isErr()
          vector[3].error == res.error
