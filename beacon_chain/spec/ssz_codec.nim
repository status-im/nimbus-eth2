import
  std/[typetraits],
  ssz_serialization/codec,
  ./datatypes/base

export codec, base, typetraits

template toSszType*(v: Slot|Epoch|SyncCommitteePeriod): auto = uint64(v)
template toSszType*(v: BlsCurveType): auto = toRaw(v)
template toSszType*(v: Version): auto = distinctBase(v)

func fromSszBytes*(
    T: type GraffitiBytes, data: openArray[byte]): T {.raises: [SszError].} =
  if data.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr data[0], sizeof(result))

template fromSszBytes*(T: type Slot, bytes: openArray[byte]): T =
  T fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type Epoch, bytes: openArray[byte]): T =
  T fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type SyncCommitteePeriod, bytes: openArray[byte]): T =
  T fromSszBytes(uint64, bytes)

func fromSszBytes*(
    T: type Version, bytes: openArray[byte]): T {.raises: [SszError].} =
  if bytes.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr bytes[0], sizeof(result))

template toSszType*(v: HashedValidatorPubKey): auto = toRaw(v.pubkey)
