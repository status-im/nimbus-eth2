# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.pragma: raisesssz, raises: [Defect, MalformedSszError, SszSizeMismatchError].}

import
  std/[typetraits],
  ssz_serialization/codec,
  ./datatypes/base

from ./datatypes/altair import
  ParticipationFlags, EpochParticipationFlags

export codec, base, typetraits, EpochParticipationFlags

# Coding and decoding of SSZ to spec-specific types

template toSszType*(v: Slot|Epoch|SyncCommitteePeriod): auto = uint64(v)
template toSszType*(v: BlsCurveType): auto = toRaw(v)
template toSszType*(v: ForkDigest|GraffitiBytes): auto = distinctBase(v)
template toSszType*(v: Version): auto = distinctBase(v)
template toSszType*(v: JustificationBits): auto = distinctBase(v)
template toSszType*(v: EpochParticipationFlags): auto = asList v

func fromSszBytes*(T: type GraffitiBytes, data: openArray[byte]): T {.raisesssz.} =
  if data.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr data[0], sizeof(result))

template fromSszBytes*(T: type Slot, bytes: openArray[byte]): T =
  T fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type Epoch, bytes: openArray[byte]): T =
  T fromSszBytes(uint64, bytes)

template fromSszBytes*(T: type SyncCommitteePeriod, bytes: openArray[byte]): T =
  T fromSszBytes(uint64, bytes)

func fromSszBytes*(T: type ForkDigest, bytes: openArray[byte]): T {.raisesssz.} =
  if bytes.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr bytes[0], sizeof(result))

func fromSszBytes*(T: type Version, bytes: openArray[byte]): T {.raisesssz.} =
  if bytes.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr bytes[0], sizeof(result))

func fromSszBytes*(T: type JustificationBits, bytes: openArray[byte]): T {.raisesssz.} =
  if bytes.len != sizeof(result):
    raiseIncorrectSize T
  copyMem(result.addr, unsafeAddr bytes[0], sizeof(result))

func fromSszBytes*(T: type EpochParticipationFlags, bytes: openArray[byte]): T {.raisesssz.} =
  # TODO https://github.com/nim-lang/Nim/issues/21123
  let tmp = cast[ptr List[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT]](addr result)
  readSszValue(bytes, tmp[])
