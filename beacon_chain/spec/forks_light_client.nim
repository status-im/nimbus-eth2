# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  ./datatypes/[phase0, altair, bellatrix, capella, eip4844]

type
  LightClientDataFork* {.pure.} = enum  # Append only, used in DB data!
    None = 0,  # only use non-0 in DB to detect accidentally uninitialized data
    Altair = 1

  ForkyLightClientHeader* =
    altair.LightClientHeader

  ForkyLightClientBootstrap* =
    altair.LightClientBootstrap

  ForkyLightClientUpdate* =
    altair.LightClientUpdate

  ForkyLightClientFinalityUpdate* =
    altair.LightClientFinalityUpdate

  ForkyLightClientOptimisticUpdate* =
    altair.LightClientOptimisticUpdate

  SomeForkyLightClientUpdateWithSyncCommittee* =
    ForkyLightClientUpdate

  SomeForkyLightClientUpdateWithFinality* =
    ForkyLightClientUpdate |
    ForkyLightClientFinalityUpdate

  SomeForkyLightClientUpdate* =
    ForkyLightClientUpdate |
    ForkyLightClientFinalityUpdate |
    ForkyLightClientOptimisticUpdate

  SomeForkyLightClientObject* =
    ForkyLightClientBootstrap |
    SomeForkyLightClientUpdate

  ForkyLightClientStore* =
    altair.LightClientStore

  ForkedLightClientHeader* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientHeader

  ForkedLightClientBootstrap* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientBootstrap

  ForkedLightClientUpdate* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientUpdate

  ForkedLightClientFinalityUpdate* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientFinalityUpdate

  ForkedLightClientOptimisticUpdate* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientOptimisticUpdate

  SomeForkedLightClientUpdateWithSyncCommittee* =
    ForkedLightClientUpdate

  SomeForkedLightClientUpdateWithFinality* =
    ForkedLightClientUpdate |
    ForkedLightClientFinalityUpdate

  SomeForkedLightClientUpdate* =
    ForkedLightClientUpdate |
    ForkedLightClientFinalityUpdate |
    ForkedLightClientOptimisticUpdate

  SomeForkedLightClientObject* =
    ForkedLightClientBootstrap |
    SomeForkedLightClientUpdate

  ForkedLightClientStore* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientStore

func lcDataForkAtEpoch*(
    cfg: RuntimeConfig, epoch: Epoch): LightClientDataFork =
  static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
  if epoch >= cfg.ALTAIR_FORK_EPOCH:
    LightClientDataFork.Altair
  else:
    LightClientDataFork.None

template kind*(
    x: typedesc[ # `SomeLightClientObject` doesn't work here (Nim 1.6)
      altair.LightClientHeader |
      altair.LightClientBootstrap |
      altair.LightClientUpdate |
      altair.LightClientFinalityUpdate |
      altair.LightClientOptimisticUpdate |
      altair.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Altair

template LightClientHeader*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientHeader]
  else:
    static: raiseAssert "Unreachable"

template LightClientBootstrap*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientBootstrap]
  else:
    static: raiseAssert "Unreachable"

template LightClientUpdate*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientUpdate]
  else:
    static: raiseAssert "Unreachable"

template LightClientFinalityUpdate*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientFinalityUpdate]
  else:
    static: raiseAssert "Unreachable"

template LightClientOptimisticUpdate*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientOptimisticUpdate]
  else:
    static: raiseAssert "Unreachable"

template LightClientStore*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientStore]
  else:
    static: raiseAssert "Unreachable"

template Forky*(
    x: typedesc[ForkedLightClientHeader],
    kind: static LightClientDataFork): auto =
  kind.LightClientHeader

template Forky*(
    x: typedesc[ForkedLightClientBootstrap],
    kind: static LightClientDataFork): auto =
  kind.LightClientBootstrap

template Forky*(
    x: typedesc[ForkedLightClientUpdate],
    kind: static LightClientDataFork): auto =
  kind.LightClientUpdate

template Forky*(
    x: typedesc[ForkedLightClientFinalityUpdate],
    kind: static LightClientDataFork): auto =
  kind.LightClientFinalityUpdate

template Forky*(
    x: typedesc[ForkedLightClientOptimisticUpdate],
    kind: static LightClientDataFork): auto =
  kind.LightClientOptimisticUpdate

template Forky*(
    x: typedesc[ForkedLightClientStore],
    kind: static LightClientDataFork): auto =
  kind.LightClientStore

template Forked*(x: typedesc[ForkyLightClientHeader]): auto =
  typedesc[ForkedLightClientHeader]

template Forked*(x: typedesc[ForkyLightClientBootstrap]): auto =
  typedesc[ForkedLightClientBootstrap]

template Forked*(x: typedesc[ForkyLightClientUpdate]): auto =
  typedesc[ForkedLightClientUpdate]

template Forked*(x: typedesc[ForkyLightClientFinalityUpdate]): auto =
  typedesc[ForkedLightClientFinalityUpdate]

template Forked*(x: typedesc[ForkyLightClientOptimisticUpdate]): auto =
  typedesc[ForkedLightClientOptimisticUpdate]

template Forked*(x: typedesc[ForkyLightClientStore]): auto =
  typedesc[ForkedLightClientStore]

template withAll*(
    x: typedesc[LightClientDataFork], body: untyped): untyped =
  static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    body
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withLcDataFork*(
    x: LightClientDataFork, body: untyped): untyped =
  case x
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyHeader*(
    x: ForkedLightClientHeader, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyHeader: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyBootstrap*(
    x: ForkedLightClientBootstrap, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyBootstrap: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyUpdate*(
    x: ForkedLightClientUpdate, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyUpdate: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyFinalityUpdate*(
    x: ForkedLightClientFinalityUpdate, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyFinalityUpdate: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyOptimisticUpdate*(
    x: ForkedLightClientOptimisticUpdate, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyOptimisticUpdate: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyObject*(
    x: SomeForkedLightClientObject, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyObject: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyStore*(
    x: ForkedLightClientStore, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyStore: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template toFull*(
    update: SomeForkedLightClientUpdate): ForkedLightClientUpdate =
  when update is ForkyLightClientUpdate:
    update
  else:
    withForkyObject(update):
      when lcDataFork > LightClientDataFork.None:
        var res = ForkedLightClientUpdate(kind: lcDataFork)
        template forkyRes: untyped = res.forky(lcDataFork)
        forkyRes = forkyObject.toFull()
        res
      else:
        default(ForkedLightClientUpdate)

template toFinality*(
    update: SomeForkedLightClientUpdate): ForkedLightClientFinalityUpdate =
  when update is ForkyLightClientFinalityUpdate:
    update
  else:
    withForkyObject(update):
      when lcDataFork > LightClientDataFork.None:
        var res = ForkedLightClientFinalityUpdate(kind: lcDataFork)
        template forkyRes: untyped = res.forky(lcDataFork)
        forkyRes = forkyObject.toFinality()
        res
      else:
        default(ForkedLightClientFinalityUpdate)

template toOptimistic*(
    update: SomeForkedLightClientUpdate): ForkedLightClientOptimisticUpdate =
  when update is ForkyLightClientOptimisticUpdate:
    update
  else:
    withForkyObject(update):
      when lcDataFork > LightClientDataFork.None:
        var res = ForkedLightClientOptimisticUpdate(kind: lcDataFork)
        template forkyRes: untyped = res.forky(lcDataFork)
        forkyRes = forkyObject.toOptimistic()
        res
      else:
        default(ForkedLightClientOptimisticUpdate)

func matches*[A, B: SomeForkedLightClientUpdate](a: A, b: B): bool =
  if a.kind != b.kind:
    return false
  withForkyObject(a):
    when lcDataFork > LightClientDataFork.None:
      forkyObject.matches(b.forky(lcDataFork))
    else:
      true

template forky*(
    x:
      ForkedLightClientHeader |
      SomeForkedLightClientObject |
      ForkedLightClientStore,
    kind: static LightClientDataFork): untyped =
  when kind == LightClientDataFork.Altair:
    x.altairData
  else:
    static: raiseAssert "Unreachable"

func migrateToDataFork*(
    x: var ForkedLightClientHeader,
    newKind: static LightClientDataFork) =
  if newKind == x.kind:
    # Already at correct kind
    discard
  elif newKind < x.kind:
    # Downgrade not supported, re-initialize
    x = ForkedLightClientHeader(kind: newKind)
  else:
    # Upgrade to Altair
    when newKind >= LightClientDataFork.Altair:
      if x.kind == LightClientDataFork.None:
        x = ForkedLightClientHeader(
          kind: LightClientDataFork.Altair)

    static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientBootstrap,
    newKind: static LightClientDataFork) =
  if newKind == x.kind:
    # Already at correct kind
    discard
  elif newKind < x.kind:
    # Downgrade not supported, re-initialize
    x = ForkedLightClientBootstrap(kind: newKind)
  else:
    # Upgrade to Altair
    when newKind >= LightClientDataFork.Altair:
      if x.kind == LightClientDataFork.None:
        x = ForkedLightClientBootstrap(
          kind: LightClientDataFork.Altair)

    static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientUpdate,
    newKind: static LightClientDataFork) =
  if newKind == x.kind:
    # Already at correct kind
    discard
  elif newKind < x.kind:
    # Downgrade not supported, re-initialize
    x = ForkedLightClientUpdate(kind: newKind)
  else:
    # Upgrade to Altair
    when newKind >= LightClientDataFork.Altair:
      if x.kind == LightClientDataFork.None:
        x = ForkedLightClientUpdate(
          kind: LightClientDataFork.Altair)

    static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientFinalityUpdate,
    newKind: static LightClientDataFork) =
  if newKind == x.kind:
    # Already at correct kind
    discard
  elif newKind < x.kind:
    # Downgrade not supported, re-initialize
    x = ForkedLightClientFinalityUpdate(kind: newKind)
  else:
    # Upgrade to Altair
    when newKind >= LightClientDataFork.Altair:
      if x.kind == LightClientDataFork.None:
        x = ForkedLightClientFinalityUpdate(
          kind: LightClientDataFork.Altair)

    static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientOptimisticUpdate,
    newKind: static LightClientDataFork) =
  if newKind == x.kind:
    # Already at correct kind
    discard
  elif newKind < x.kind:
    # Downgrade not supported, re-initialize
    x = ForkedLightClientOptimisticUpdate(kind: newKind)
  else:
    # Upgrade to Altair
    when newKind >= LightClientDataFork.Altair:
      if x.kind == LightClientDataFork.None:
        x = ForkedLightClientOptimisticUpdate(
          kind: LightClientDataFork.Altair)

    static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientStore,
    newKind: static LightClientDataFork) =
  if newKind == x.kind:
    # Already at correct kind
    discard
  elif newKind < x.kind:
    # Downgrade not supported, re-initialize
    x = ForkedLightClientStore(kind: newKind)
  else:
    # Upgrade to Altair
    when newKind >= LightClientDataFork.Altair:
      if x.kind == LightClientDataFork.None:
        x = ForkedLightClientStore(
          kind: LightClientDataFork.Altair)

    static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
    doAssert x.kind == newKind

func migratingToDataFork*[
    T:
      ForkedLightClientHeader |
      SomeForkedLightClientObject |
      ForkedLightClientStore](
    x: T, newKind: static LightClientDataFork): T =
  var upgradedObject = x
  upgradedObject.migrateToDataFork(newKind)
  upgradedObject

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/altair/light-client/full-node.md#block_to_light_client_header
func toAltairLightClientHeader(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock |
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock |
      eip4844.SignedBeaconBlock | eip4844.TrustedSignedBeaconBlock
): altair.LightClientHeader =
  altair.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader())

func toLightClientHeader*(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock |
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock |
      eip4844.SignedBeaconBlock | eip4844.TrustedSignedBeaconBlock,
    kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Altair:
    blck.toAltairLightClientHeader()
  else:
    static: raiseAssert "Unreachable"
