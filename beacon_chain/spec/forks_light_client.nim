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
  ./datatypes/[phase0, altair]

type
  LightClientDataFork* {.pure.} = enum  # Append only, used in DB data!
    None = 0,  # only use non-0 in DB to detect accidentally uninitialized data
    Altair = 1

  ForkyLightClientHeader* =
    BeaconBlockHeader

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

  SomeForkedLightClientUpdate* =
    ForkedLightClientUpdate |
    ForkedLightClientFinalityUpdate |
    ForkedLightClientOptimisticUpdate

  SomeForkedLightClientObject* =
    ForkedLightClientBootstrap |
    SomeForkedLightClientUpdate

func lcDataForkAtEpoch*(
    cfg: RuntimeConfig, epoch: Epoch): LightClientDataFork =
  if epoch >= cfg.ALTAIR_FORK_EPOCH:
    LightClientDataFork.Altair
  else:
    LightClientDataFork.None

template kind*(x: typedesc[altair.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Altair

template header*(kind: static LightClientDataFork): auto =
  when kind >= LightClientDataFork.Altair:
    typedesc[BeaconBlockHeader]
  else:
    static: raiseAssert "Unreachable"

template forky*(
    x: typedesc[ForkedLightClientBootstrap],
    kind: static LightClientDataFork): auto =
  when kind >= LightClientDataFork.Altair:
    typedesc[altair.LightClientBootstrap]
  else:
    static: raiseAssert "Unreachable"

template forky*(
    x: typedesc[ForkedLightClientUpdate],
    kind: static LightClientDataFork): auto =
  when kind >= LightClientDataFork.Altair:
    typedesc[altair.LightClientUpdate]
  else:
    static: raiseAssert "Unreachable"

template forky*(
    x: typedesc[ForkedLightClientFinalityUpdate],
    kind: static LightClientDataFork): auto =
  when kind >= LightClientDataFork.Altair:
    typedesc[altair.LightClientFinalityUpdate]
  else:
    static: raiseAssert "Unreachable"

template forky*(
    x: typedesc[ForkedLightClientOptimisticUpdate],
    kind: static LightClientDataFork): auto =
  when kind >= LightClientDataFork.Altair:
    typedesc[altair.LightClientOptimisticUpdate]
  else:
    static: raiseAssert "Unreachable"

template forked*(x: typedesc[ForkyLightClientBootstrap]): auto =
  typedesc[ForkedLightClientBootstrap]

template forked*(x: typedesc[ForkyLightClientUpdate]): auto =
  typedesc[ForkedLightClientUpdate]

template forked*(x: typedesc[ForkyLightClientFinalityUpdate]): auto =
  typedesc[ForkedLightClientFinalityUpdate]

template forked*(x: typedesc[ForkyLightClientOptimisticUpdate]): auto =
  typedesc[ForkedLightClientOptimisticUpdate]

template withForkyBootstrap*(
    x: ForkedLightClientBootstrap, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject.} = LightClientDataFork.Altair
    template forkyBootstrap: untyped {.inject.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject.} = LightClientDataFork.None
    body

template withForkyUpdate*(
    x: ForkedLightClientUpdate, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject.} = LightClientDataFork.Altair
    template forkyUpdate: untyped {.inject.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject.} = LightClientDataFork.None
    body

template withForkyFinalityUpdate*(
    x: ForkedLightClientFinalityUpdate, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject.} = LightClientDataFork.Altair
    template forkyFinalityUpdate: untyped {.inject.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject.} = LightClientDataFork.None
    body

template withForkyOptimisticUpdate*(
    x: ForkedLightClientOptimisticUpdate, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject.} = LightClientDataFork.Altair
    template forkyOptimisticUpdate: untyped {.inject.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject.} = LightClientDataFork.None
    body

template withForkyObject*(
    x: SomeForkedLightClientObject, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Altair:
    const lcDataFork {.inject.} = LightClientDataFork.Altair
    template forkyObject: untyped {.inject.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject.} = LightClientDataFork.None
    body

template toOptimistic*(
    update: SomeForkedLightClientUpdate): ForkedLightClientOptimisticUpdate =
  when update is ForkyLightClientOptimisticUpdate:
    update
  else:
    withForkyObject(update):
      when lcDataFork >= LightClientDataFork.Altair:
        ForkedLightClientOptimisticUpdate(
          kind: lcDataFork,
          altairData: forkyObject.toOptimistic())
      else:
        default(ForkedLightClientOptimisticUpdate)

func matches*[A, B: SomeForkedLightClientUpdate](a: A, b: B): bool =
  if a.kind != b.kind:
    return false
  withForkyObject(a):
    when lcDataFork >= LightClientDataFork.Altair:
      forkyObject.matches(b.forky(lcDataFork))
    else:
      true

template forky*(
    x: SomeForkedLightClientObject, kind: static LightClientDataFork): untyped =
  when kind == LightClientDataFork.Altair:
    x.altairData
  else:
    discard

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
      if x.kind < LightClientDataFork.Altair:
        x = ForkedLightClientBootstrap(
          kind: LightClientDataFork.Altair)

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
      if x.kind < LightClientDataFork.Altair:
        x = ForkedLightClientUpdate(
          kind: LightClientDataFork.Altair)

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
      if x.kind < LightClientDataFork.Altair:
        x = ForkedLightClientFinalityUpdate(
          kind: LightClientDataFork.Altair)

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
      if x.kind < LightClientDataFork.Altair:
        x = ForkedLightClientOptimisticUpdate(
          kind: LightClientDataFork.Altair)

    doAssert x.kind == newKind

func migratedToDataFork*[T: SomeForkedLightClientObject](
    x: T, newKind: static LightClientDataFork): T =
  var upgradedObject = x
  upgradedObject.migrateToDataFork(newKind)
  upgradedObject
