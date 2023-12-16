# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ./datatypes/[phase0, altair, bellatrix, capella, deneb],
  ./eth2_merkleization

type
  LightClientDataFork* {.pure.} = enum  # Append only, used in DB data!
    None = 0,  # only use non-0 in DB to detect accidentally uninitialized data
    Altair = 1,
    Capella = 2,
    Deneb = 3

  ForkyLightClientHeader* =
    altair.LightClientHeader |
    capella.LightClientHeader |
    deneb.LightClientHeader

  ForkyLightClientBootstrap* =
    altair.LightClientBootstrap |
    capella.LightClientBootstrap |
    deneb.LightClientBootstrap

  ForkyLightClientUpdate* =
    altair.LightClientUpdate |
    capella.LightClientUpdate |
    deneb.LightClientUpdate

  ForkyLightClientFinalityUpdate* =
    altair.LightClientFinalityUpdate |
    capella.LightClientFinalityUpdate |
    deneb.LightClientFinalityUpdate

  ForkyLightClientOptimisticUpdate* =
    altair.LightClientOptimisticUpdate |
    capella.LightClientOptimisticUpdate |
    deneb.LightClientOptimisticUpdate

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
    altair.LightClientStore |
    capella.LightClientStore |
    deneb.LightClientStore

  ForkedLightClientHeader* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientHeader
    of LightClientDataFork.Capella:
      capellaData*: capella.LightClientHeader
    of LightClientDataFork.Deneb:
      denebData*: deneb.LightClientHeader

  ForkedLightClientBootstrap* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientBootstrap
    of LightClientDataFork.Capella:
      capellaData*: capella.LightClientBootstrap
    of LightClientDataFork.Deneb:
      denebData*: deneb.LightClientBootstrap

  ForkedLightClientUpdate* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientUpdate
    of LightClientDataFork.Capella:
      capellaData*: capella.LightClientUpdate
    of LightClientDataFork.Deneb:
      denebData*: deneb.LightClientUpdate

  ForkedLightClientFinalityUpdate* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientFinalityUpdate
    of LightClientDataFork.Capella:
      capellaData*: capella.LightClientFinalityUpdate
    of LightClientDataFork.Deneb:
      denebData*: deneb.LightClientFinalityUpdate

  ForkedLightClientOptimisticUpdate* = object
    case kind*: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData*: altair.LightClientOptimisticUpdate
    of LightClientDataFork.Capella:
      capellaData*: capella.LightClientOptimisticUpdate
    of LightClientDataFork.Deneb:
      denebData*: deneb.LightClientOptimisticUpdate

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
    of LightClientDataFork.Capella:
      capellaData*: capella.LightClientStore
    of LightClientDataFork.Deneb:
      denebData*: deneb.LightClientStore

func lcDataForkAtEpoch*(
    cfg: RuntimeConfig, epoch: Epoch): LightClientDataFork =
  static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
  if epoch >= cfg.DENEB_FORK_EPOCH:
    LightClientDataFork.Deneb
  elif epoch >= cfg.CAPELLA_FORK_EPOCH:
    LightClientDataFork.Capella
  elif epoch >= cfg.ALTAIR_FORK_EPOCH:
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

template kind*(
    x: typedesc[ # `SomeLightClientObject` doesn't work here (Nim 1.6)
      capella.LightClientHeader |
      capella.LightClientBootstrap |
      capella.LightClientUpdate |
      capella.LightClientFinalityUpdate |
      capella.LightClientOptimisticUpdate |
      capella.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Capella

template kind*(
    x: typedesc[ # `SomeLightClientObject` doesn't work here (Nim 1.6)
      deneb.LightClientHeader |
      deneb.LightClientBootstrap |
      deneb.LightClientUpdate |
      deneb.LightClientFinalityUpdate |
      deneb.LightClientOptimisticUpdate |
      deneb.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Deneb

template LightClientHeader*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Deneb:
    typedesc[deneb.LightClientHeader]
  elif kind == LightClientDataFork.Capella:
    typedesc[capella.LightClientHeader]
  elif kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientHeader]
  else:
    static: raiseAssert "Unreachable"

template LightClientBootstrap*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Deneb:
    typedesc[deneb.LightClientBootstrap]
  elif kind == LightClientDataFork.Capella:
    typedesc[capella.LightClientBootstrap]
  elif kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientBootstrap]
  else:
    static: raiseAssert "Unreachable"

template LightClientUpdate*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Deneb:
    typedesc[deneb.LightClientUpdate]
  elif kind == LightClientDataFork.Capella:
    typedesc[capella.LightClientUpdate]
  elif kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientUpdate]
  else:
    static: raiseAssert "Unreachable"

template LightClientFinalityUpdate*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Deneb:
    typedesc[deneb.LightClientFinalityUpdate]
  elif kind == LightClientDataFork.Capella:
    typedesc[capella.LightClientFinalityUpdate]
  elif kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientFinalityUpdate]
  else:
    static: raiseAssert "Unreachable"

template LightClientOptimisticUpdate*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Deneb:
    typedesc[deneb.LightClientOptimisticUpdate]
  elif kind == LightClientDataFork.Capella:
    typedesc[capella.LightClientOptimisticUpdate]
  elif kind == LightClientDataFork.Altair:
    typedesc[altair.LightClientOptimisticUpdate]
  else:
    static: raiseAssert "Unreachable"

template LightClientStore*(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Deneb:
    typedesc[deneb.LightClientStore]
  elif kind == LightClientDataFork.Capella:
    typedesc[capella.LightClientStore]
  elif kind == LightClientDataFork.Altair:
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
  static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    body
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    body
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    body
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withLcDataFork*(
    x: LightClientDataFork, body: untyped): untyped =
  case x
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    body
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

template withForkyHeader*(
    x: ForkedLightClientHeader, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    template forkyHeader: untyped {.inject, used.} = x.denebData
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyHeader: untyped {.inject, used.} = x.capellaData
    body
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
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    template forkyBootstrap: untyped {.inject, used.} = x.denebData
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyBootstrap: untyped {.inject, used.} = x.capellaData
    body
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
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    template forkyUpdate: untyped {.inject, used.} = x.denebData
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyUpdate: untyped {.inject, used.} = x.capellaData
    body
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
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    template forkyFinalityUpdate: untyped {.inject, used.} = x.denebData
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyFinalityUpdate: untyped {.inject, used.} = x.capellaData
    body
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
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    template forkyOptimisticUpdate: untyped {.inject, used.} = x.denebData
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyOptimisticUpdate: untyped {.inject, used.} = x.capellaData
    body
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
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    template forkyObject: untyped {.inject, used.} = x.denebData
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyObject: untyped {.inject, used.} = x.capellaData
    body
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
  of LightClientDataFork.Deneb:
    const lcDataFork {.inject, used.} = LightClientDataFork.Deneb
    template forkyStore: untyped {.inject, used.} = x.denebData
    body
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyStore: untyped {.inject, used.} = x.capellaData
    body
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyStore: untyped {.inject, used.} = x.altairData
    body
  of LightClientDataFork.None:
    const lcDataFork {.inject, used.} = LightClientDataFork.None
    body

func init*(
    x: typedesc[
      ForkedLightClientHeader |
      SomeForkedLightClientObject |
      ForkedLightClientStore],
    forkyData:
      ForkyLightClientHeader |
      SomeForkyLightClientObject |
      ForkyLightClientStore): auto =
  type ResultType = typeof(forkyData).Forked
  static: doAssert ResultType is x
  const kind = typeof(forkyData).kind
  when kind == LightClientDataFork.Deneb:
    ResultType(kind: kind, denebData: forkyData)
  elif kind == LightClientDataFork.Capella:
    ResultType(kind: kind, capellaData: forkyData)
  elif kind == LightClientDataFork.Altair:
    ResultType(kind: kind, altairData: forkyData)
  else:
    static: raiseAssert "Unreachable"

template forky*(
    x:
      ForkedLightClientHeader |
      SomeForkedLightClientObject |
      ForkedLightClientStore,
    kind: static LightClientDataFork): untyped =
  when kind == LightClientDataFork.Deneb:
    x.denebData
  elif kind == LightClientDataFork.Capella:
    x.capellaData
  elif kind == LightClientDataFork.Altair:
    x.altairData
  else:
    static: raiseAssert "Unreachable"

func toFull*(
    update: SomeForkyLightClientUpdate): auto =
  type ResultType = typeof(update).kind.LightClientUpdate
  when update is ForkyLightClientUpdate:
    static: doAssert update is ResultType
    update
  elif update is SomeForkyLightClientUpdateWithFinality:
    ResultType(
      attested_header: update.attested_header,
      finalized_header: update.finalized_header,
      finality_branch: update.finality_branch,
      sync_aggregate: update.sync_aggregate,
      signature_slot: update.signature_slot)
  else:
    ResultType(
      attested_header: update.attested_header,
      sync_aggregate: update.sync_aggregate,
      signature_slot: update.signature_slot)

func toFull*(
    update: SomeForkedLightClientUpdate): ForkedLightClientUpdate =
  when update is ForkyLightClientUpdate:
    update
  else:
    withForkyObject(update):
      when lcDataFork > LightClientDataFork.None:
        ForkedLightClientUpdate.init(forkyObject.toFull())
      else:
        default(ForkedLightClientUpdate)

func toFinality*(
    update: SomeForkyLightClientUpdate): auto =
  type ResultType = typeof(update).kind.LightClientFinalityUpdate
  when update is ForkyLightClientFinalityUpdate:
    update
  elif update is SomeForkyLightClientUpdateWithFinality:
    ResultType(
      attested_header: update.attested_header,
      finalized_header: update.finalized_header,
      finality_branch: update.finality_branch,
      sync_aggregate: update.sync_aggregate,
      signature_slot: update.signature_slot)
  else:
    ResultType(
      attested_header: update.attested_header,
      sync_aggregate: update.sync_aggregate,
      signature_slot: update.signature_slot)

func toFinality*(
    update: SomeForkedLightClientUpdate): ForkedLightClientFinalityUpdate =
  when update is ForkyLightClientFinalityUpdate:
    update
  else:
    withForkyObject(update):
      when lcDataFork > LightClientDataFork.None:
        ForkedLightClientFinalityUpdate.init(forkyObject.toFinality())
      else:
        default(ForkedLightClientFinalityUpdate)

func toOptimistic*(
    update: SomeForkyLightClientUpdate): auto =
  type ResultType = typeof(update).kind.LightClientOptimisticUpdate
  when update is ForkyLightClientOptimisticUpdate:
    update
  else:
    ResultType(
      attested_header: update.attested_header,
      sync_aggregate: update.sync_aggregate,
      signature_slot: update.signature_slot)

func toOptimistic*(
    update: SomeForkedLightClientUpdate): ForkedLightClientOptimisticUpdate =
  when update is ForkyLightClientOptimisticUpdate:
    update
  else:
    withForkyObject(update):
      when lcDataFork > LightClientDataFork.None:
        ForkedLightClientOptimisticUpdate.init(forkyObject.toOptimistic())
      else:
        default(ForkedLightClientOptimisticUpdate)

func matches*[A, B: SomeForkyLightClientUpdate](a: A, b: B): bool =
  static: doAssert typeof(A).kind == typeof(B).kind
  if a.attested_header != b.attested_header:
    return false
  when a is SomeForkyLightClientUpdateWithSyncCommittee and
      b is SomeForkyLightClientUpdateWithSyncCommittee:
    if a.next_sync_committee != b.next_sync_committee:
      return false
    if a.next_sync_committee_branch != b.next_sync_committee_branch:
      return false
  when a is SomeForkyLightClientUpdateWithFinality and
      b is SomeForkyLightClientUpdateWithFinality:
    if a.finalized_header != b.finalized_header:
      return false
    if a.finality_branch != b.finality_branch:
      return false
  if a.sync_aggregate != b.sync_aggregate:
    return false
  if a.signature_slot != b.signature_slot:
    return false
  true

func matches*[A, B: SomeForkedLightClientUpdate](a: A, b: B): bool =
  if a.kind != b.kind:
    return false
  withForkyObject(a):
    when lcDataFork > LightClientDataFork.None:
      forkyObject.matches(b.forky(lcDataFork))
    else:
      true

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

    # Upgrade to Capella
    when newKind >= LightClientDataFork.Capella:
      if x.kind == LightClientDataFork.Altair:
        x = ForkedLightClientHeader(
          kind: LightClientDataFork.Capella,
          capellaData: upgrade_lc_header_to_capella(
            x.forky(LightClientDataFork.Altair)))

    # Upgrade to Deneb
    when newKind >= LightClientDataFork.Deneb:
      if x.kind == LightClientDataFork.Capella:
        x = ForkedLightClientHeader(
          kind: LightClientDataFork.Deneb,
          denebData: upgrade_lc_header_to_deneb(
            x.forky(LightClientDataFork.Capella)))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
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

    # Upgrade to Capella
    when newKind >= LightClientDataFork.Capella:
      if x.kind == LightClientDataFork.Altair:
        x = ForkedLightClientBootstrap(
          kind: LightClientDataFork.Capella,
          capellaData: upgrade_lc_bootstrap_to_capella(
            x.forky(LightClientDataFork.Altair)))

    # Upgrade to Deneb
    when newKind >= LightClientDataFork.Deneb:
      if x.kind == LightClientDataFork.Capella:
        x = ForkedLightClientBootstrap(
          kind: LightClientDataFork.Deneb,
          denebData: upgrade_lc_bootstrap_to_deneb(
            x.forky(LightClientDataFork.Capella)))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
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

    # Upgrade to Capella
    when newKind >= LightClientDataFork.Capella:
      if x.kind == LightClientDataFork.Altair:
        x = ForkedLightClientUpdate(
          kind: LightClientDataFork.Capella,
          capellaData: upgrade_lc_update_to_capella(
            x.forky(LightClientDataFork.Altair)))

    # Upgrade to Deneb
    when newKind >= LightClientDataFork.Deneb:
      if x.kind == LightClientDataFork.Capella:
        x = ForkedLightClientUpdate(
          kind: LightClientDataFork.Deneb,
          denebData: upgrade_lc_update_to_deneb(
            x.forky(LightClientDataFork.Capella)))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
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

    # Upgrade to Capella
    when newKind >= LightClientDataFork.Capella:
      if x.kind == LightClientDataFork.Altair:
        x = ForkedLightClientFinalityUpdate(
          kind: LightClientDataFork.Capella,
          capellaData: upgrade_lc_finality_update_to_capella(
            x.forky(LightClientDataFork.Altair)))

    # Upgrade to Deneb
    when newKind >= LightClientDataFork.Deneb:
      if x.kind == LightClientDataFork.Capella:
        x = ForkedLightClientFinalityUpdate(
          kind: LightClientDataFork.Deneb,
          denebData: upgrade_lc_finality_update_to_deneb(
            x.forky(LightClientDataFork.Capella)))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
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

    # Upgrade to Capella
    when newKind >= LightClientDataFork.Capella:
      if x.kind == LightClientDataFork.Altair:
        x = ForkedLightClientOptimisticUpdate(
          kind: LightClientDataFork.Capella,
          capellaData: upgrade_lc_optimistic_update_to_capella(
            x.forky(LightClientDataFork.Altair)))

    # Upgrade to Deneb
    when newKind >= LightClientDataFork.Deneb:
      if x.kind == LightClientDataFork.Capella:
        x = ForkedLightClientOptimisticUpdate(
          kind: LightClientDataFork.Deneb,
          denebData: upgrade_lc_optimistic_update_to_deneb(
            x.forky(LightClientDataFork.Capella)))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
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

    # Upgrade to Capella
    when newKind >= LightClientDataFork.Capella:
      if x.kind == LightClientDataFork.Altair:
        x = ForkedLightClientStore(
          kind: LightClientDataFork.Capella,
          capellaData: upgrade_lc_store_to_capella(
            x.forky(LightClientDataFork.Altair)))

    # Upgrade to Deneb
    when newKind >= LightClientDataFork.Deneb:
      if x.kind == LightClientDataFork.Capella:
        x = ForkedLightClientStore(
          kind: LightClientDataFork.Deneb,
          denebData: upgrade_lc_store_to_deneb(
            x.forky(LightClientDataFork.Capella)))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/full-node.md#block_to_light_client_header
func toAltairLightClientHeader(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock
): altair.LightClientHeader =
  altair.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader())

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/full-node.md#modified-block_to_light_client_header
func toCapellaLightClientHeader(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock
): capella.LightClientHeader =
  # Note that during fork transitions, `finalized_header` may still
  # point to earlier forks. While Bellatrix blocks also contain an
  # `ExecutionPayload` (minus `withdrawals_root`), it was not included
  # in the corresponding light client data. To ensure compatibility
  # with legacy data going through `upgrade_lc_header_to_capella`,
  # leave out execution data.
  capella.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader())

func toCapellaLightClientHeader(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock
): capella.LightClientHeader =
  template payload: untyped = blck.message.body.execution_payload
  capella.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution: capella.ExecutionPayloadHeader(
      parent_hash: payload.parent_hash,
      fee_recipient: payload.fee_recipient,
      state_root: payload.state_root,
      receipts_root: payload.receipts_root,
      logs_bloom: payload.logs_bloom,
      prev_randao: payload.prev_randao,
      block_number: payload.block_number,
      gas_limit: payload.gas_limit,
      gas_used: payload.gas_used,
      timestamp: payload.timestamp,
      extra_data: payload.extra_data,
      base_fee_per_gas: payload.base_fee_per_gas,
      block_hash: payload.block_hash,
      transactions_root: hash_tree_root(payload.transactions),
      withdrawals_root: hash_tree_root(payload.withdrawals)),
    execution_branch: blck.message.body.build_proof(
      capella.EXECUTION_PAYLOAD_GINDEX).get)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.0/specs/deneb/light-client/full-node.md#modified-block_to_light_client_header
func toDenebLightClientHeader(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock
): deneb.LightClientHeader =
  # Note that during fork transitions, `finalized_header` may still
  # point to earlier forks. While Bellatrix blocks also contain an
  # `ExecutionPayload` (minus `withdrawals_root`), it was not included
  # in the corresponding light client data. To ensure compatibility
  # with legacy data going through `upgrade_lc_header_to_capella`,
  # leave out execution data.
  deneb.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader())

func toDenebLightClientHeader(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock
): deneb.LightClientHeader =
  template payload: untyped = blck.message.body.execution_payload
  deneb.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution: deneb.ExecutionPayloadHeader(
      parent_hash: payload.parent_hash,
      fee_recipient: payload.fee_recipient,
      state_root: payload.state_root,
      receipts_root: payload.receipts_root,
      logs_bloom: payload.logs_bloom,
      prev_randao: payload.prev_randao,
      block_number: payload.block_number,
      gas_limit: payload.gas_limit,
      gas_used: payload.gas_used,
      timestamp: payload.timestamp,
      extra_data: payload.extra_data,
      base_fee_per_gas: payload.base_fee_per_gas,
      block_hash: payload.block_hash,
      transactions_root: hash_tree_root(payload.transactions),
      withdrawals_root: hash_tree_root(payload.withdrawals)),
    execution_branch: blck.message.body.build_proof(
      capella.EXECUTION_PAYLOAD_GINDEX).get)

func toDenebLightClientHeader(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      deneb.SignedBeaconBlock | deneb.TrustedSignedBeaconBlock
): deneb.LightClientHeader =
  template payload: untyped = blck.message.body.execution_payload
  deneb.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution: deneb.ExecutionPayloadHeader(
      parent_hash: payload.parent_hash,
      fee_recipient: payload.fee_recipient,
      state_root: payload.state_root,
      receipts_root: payload.receipts_root,
      logs_bloom: payload.logs_bloom,
      prev_randao: payload.prev_randao,
      block_number: payload.block_number,
      gas_limit: payload.gas_limit,
      gas_used: payload.gas_used,
      timestamp: payload.timestamp,
      extra_data: payload.extra_data,
      base_fee_per_gas: payload.base_fee_per_gas,
      block_hash: payload.block_hash,
      transactions_root: hash_tree_root(payload.transactions),
      withdrawals_root: hash_tree_root(payload.withdrawals),
      excess_blob_gas: payload.excess_blob_gas),
    execution_branch: blck.message.body.build_proof(
      capella.EXECUTION_PAYLOAD_GINDEX).get)

func toLightClientHeader*(
    blck:  # `SomeSignedBeaconBlock` doesn't work here (Nim 1.6)
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock |
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock |
      deneb.SignedBeaconBlock | deneb.TrustedSignedBeaconBlock,
    kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Deneb:
    blck.toDenebLightClientHeader()
  elif kind == LightClientDataFork.Capella:
    blck.toCapellaLightClientHeader()
  elif kind == LightClientDataFork.Altair:
    blck.toAltairLightClientHeader()
  else:
    static: raiseAssert "Unreachable"

import chronicles

func shortLog*[
    T:
      ForkedLightClientHeader |
      SomeForkedLightClientObject |
      ForkedLightClientStore](
    x: T): auto =
  type ResultType = object
    case kind: LightClientDataFork
    of LightClientDataFork.None:
      discard
    of LightClientDataFork.Altair:
      altairData: typeof(x.altairData.shortLog())
    of LightClientDataFork.Capella:
      capellaData: typeof(x.capellaData.shortLog())
    of LightClientDataFork.Deneb:
      denebData: typeof(x.denebData.shortLog())

  let xKind = x.kind  # Nim 1.6.12: Using `kind: x.kind` inside case is broken
  case xKind
  of LightClientDataFork.Deneb:
    ResultType(kind: xKind, denebData: x.denebData.shortLog())
  of LightClientDataFork.Capella:
    ResultType(kind: xKind, capellaData: x.capellaData.shortLog())
  of LightClientDataFork.Altair:
    ResultType(kind: xKind, altairData: x.altairData.shortLog())
  of LightClientDataFork.None:
    ResultType(kind: xKind)

chronicles.formatIt ForkedLightClientHeader: it.shortLog
chronicles.formatIt SomeForkedLightClientObject: it.shortLog
chronicles.formatIt ForkedLightClientStore: it.shortLog
