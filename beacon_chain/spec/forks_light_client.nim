# beacon_chain
# Copyright (c) 2023-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ./datatypes/[
    phase0, altair, bellatrix, capella, deneb, electra, fulu, gloas, heze],
  ./eth2_merkleization

type
  LightClientDataFork* {.pure.} = enum  # Append only, used in DB data!
    None = 0,  # only use non-0 in DB to detect accidentally uninitialized data
    Altair = 1,
    Capella = 2,
    Deneb = 3,
    Electra = 4,
    Gloas = 5

  ForkyCurrentSyncCommitteeBranch* =
    altair.CurrentSyncCommitteeBranch |
    electra.CurrentSyncCommitteeBranch

  ForkyLightClientHeader* =
    altair.LightClientHeader |
    capella.LightClientHeader |
    deneb.LightClientHeader |
    electra.LightClientHeader |
    gloas.LightClientHeader

  ForkyLightClientBootstrap* =
    altair.LightClientBootstrap |
    capella.LightClientBootstrap |
    deneb.LightClientBootstrap |
    electra.LightClientBootstrap |
    gloas.LightClientBootstrap

  ForkyLightClientUpdate* =
    altair.LightClientUpdate |
    capella.LightClientUpdate |
    deneb.LightClientUpdate |
    electra.LightClientUpdate |
    gloas.LightClientUpdate

  ForkyLightClientFinalityUpdate* =
    altair.LightClientFinalityUpdate |
    capella.LightClientFinalityUpdate |
    deneb.LightClientFinalityUpdate |
    electra.LightClientFinalityUpdate |
    gloas.LightClientFinalityUpdate

  ForkyLightClientOptimisticUpdate* =
    altair.LightClientOptimisticUpdate |
    capella.LightClientOptimisticUpdate |
    deneb.LightClientOptimisticUpdate |
    electra.LightClientOptimisticUpdate |
    gloas.LightClientOptimisticUpdate

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
    deneb.LightClientStore |
    electra.LightClientStore |
    gloas.LightClientStore

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
    of LightClientDataFork.Electra:
      electraData*: electra.LightClientHeader
    of LightClientDataFork.Gloas:
      gloasData*: gloas.LightClientHeader

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
    of LightClientDataFork.Electra:
      electraData*: electra.LightClientBootstrap
    of LightClientDataFork.Gloas:
      gloasData*: gloas.LightClientBootstrap

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
    of LightClientDataFork.Electra:
      electraData*: electra.LightClientUpdate
    of LightClientDataFork.Gloas:
      gloasData*: gloas.LightClientUpdate

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
    of LightClientDataFork.Electra:
      electraData*: electra.LightClientFinalityUpdate
    of LightClientDataFork.Gloas:
      gloasData*: gloas.LightClientFinalityUpdate

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
    of LightClientDataFork.Electra:
      electraData*: electra.LightClientOptimisticUpdate
    of LightClientDataFork.Gloas:
      gloasData*: gloas.LightClientOptimisticUpdate

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
    of LightClientDataFork.Electra:
      electraData*: electra.LightClientStore
    of LightClientDataFork.Gloas:
      gloasData*: gloas.LightClientStore

template kind*(
    x: typedesc[
      altair.SomeLightClientObject |
      altair.LightClientHeader |
      altair.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Altair

template kind*(
    x: typedesc[
      capella.SomeLightClientObject |
      capella.LightClientHeader |
      capella.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Capella

template kind*(
    x: typedesc[
      deneb.SomeLightClientObject |
      deneb.LightClientHeader |
      deneb.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Deneb

template kind*(
    x: typedesc[
      electra.SomeLightClientObject |
      electra.LightClientHeader |
      electra.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Electra

template kind*(
    x: typedesc[
      gloas.SomeLightClientObject |
      gloas.LightClientHeader |
      gloas.LightClientStore]): LightClientDataFork =
  LightClientDataFork.Gloas

template execution_block_hash*(
    forkyHeader:
      capella.LightClientHeader |
      deneb.LightClientHeader |
      electra.LightClientHeader): Eth2Digest =
  forkyHeader.execution.block_hash

template finalized_root_gindex*(
    kind: static LightClientDataFork): GeneralizedIndex =
  when kind >= LightClientDataFork.Electra:
    FINALIZED_ROOT_GINDEX_ELECTRA
  elif kind >= LightClientDataFork.Altair:
    FINALIZED_ROOT_GINDEX
  else:
    {.error: "finalized_root_gindex unsupported in " & $kind.}

template FinalityBranch*(
    kind: static LightClientDataFork): typedesc =
  when kind >= LightClientDataFork.Electra:
    electra.FinalityBranch
  elif kind >= LightClientDataFork.Altair:
    altair.FinalityBranch
  else:
    {.error: "FinalityBranch unsupported in " & $kind.}

template current_sync_committee_gindex*(
    kind: static LightClientDataFork): GeneralizedIndex =
  when kind >= LightClientDataFork.Electra:
    CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA
  elif kind >= LightClientDataFork.Altair:
    CURRENT_SYNC_COMMITTEE_GINDEX
  else:
    {.error: "current_sync_committee_gindex unsupported in " & $kind.}

template CurrentSyncCommitteeBranch*(
    kind: static LightClientDataFork): typedesc =
  when kind >= LightClientDataFork.Electra:
    electra.CurrentSyncCommitteeBranch
  elif kind >= LightClientDataFork.Altair:
    altair.CurrentSyncCommitteeBranch
  else:
    {.error: "CurrentSyncCommitteeBranch unsupported in " & $kind.}

template next_sync_committee_gindex*(
    kind: static LightClientDataFork): GeneralizedIndex =
  when kind >= LightClientDataFork.Electra:
    NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA
  elif kind >= LightClientDataFork.Altair:
    NEXT_SYNC_COMMITTEE_GINDEX
  else:
    {.error: "next_sync_committee_gindex unsupported in " & $kind.}

template NextSyncCommitteeBranch*(
    kind: static LightClientDataFork): typedesc =
  when kind >= LightClientDataFork.Electra:
    electra.NextSyncCommitteeBranch
  elif kind >= LightClientDataFork.Altair:
    altair.NextSyncCommitteeBranch
  else:
    {.error: "NextSyncCommitteeBranch unsupported in " & $kind.}

template LightClientHeader*(kind: static LightClientDataFork): typedesc =
  when kind == LightClientDataFork.Gloas:
    gloas.LightClientHeader
  elif kind == LightClientDataFork.Electra:
    electra.LightClientHeader
  elif kind == LightClientDataFork.Deneb:
    deneb.LightClientHeader
  elif kind == LightClientDataFork.Capella:
    capella.LightClientHeader
  elif kind == LightClientDataFork.Altair:
    altair.LightClientHeader
  else:
    {.error: "LightClientHeader unsupported in " & $kind.}

template LightClientBootstrap*(kind: static LightClientDataFork): typedesc =
  when kind == LightClientDataFork.Gloas:
    gloas.LightClientBootstrap
  elif kind == LightClientDataFork.Electra:
    electra.LightClientBootstrap
  elif kind == LightClientDataFork.Deneb:
    deneb.LightClientBootstrap
  elif kind == LightClientDataFork.Capella:
    capella.LightClientBootstrap
  elif kind == LightClientDataFork.Altair:
    altair.LightClientBootstrap
  else:
    {.error: "LightClientBootstrap unsupported in " & $kind.}

template LightClientUpdate*(kind: static LightClientDataFork): typedesc =
  when kind == LightClientDataFork.Gloas:
    gloas.LightClientUpdate
  elif kind == LightClientDataFork.Electra:
    electra.LightClientUpdate
  elif kind == LightClientDataFork.Deneb:
    deneb.LightClientUpdate
  elif kind == LightClientDataFork.Capella:
    capella.LightClientUpdate
  elif kind == LightClientDataFork.Altair:
    altair.LightClientUpdate
  else:
    {.error: "LightClientUpdate unsupported in " & $kind.}

template LightClientFinalityUpdate*(kind: static LightClientDataFork): typedesc =
  when kind == LightClientDataFork.Gloas:
    gloas.LightClientFinalityUpdate
  elif kind == LightClientDataFork.Electra:
    electra.LightClientFinalityUpdate
  elif kind == LightClientDataFork.Deneb:
    deneb.LightClientFinalityUpdate
  elif kind == LightClientDataFork.Capella:
    capella.LightClientFinalityUpdate
  elif kind == LightClientDataFork.Altair:
    altair.LightClientFinalityUpdate
  else:
    {.error: "LightClientFinalityUpdate unsupported in " & $kind.}

template LightClientOptimisticUpdate*(kind: static LightClientDataFork): typedesc =
  when kind == LightClientDataFork.Gloas:
    gloas.LightClientOptimisticUpdate
  elif kind == LightClientDataFork.Electra:
    electra.LightClientOptimisticUpdate
  elif kind == LightClientDataFork.Deneb:
    deneb.LightClientOptimisticUpdate
  elif kind == LightClientDataFork.Capella:
    capella.LightClientOptimisticUpdate
  elif kind == LightClientDataFork.Altair:
    altair.LightClientOptimisticUpdate
  else:
    {.error: "LightClientOptimisticUpdate unsupported in " & $kind.}

template LightClientStore*(kind: static LightClientDataFork): typedesc =
  when kind == LightClientDataFork.Gloas:
    gloas.LightClientStore
  elif kind == LightClientDataFork.Electra:
    electra.LightClientStore
  elif kind == LightClientDataFork.Deneb:
    deneb.LightClientStore
  elif kind == LightClientDataFork.Capella:
    capella.LightClientStore
  elif kind == LightClientDataFork.Altair:
    altair.LightClientStore
  else:
    {.error: "LightClientStore unsupported in " & $kind.}

template Forky*(
    x: typedesc[ForkedLightClientHeader],
    kind: static LightClientDataFork): typedesc =
  kind.LightClientHeader

template Forky*(
    x: typedesc[ForkedLightClientBootstrap],
    kind: static LightClientDataFork): typedesc =
  kind.LightClientBootstrap

template Forky*(
    x: typedesc[ForkedLightClientUpdate],
    kind: static LightClientDataFork): typedesc =
  kind.LightClientUpdate

template Forky*(
    x: typedesc[ForkedLightClientFinalityUpdate],
    kind: static LightClientDataFork): typedesc =
  kind.LightClientFinalityUpdate

template Forky*(
    x: typedesc[ForkedLightClientOptimisticUpdate],
    kind: static LightClientDataFork): typedesc =
  kind.LightClientOptimisticUpdate

template Forky*(
    x: typedesc[ForkedLightClientStore],
    kind: static LightClientDataFork): typedesc =
  kind.LightClientStore

template Forked*(x: typedesc[ForkyLightClientHeader]): typedesc =
  ForkedLightClientHeader

template Forked*(x: typedesc[ForkyLightClientBootstrap]): typedesc =
  ForkedLightClientBootstrap

template Forked*(x: typedesc[ForkyLightClientUpdate]): typedesc =
  ForkedLightClientUpdate

template Forked*(x: typedesc[ForkyLightClientFinalityUpdate]): typedesc =
  ForkedLightClientFinalityUpdate

template Forked*(x: typedesc[ForkyLightClientOptimisticUpdate]): typedesc =
  ForkedLightClientOptimisticUpdate

template Forked*(x: typedesc[ForkyLightClientStore]): typedesc =
  ForkedLightClientStore

template withAll*(
    x: typedesc[LightClientDataFork], body: untyped): untyped =
  static: doAssert LightClientDataFork.high == LightClientDataFork.Gloas
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    body
  block:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    template forkyHeader: untyped {.inject, used.} = x.gloasData
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    template forkyHeader: untyped {.inject, used.} = x.electraData
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    template forkyBootstrap: untyped {.inject, used.} = x.gloasData
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    template forkyBootstrap: untyped {.inject, used.} = x.electraData
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    template forkyUpdate: untyped {.inject, used.} = x.gloasData
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    template forkyUpdate: untyped {.inject, used.} = x.electraData
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    template forkyFinalityUpdate: untyped {.inject, used.} = x.gloasData
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    template forkyFinalityUpdate: untyped {.inject, used.} = x.electraData
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    template forkyOptimisticUpdate: untyped {.inject, used.} = x.gloasData
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    template forkyOptimisticUpdate: untyped {.inject, used.} = x.electraData
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    template forkyObject: untyped {.inject, used.} = x.gloasData
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    template forkyObject: untyped {.inject, used.} = x.electraData
    body
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
  of LightClientDataFork.Gloas:
    const lcDataFork {.inject, used.} = LightClientDataFork.Gloas
    template forkyStore: untyped {.inject, used.} = x.gloasData
    body
  of LightClientDataFork.Electra:
    const lcDataFork {.inject, used.} = LightClientDataFork.Electra
    template forkyStore: untyped {.inject, used.} = x.electraData
    body
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
  when kind == LightClientDataFork.Gloas:
    ResultType(kind: kind, gloasData: forkyData)
  elif kind == LightClientDataFork.Electra:
    ResultType(kind: kind, electraData: forkyData)
  elif kind == LightClientDataFork.Deneb:
    ResultType(kind: kind, denebData: forkyData)
  elif kind == LightClientDataFork.Capella:
    ResultType(kind: kind, capellaData: forkyData)
  elif kind == LightClientDataFork.Altair:
    ResultType(kind: kind, altairData: forkyData)
  else:
    {.error: "init(" & $x & ") unsupported in " & $kind.}

template forky*(
    x:
      ForkedLightClientHeader |
      SomeForkedLightClientObject |
      ForkedLightClientStore,
    kind: static LightClientDataFork): untyped =
  when kind == LightClientDataFork.Gloas:
    x.gloasData
  elif kind == LightClientDataFork.Electra:
    x.electraData
  elif kind == LightClientDataFork.Deneb:
    x.denebData
  elif kind == LightClientDataFork.Capella:
    x.capellaData
  elif kind == LightClientDataFork.Altair:
    x.altairData
  else:
    {.error: "forky(" & $typeof(x) & ") unsupported in " & $kind.}

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
    newKind: static LightClientDataFork,
    cfg: RuntimeConfig) =
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

    # Upgrade to Electra
    when newKind >= LightClientDataFork.Electra:
      if x.kind == LightClientDataFork.Deneb:
        x = ForkedLightClientHeader(
          kind: LightClientDataFork.Electra,
          electraData: upgrade_lc_header_to_electra(
            x.forky(LightClientDataFork.Deneb)))

    # Upgrade to Gloas
    when newKind >= LightClientDataFork.Gloas:
      if x.kind == LightClientDataFork.Electra:
        x = ForkedLightClientHeader(
          kind: LightClientDataFork.Gloas,
          gloasData: upgrade_lc_header_to_gloas(
            x.forky(LightClientDataFork.Electra), cfg))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Gloas
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientBootstrap,
    newKind: static LightClientDataFork,
    cfg: RuntimeConfig) =
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

    # Upgrade to Electra
    when newKind >= LightClientDataFork.Electra:
      if x.kind == LightClientDataFork.Deneb:
        x = ForkedLightClientBootstrap(
          kind: LightClientDataFork.Electra,
          electraData: upgrade_lc_bootstrap_to_electra(
            x.forky(LightClientDataFork.Deneb)))

    # Upgrade to Gloas
    when newKind >= LightClientDataFork.Gloas:
      if x.kind == LightClientDataFork.Electra:
        x = ForkedLightClientBootstrap(
          kind: LightClientDataFork.Gloas,
          gloasData: upgrade_lc_bootstrap_to_gloas(
            x.forky(LightClientDataFork.Electra), cfg))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Gloas
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientUpdate,
    newKind: static LightClientDataFork,
    cfg: RuntimeConfig) =
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

    # Upgrade to Electra
    when newKind >= LightClientDataFork.Electra:
      if x.kind == LightClientDataFork.Deneb:
        x = ForkedLightClientUpdate(
          kind: LightClientDataFork.Electra,
          electraData: upgrade_lc_update_to_electra(
            x.forky(LightClientDataFork.Deneb)))

    # Upgrade to Gloas
    when newKind >= LightClientDataFork.Gloas:
      if x.kind == LightClientDataFork.Electra:
        x = ForkedLightClientUpdate(
          kind: LightClientDataFork.Gloas,
          gloasData: upgrade_lc_update_to_gloas(
            x.forky(LightClientDataFork.Electra), cfg))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Gloas
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientFinalityUpdate,
    newKind: static LightClientDataFork,
    cfg: RuntimeConfig) =
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

    # Upgrade to Electra
    when newKind >= LightClientDataFork.Electra:
      if x.kind == LightClientDataFork.Deneb:
        x = ForkedLightClientFinalityUpdate(
          kind: LightClientDataFork.Electra,
          electraData: upgrade_lc_finality_update_to_electra(
            x.forky(LightClientDataFork.Deneb)))

    # Upgrade to Gloas
    when newKind >= LightClientDataFork.Gloas:
      if x.kind == LightClientDataFork.Electra:
        x = ForkedLightClientFinalityUpdate(
          kind: LightClientDataFork.Gloas,
          gloasData: upgrade_lc_finality_update_to_gloas(
            x.forky(LightClientDataFork.Electra), cfg))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Gloas
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientOptimisticUpdate,
    newKind: static LightClientDataFork,
    cfg: RuntimeConfig) =
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

    # Upgrade to Electra
    when newKind >= LightClientDataFork.Electra:
      if x.kind == LightClientDataFork.Deneb:
        x = ForkedLightClientOptimisticUpdate(
          kind: LightClientDataFork.Electra,
          electraData: upgrade_lc_optimistic_update_to_electra(
            x.forky(LightClientDataFork.Deneb)))

    # Upgrade to Gloas
    when newKind >= LightClientDataFork.Gloas:
      if x.kind == LightClientDataFork.Electra:
        x = ForkedLightClientOptimisticUpdate(
          kind: LightClientDataFork.Gloas,
          gloasData: upgrade_lc_optimistic_update_to_gloas(
            x.forky(LightClientDataFork.Electra), cfg))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Gloas
    doAssert x.kind == newKind

func migrateToDataFork*(
    x: var ForkedLightClientStore,
    newKind: static LightClientDataFork,
    cfg: RuntimeConfig) =
  if newKind == x.kind:
    # Already at correct kind
    discard
  elif newKind < x.kind:
    # Downgrade not supported, re-initialize
    x = static(ForkedLightClientStore(kind: newKind))
  else:
    # Upgrade to Altair
    when newKind >= LightClientDataFork.Altair:
      if x.kind == LightClientDataFork.None:
        x = static(ForkedLightClientStore(
          kind: LightClientDataFork.Altair))

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

    # Upgrade to Electra
    when newKind >= LightClientDataFork.Electra:
      if x.kind == LightClientDataFork.Deneb:
        x = ForkedLightClientStore(
          kind: LightClientDataFork.Electra,
          electraData: upgrade_lc_store_to_electra(
            x.forky(LightClientDataFork.Deneb)))

    # Upgrade to Gloas
    when newKind >= LightClientDataFork.Gloas:
      if x.kind == LightClientDataFork.Electra:
        x = ForkedLightClientStore(
          kind: LightClientDataFork.Gloas,
          gloasData: upgrade_lc_store_to_gloas(
            x.forky(LightClientDataFork.Electra), cfg))

    static: doAssert LightClientDataFork.high == LightClientDataFork.Gloas
    doAssert x.kind == newKind

func migratingToDataFork*[
    T:
      ForkedLightClientHeader |
      SomeForkedLightClientObject |
      ForkedLightClientStore](
    x: T, newKind: static LightClientDataFork, cfg: RuntimeConfig): T =
  var upgradedObject = x
  upgradedObject.migrateToDataFork(newKind, cfg)
  upgradedObject

# Convenience-based location for toExecutionPayloadHeader because this is the
# first time we have access to `hash_tree_root` in a universally available
# module
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/beacon-chain.md#process_execution_payload
proc toExecutionPayloadHeader*(
    payload: bellatrix.ExecutionPayload
): bellatrix.ExecutionPayloadHeader =
  bellatrix.ExecutionPayloadHeader(
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
    base_fee_per_gas: payload.base_fee_per_gas,
    block_hash: payload.block_hash,
    extra_data: payload.extra_data,
    transactions_root: hash_tree_root(payload.transactions),
  )

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#modified-process_execution_payload
proc toExecutionPayloadHeader*(
    payload: capella.ExecutionPayload
): capella.ExecutionPayloadHeader =
  capella.ExecutionPayloadHeader(
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
    base_fee_per_gas: payload.base_fee_per_gas,
    block_hash: payload.block_hash,
    extra_data: payload.extra_data,
    transactions_root: hash_tree_root(payload.transactions),
    withdrawals_root: hash_tree_root(payload.withdrawals), # [New in Capella]
  )

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/beacon-chain.md#process_execution_payload
proc toExecutionPayloadHeader*(
    payload: deneb.ExecutionPayload
): deneb.ExecutionPayloadHeader =
  deneb.ExecutionPayloadHeader(
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
    base_fee_per_gas: payload.base_fee_per_gas,
    block_hash: payload.block_hash,
    extra_data: payload.extra_data,
    transactions_root: hash_tree_root(payload.transactions),
    withdrawals_root: hash_tree_root(payload.withdrawals),
    blob_gas_used: payload.blob_gas_used, # [New in Deneb]
    excess_blob_gas: payload.excess_blob_gas, # [New in Deneb]
  )

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/full-node.md#block_to_light_client_header
func toAltairLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock
): altair.LightClientHeader =
  altair.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader())

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/full-node.md#modified-block_to_light_client_header
func toCapellaLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
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
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock
): capella.LightClientHeader =
  capella.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution: blck.message.body.execution_payload.toExecutionPayloadHeader(),
    execution_branch: blck.message.body.build_proof(
      capella.EXECUTION_PAYLOAD_GINDEX).get)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.0/specs/deneb/light-client/full-node.md#modified-block_to_light_client_header
func toDenebLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
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
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
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
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      deneb.SignedBeaconBlock | deneb.TrustedSignedBeaconBlock
): deneb.LightClientHeader =
  deneb.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution: blck.message.body.execution_payload.toExecutionPayloadHeader(),
    execution_branch: blck.message.body.build_proof(
      capella.EXECUTION_PAYLOAD_GINDEX).get)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/light-client/full-node.md#modified-block_to_light_client_header
func toElectraLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock
): electra.LightClientHeader =
  # Note that during fork transitions, `finalized_header` may still
  # point to earlier forks. While Bellatrix blocks also contain an
  # `ExecutionPayload` (minus `withdrawals_root`), it was not included
  # in the corresponding light client data. To ensure compatibility
  # with legacy data going through `upgrade_lc_header_to_capella`,
  # leave out execution data.
  electra.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader())

func toElectraLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock
): electra.LightClientHeader =
  template payload: untyped = blck.message.body.execution_payload
  electra.LightClientHeader(
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

func toElectraLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      deneb.SignedBeaconBlock | deneb.TrustedSignedBeaconBlock |
      electra.SignedBeaconBlock | electra.TrustedSignedBeaconBlock |
      fulu.SignedBeaconBlock | fulu.TrustedSignedBeaconBlock
): electra.LightClientHeader =
  electra.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution: blck.message.body.execution_payload.toExecutionPayloadHeader(),
    execution_branch: blck.message.body.build_proof(
      capella.EXECUTION_PAYLOAD_GINDEX).get)

func toGloasLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock
): gloas.LightClientHeader =
  gloas.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader())

func toGloasLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock
): gloas.LightClientHeader =
  gloas.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution_block_hash: blck.message.body.execution_payload.block_hash,
    execution_branch: normalize_merkle_branch(
      blck.message.body.build_proof(EXECUTION_BLOCK_HASH_GINDEX).get,
      EXECUTION_BLOCK_HASH_GINDEX_GLOAS))

func toGloasLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      deneb.SignedBeaconBlock | deneb.TrustedSignedBeaconBlock |
      electra.SignedBeaconBlock | electra.TrustedSignedBeaconBlock |
      fulu.SignedBeaconBlock | fulu.TrustedSignedBeaconBlock
): gloas.LightClientHeader =
  gloas.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution_block_hash: blck.message.body.execution_payload.block_hash,
    execution_branch: normalize_merkle_branch(
      blck.message.body.build_proof(EXECUTION_BLOCK_HASH_GINDEX_DENEB).get,
      EXECUTION_BLOCK_HASH_GINDEX_GLOAS))

func toGloasLightClientHeader(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      gloas.SignedBeaconBlock | gloas.TrustedSignedBeaconBlock |
      heze.SignedBeaconBlock | heze.TrustedSignedBeaconBlock
): gloas.LightClientHeader =
  gloas.LightClientHeader(
    beacon: blck.message.toBeaconBlockHeader(),
    execution_block_hash:
      blck.message.body.signed_execution_payload_bid.message.parent_block_hash,
    execution_branch:
      blck.message.body.build_proof(EXECUTION_BLOCK_HASH_GINDEX_GLOAS).get)

func toLightClientHeader*(
    # `SomeSignedBeaconBlock`: https://github.com/nim-lang/Nim/issues/18095
    blck:
      phase0.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock |
      altair.SignedBeaconBlock | altair.TrustedSignedBeaconBlock |
      bellatrix.SignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock |
      capella.SignedBeaconBlock | capella.TrustedSignedBeaconBlock |
      deneb.SignedBeaconBlock | deneb.TrustedSignedBeaconBlock |
      electra.SignedBeaconBlock | electra.TrustedSignedBeaconBlock |
      fulu.SignedBeaconBlock | fulu.TrustedSignedBeaconBlock |
      gloas.SignedBeaconBlock | gloas.TrustedSignedBeaconBlock |
      heze.SignedBeaconBlock | heze.TrustedSignedBeaconBlock,
    kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Gloas:
    blck.toGloasLightClientHeader()
  elif kind == LightClientDataFork.Electra:
    blck.toElectraLightClientHeader()
  elif kind == LightClientDataFork.Deneb:
    blck.toDenebLightClientHeader()
  elif kind == LightClientDataFork.Capella:
    blck.toCapellaLightClientHeader()
  elif kind == LightClientDataFork.Altair:
    blck.toAltairLightClientHeader()
  else:
    {.error: "toLightClientHeader unsupported in " & $kind.}

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
    of LightClientDataFork.Electra:
      electraData: typeof(x.electraData.shortLog())
    of LightClientDataFork.Gloas:
      gloasData: typeof(x.gloasData.shortLog())

  let xKind = x.kind  # https://github.com/nim-lang/Nim/issues/23762
  case xKind
  of LightClientDataFork.Gloas:
    ResultType(kind: xKind, gloasData: x.gloasData.shortLog())
  of LightClientDataFork.Electra:
    ResultType(kind: xKind, electraData: x.electraData.shortLog())
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
