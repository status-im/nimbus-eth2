# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Beacon chain internals
  ../spec/datatypes/altair,
  ../beacon_chain_db_light_client,
  ./block_dag

type
  LightClientDataImportMode* {.pure.} = enum
    ## Controls which classes of light client data are imported.
    None = "none"
      ## Do not import new light client data.
    OnlyNew = "only-new"
      ## Incrementally import new light client data.
    Full = "full"
      ## Import historic light client data (slow startup).
    OnDemand = "on-demand"
      ## Like `full`, but import on demand instead of on start.

  OnLightClientFinalityUpdateCallback* =
    proc(data: ForkedLightClientFinalityUpdate) {.gcsafe, raises: [].}
  OnLightClientOptimisticUpdateCallback* =
    proc(data: ForkedLightClientOptimisticUpdate) {.gcsafe, raises: [].}

  CachedLightClientData* = object
    ## Cached data from historical non-finalized states to improve speed when
    ## creating future `LightClientUpdate` and `LightClientBootstrap` instances.
    current_sync_committee_branch*: altair.CurrentSyncCommitteeBranch
    next_sync_committee_branch*: altair.NextSyncCommitteeBranch

    finalized_slot*: Slot
    finality_branch*: altair.FinalityBranch

    current_period_best_update*: ref ForkedLightClientUpdate

  LightClientDataCache* = object
    data*: Table[BlockId, CachedLightClientData]
      ## Cached data for creating future `LightClientUpdate` instances.
      ## Key is the block ID of which the post state was used to get the data.
      ## Data stored for the finalized head block and all non-finalized blocks.

    latest*: ForkedLightClientFinalityUpdate
      ## Tracks light client data for the latest slot that was signed by
      ## at least `MIN_SYNC_COMMITTEE_PARTICIPANTS`. May be older than head.

    tailSlot*: Slot
      ## The earliest slot for which light client data is imported.

  LightClientDataConfig* = object
    serve*: bool
      ## Whether to make local light client data available or not
    importMode*: LightClientDataImportMode
      ## Which classes of light client data to import
    maxPeriods*: Option[uint64]
      ## Maximum number of sync committee periods to retain light client data
    onLightClientFinalityUpdate*: OnLightClientFinalityUpdateCallback
      ## On new `LightClientFinalityUpdate` callback
    onLightClientOptimisticUpdate*: OnLightClientOptimisticUpdateCallback
      ## On new `LightClientOptimisticUpdate` callback

  LightClientDataStore* = object
    # -----------------------------------
    # Light client data

    cache*: LightClientDataCache
      ## Cached data to accelerate creating light client data
    db*: LightClientDataDB
      ## Persistent light client data to avoid expensive recomputations

    # -----------------------------------
    # Config

    serve*: bool
      ## Whether to make local light client data available or not
    importMode*: LightClientDataImportMode
      ## Which classes of light client data to import
    maxPeriods*: uint64
      ## Maximum number of sync committee periods to retain light client data

    # -----------------------------------
    # Callbacks

    onLightClientFinalityUpdate*: OnLightClientFinalityUpdateCallback
      ## On new `LightClientFinalityUpdate` callback
    onLightClientOptimisticUpdate*: OnLightClientOptimisticUpdateCallback
      ## On new `LightClientOptimisticUpdate` callback
