# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  # Beacon chain internals
  ../spec/datatypes/altair,
  ../beacon_chain_db_light_client,
  ./block_dag

type
  LightClientDataImportMode* {.pure.} = enum
    ## Controls which classes of light client data are imported.
    None = "none"
      ## Import no light client data.
    OnlyNew = "only-new"
      ## Import only new light client data.
    Full = "full"
      ## Import light client data for entire weak subjectivity period.
    OnDemand = "on-demand"
      ## Don't precompute historic data. Slow, may miss validator duties.

  OnLightClientFinalityUpdateCallback* =
    proc(data: altair.LightClientFinalityUpdate) {.gcsafe, raises: [Defect].}
  OnLightClientOptimisticUpdateCallback* =
    proc(data: altair.LightClientOptimisticUpdate) {.gcsafe, raises: [Defect].}

  CachedLightClientData* = object
    ## Cached data from historical non-finalized states to improve speed when
    ## creating future `LightClientUpdate` and `LightClientBootstrap` instances.
    current_sync_committee_branch*: altair.CurrentSyncCommitteeBranch
    next_sync_committee_branch*: altair.NextSyncCommitteeBranch

    finalized_slot*: Slot
    finality_branch*: altair.FinalityBranch

  LightClientDataCache* = object
    data*: Table[BlockId, CachedLightClientData]
      ## Cached data for creating future `LightClientUpdate` instances.
      ## Key is the block ID of which the post state was used to get the data.
      ## Data stored for the finalized head block and all non-finalized blocks.

    pendingBest*:
      Table[(SyncCommitteePeriod, Eth2Digest), altair.LightClientUpdate]
      ## Same as `bestUpdates`, but for `SyncCommitteePeriod` with not yet
      ## finalized `next_sync_committee`. Key is `(attested_period,
      ## hash_tree_root(current_sync_committee | next_sync_committee)`.

    latest*: altair.LightClientFinalityUpdate
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
