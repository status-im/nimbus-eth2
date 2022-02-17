# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Status libraries
  stew/bitops2,
  # Beacon chain internals
  ../spec/datatypes/altair,
  ./block_dag

type
  OnOptimisticLightClientUpdateCallback* =
    proc(data: OptimisticLightClientUpdate) {.gcsafe, raises: [Defect].}

  ImportLightClientData* {.pure.} = enum
    ## Controls which classes of light client data are imported.
    None = "none"
      ## Import no light client data.
    OnlyNew = "only-new"
      ## Import only new light client data (new non-finalized blocks).
    Full = "full"
      ## Import light client data for entire weak subjectivity period.
    OnDemand = "on-demand"
      ## No precompute of historic data. Is slow and may miss validator duties.

  CachedLightClientData* = object
    ## Cached data from historical non-finalized states to improve speed when
    ## creating future `LightClientUpdate` and `LightClientBootstrap` instances.
    current_sync_committee_branch*:
      array[log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX), Eth2Digest]

    next_sync_committee_branch*:
      array[log2trunc(altair.NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest]

    finalized_bid*: BlockId
    finality_branch*:
      array[log2trunc(altair.FINALIZED_ROOT_INDEX), Eth2Digest]

  CachedLightClientBootstrap* = object
    ## Cached data from historical finalized epoch boundary blocks to improve
    ## speed when creating future `LightClientBootstrap` instances.
    current_sync_committee_branch*:
      array[log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX), Eth2Digest]

  LightClientDatabase* = object
    cachedData*: Table[BlockId, CachedLightClientData]
      ## Cached data for creating future `LightClientUpdate` instances.
      ## Key is the block ID of which the post state was used to get the data.
      ## Data is stored for the most recent 4 finalized checkpoints, as well as
      ## for all non-finalized blocks.

    cachedBootstrap*: Table[Slot, CachedLightClientBootstrap]
      ## Cached data for creating future `LightClientBootstrap` instances.
      ## Key is the block slot of which the post state was used to get the data.
      ## Data is stored for finalized epoch boundary blocks.

    latestCheckpoints*: array[4, Checkpoint]
      ## Keeps track of the latest four `finalized_checkpoint` references
      ## leading to `finalizedHead`. Used to prune `cachedData`.
      ## Non-finalized states may only refer to these checkpoints.

    lastCheckpointIndex*: int
      ## Last index that was modified in `latestCheckpoints`.

    bestUpdates*: Table[SyncCommitteePeriod, altair.LightClientUpdate]
      ## Stores the `LightClientUpdate` with the most `sync_committee_bits` per
      ## `SyncCommitteePeriod`. Updates with a finality proof have precedence.

    pendingBestUpdates*:
      Table[(SyncCommitteePeriod, Eth2Digest), altair.LightClientUpdate]
      ## Same as `bestUpdates`, but for `SyncCommitteePeriod` with
      ## `next_sync_committee` that are not finalized. Key is `(period,
      ## hash_tree_root(current_sync_committee | next_sync_committee)`.

    latestUpdate*: altair.LightClientUpdate
      ## Tracks the `LightClientUpdate` for the latest slot. This may be older
      ## than head for empty slots or if not signed by sync committee.

    optimisticUpdate*: OptimisticLightClientUpdate
      ## Tracks the `OptimisticLightClientUpdate` for the latest slot. This may
      ## be older than head for empty slots or if not signed by sync committee.
