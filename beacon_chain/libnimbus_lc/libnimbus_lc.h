/**
 * beacon_chain
 * Copyright (c) 2023 Status Research & Development GmbH
 * Licensed and distributed under either of
 *   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
 *   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
 * at your option. This file may not be copied, modified, or distributed except according to those terms.
 */

#ifndef LIBNIMBUS_LC_H
#define LIBNIMBUS_LC_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_attribute(warn_unused_result)
#define ETH_RESULT_USE_CHECK __attribute__((warn_unused_result))
#else
#define ETH_RESULT_USE_CHECK
#endif

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

#if !__has_feature(nullability)
#define _Nonnull
#define _Nullable
#endif

/**
 * Initializes Nim & Garbage Collector. Must be called before anything else
 * of the API. Also, all following calls must come from the same thread as from
 * which this call was done.
 */
void NimMain(void);

/**
 * Cryptographically secure random number generator.
 */
typedef struct ETHRandomNumber ETHRandomNumber;

/**
 * Creates a new cryptographically secure random number generator.
 *
 * - The cryptographically secure random number generator must be destroyed
 *   with `ETHRandomNumberDestroy` once no longer needed, to release memory.
 *
 * @return Pointer to an initialized cryptographically secure random number
 *         generator context - If successful.
 * @return `NULL` - If an error occurred.
 */
ETH_RESULT_USE_CHECK
ETHRandomNumber *ETHRandomNumberCreate(void);

/**
 * Destroys a cryptographically secure random number generator.
 *
 * - The cryptographically secure random number generator
 *   must no longer be used after destruction.
 *
 * @param      rng                  Cryptographically secure random number generator.
 */
void ETHRandomNumberDestroy(ETHRandomNumber *rng);

/**
 * Ethereum Consensus Layer network configuration.
 */
typedef struct ETHConsensusConfig ETHConsensusConfig;

/**
 * Creates a new Ethereum Consensus Layer network configuration
 * based on the given `config.yaml` file content from an
 * Ethereum network definition.
 *
 * - The Ethereum Consensus Layer network configuration must be destroyed with
 *   `ETHConsensusConfigDestroy` once no longer needed, to release memory.
 *
 * @param      configFileContent    `config.yaml` file content. NULL-terminated.
 *
 * @return Pointer to an initialized Ethereum Consensus Layer network configuration
 *         based on the given `config.yaml` file content - If successful.
 * @return `NULL` - If the given `config.yaml` is malformed or incompatible.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/configs/README.md
 */
ETH_RESULT_USE_CHECK
ETHConsensusConfig *ETHConsensusConfigCreateFromYaml(const char *configFileContent);

/**
 * Destroys an Ethereum Consensus Layer network configuration.
 *
 * - The Ethereum Consensus Layer network configuration
 *   must no longer be used after destruction.
 *
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 */
void ETHConsensusConfigDestroy(ETHConsensusConfig *cfg);

/**
 * Returns the expected `Eth-Consensus-Version` for a given `epoch`.
 *
 * - The returned `Eth-Consensus-Version` is statically allocated.
 *   It must neither be released nor written to.
 *
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      epoch                Epoch number for which to obtain `Eth-Consensus-Version`
 *
 * @return Expected `Eth-Consensus-Version` for the given `epoch`. NULL-terminated.
 *
 * @see https://github.com/ethereum/beacon-APIs/blob/v2.4.1/beacon-node-oapi.yaml#L419
 */
ETH_RESULT_USE_CHECK
const char *ETHConsensusConfigGetConsensusVersionAtEpoch(const ETHConsensusConfig *cfg, int epoch);

/**
 * Beacon state.
 */
typedef struct ETHBeaconState ETHBeaconState;

/**
 * Creates a new beacon state based on its SSZ encoded representation.
 *
 * - The beacon state must be destroyed with `ETHBeaconStateDestroy`
 *   once no longer needed, to release memory.
 *
 * - When loading a `genesis.ssz` file from an Ethereum network definition,
 *   use `ETHConsensusConfigGetConsensusVersionAtEpoch` with `epoch = 0`
 *   to determine the correct `consensusVersion`.
 *
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      consensusVersion     `Eth-Consensus-Version` for the given `sszBytes`.
 * @param      sszBytes             Buffer with SSZ encoded beacon state representation.
 * @param      numSszBytes          Length of buffer.
 *
 * @return Pointer to an initialized beacon state based on the given SSZ encoded
 *         representation - If successful.
 * @return `NULL` - If the given `sszBytes` is malformed.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/configs/README.md
 */
ETH_RESULT_USE_CHECK
ETHBeaconState *ETHBeaconStateCreateFromSsz(
    const ETHConsensusConfig *cfg,
    const char *consensusVersion,
    const void *sszBytes,
    int numSszBytes);

/**
 * Destroys a beacon state.
 *
 * - The beacon state must no longer be used after destruction.
 *
 * @param      state                Beacon state.
 */
void ETHBeaconStateDestroy(ETHBeaconState *state);

/**
 * Merkle root.
 */
typedef struct {
    uint8_t bytes[32];
} ETHRoot;

/**
 * Copies the `genesis_validators_root` field from a beacon state.
 *
 * - The genesis validators root must be destroyed with `ETHRootDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      state                Beacon state.
 *
 * @return Pointer to a copy of the given beacon state's genesis validators root.
 */
ETH_RESULT_USE_CHECK
ETHRoot *ETHBeaconStateCopyGenesisValidatorsRoot(const ETHBeaconState *state);

/**
 * Destroys a Merkle root.
 *
 * - The Merkle root must no longer be used after destruction.
 *
 * @param      root                 Merkle root.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#custom-types
 */
void ETHRootDestroy(ETHRoot *root);

/**
 * Fork digests cache.
 */
typedef struct ETHForkDigests ETHForkDigests;

/**
 * Creates a fork digests cache for a given beacon state.
 *
 * - The fork digests cache must be destroyed with `ETHForkDigestsDestroy`
 *    once no longer needed, to release memory.
 *
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      state                Beacon state.
 *
 * @return Pointer to an initialized fork digests cache based on the beacon state.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_fork_digest
 */
ETH_RESULT_USE_CHECK
ETHForkDigests *ETHForkDigestsCreateFromState(
    const ETHConsensusConfig *cfg, const ETHBeaconState *state);

/**
 * Destroys a fork digests cache.
 *
 * - The fork digests cache must no longer be used after destruction.
 *
 * @param      forkDigests          Fork digests cache.
 */
void ETHForkDigestsDestroy(ETHForkDigests *forkDigests);

/**
 * Beacon clock.
 */
typedef struct ETHBeaconClock ETHBeaconClock;

/**
 * Creates a beacon clock for a given beacon state's `genesis_time` field.
 *
 * - The beacon clock must be destroyed with `ETHBeaconClockDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      state                Beacon state.
 *
 * @return Pointer to an initialized beacon clock based on the beacon state.
 */
ETH_RESULT_USE_CHECK
ETHBeaconClock *ETHBeaconClockCreateFromState(const ETHBeaconState *state);

/**
 * Destroys a beacon clock.
 *
 * - The beacon clock must no longer be used after destruction.
 *
 * @param      beaconClock          Beacon clock.
 */
void ETHBeaconClockDestroy(ETHBeaconClock *beaconClock);

/**
 * Indicates the slot number for the current wall clock time.
 *
 * @param      beaconClock          Beacon clock.
 *
 * @return Slot number for the current wall clock time - If genesis has occurred.
 * @return `0` - If genesis is still pending.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#custom-types
 */
ETH_RESULT_USE_CHECK
int ETHBeaconClockGetSlot(const ETHBeaconClock *beaconClock);

/**
 * Light client store.
 */
typedef struct ETHLightClientStore ETHLightClientStore;

/**
 * Creates a light client store from light client bootstrap data.
 * The light client store is the primary object for syncing with
 * an Ethereum network.
 *
 * - To create a light client store, the Ethereum network definition
 *   including the fork schedule, `genesis_time` and `genesis_validators_root`
 *   must be known. Furthermore, a beacon block root must be assumed trusted.
 *   The trusted block root should be within the weak subjectivity period,
 *   and its root should be from a finalized `Checkpoint`.
 *
 * - The REST `/eth/v1/beacon/light_client/bootstrap/{block_root}` beacon API
 *   may be used to obtain light client bootstrap data for a given
 *   trusted block root. Setting the `Accept: application/octet-stream`
 *   HTTP header in the request selects the more compact SSZ representation.
 *
 * - After creating a light client store, `ETHLightClientStoreGetNextSyncTask`
 *   may be used to determine what further REST beacon API requests to perform
 *   for keeping the light client store in sync with the Ethereum network.
 *
 * - Once synced the REST `/eth/v1/events?topics=light_client_finality_update`
 *   `&topics=light_client_optimistic_update` beacon API provides the most
 *   recent light client data. Data from this endpoint is always JSON encoded
 *   and may be processed with `ETHLightClientStoreProcessFinalityUpdate` and
 *   `ETHLightClientStoreProcessOptimisticUpdate`.
 *
 * - The light client store must be destroyed with
 *   `ETHLightClientStoreDestroy` once no longer needed, to release memory.
 *
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      trustedBlockRoot     Trusted block root.
 * @param      mediaType            HTTP `Content-Type` associated with `bootstrapBytes`;
 *                                  `application/json` for JSON, `application/octet-stream` for SSZ.
 * @param      consensusVersion     HTTP `Eth-Consensus-Version` response header
 *                                  associated with `bootstrapBytes`.
 * @param      bootstrapBytes       Buffer with encoded light client bootstrap data.
 * @param      numBootstrapBytes    Length of buffer.
 *
 * @return Pointer to an initialized light client store based on the given
 *         light client bootstrap data - If successful.
 * @return `NULL` - If the given `bootstrapBytes` is malformed or incompatible.
 *
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientBootstrap
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/light-client.md
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/weak-subjectivity.md#weak-subjectivity-period
 */
ETH_RESULT_USE_CHECK
ETHLightClientStore *ETHLightClientStoreCreateFromBootstrap(
    const ETHConsensusConfig *cfg,
    const ETHRoot *trustedBlockRoot,
    const char *mediaType,
    const char *consensusVersion,
    const void *bootstrapBytes,
    int numBootstrapBytes);

/**
 * Destroys a light client store.
 *
 * - The light client store must no longer be used after destruction.
 *
 * @param      store                Light client store.
 */
void ETHLightClientStoreDestroy(ETHLightClientStore *store);

/** Sync task to fulfill using `/eth/v1/beacon/light_client/updates`. */
extern int kETHLcSyncKind_UpdatesByRange;
/** Sync task to fulfill using `/eth/v1/beacon/light_client/finality_update`. */
extern int kETHLcSyncKind_FinalityUpdate;
/** Sync task to fulfill using `/eth/v1/beacon/light_client/optimistic_update`. */
extern int kETHLcSyncKind_OptimisticUpdate;

/**
 * Obtains the next task for keeping a light client store in sync
 * with the Ethereum network.
 *
 * - When using the REST beacon API to fulfill a sync task, setting the
 *   `Accept: application/octet-stream` HTTP header in the request
 *   selects the more compact SSZ representation.
 *
 * - After fetching the requested light client data and processing it with the
 *   appropriate handler, `ETHLightClientStoreGetMillisecondsToNextSyncTask`
 *   may be used to obtain a delay until a new sync task becomes available.
 *   Once the delay is reached, call `ETHLightClientStoreGetNextSyncTask`
 *   again to obtain the next sync task.
 *
 * - Once synced the REST `/eth/v1/events?topics=light_client_finality_update`
 *   `&topics=light_client_optimistic_update` beacon API provides the most
 *   recent light client data. Data from this endpoint is always JSON encoded
 *   and may be processed with `ETHLightClientStoreProcessFinalityUpdate` and
 *   `ETHLightClientStoreProcessOptimisticUpdate`. Events may be processed at
 *   any time and do not require re-computing the delay until next sync task
 *   with `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
 *
 * @param      store                Light client store.
 * @param      beaconClock          Beacon clock.
 * @param[out] startPeriod          `start_period` query parameter, if applicable.
 * @param[out] count                `count` query parameter, if applicable.
 *
 * @return `kETHLcSyncKind_UpdatesByRange` - If the next sync task is fulfillable
 *         using REST `/eth/v1/beacon/light_client/updates` beacon API.
 *         The `startPeriod` and `count` parameters are filled, and to be passed to
 *         `/eth/v1/beacon/light_client/updates?start_period={startPeriod}`
 *         `&count={count}`.
 *         Process the response with `ETHLightClientStoreProcessUpdatesByRange`.
 * @return `kETHLcSyncKind_FinalityUpdate` - If the next sync task is fulfillable
 *         using REST `/eth/v1/beacon/light_client/finality_update` beacon API.
 *         Process the response with `ETHLightClientStoreProcessFinalityUpdate`.
 *         The `startPeriod` and `count` parameters are unused for this sync task.
 * @return `kETHLcSyncKind_OptimisticUpdate` - If the next sync task is fulfillable
 *         using REST `/eth/v1/beacon/light_client/optimistic_update` beacon API.
 *         Process the response with `ETHLightClientStoreProcessOptimisticUpdate`.
 *         The `startPeriod` and `count` parameters are unused for this sync task.
 *
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientUpdatesByRange
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientFinalityUpdate
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientOptimisticUpdate
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
 */
ETH_RESULT_USE_CHECK
int ETHLightClientStoreGetNextSyncTask(
    const ETHLightClientStore *store,
    const ETHBeaconClock *beaconClock,
    int *startPeriod,
    int *count);

/**
 * Indicates the delay until a new light client sync task becomes available.
 * Once the delay is reached, call `ETHLightClientStoreGetNextSyncTask`
 * to obtain the next sync task.
 *
 * @param      store                Light client store.
 * @param      rng                  Cryptographically secure random number generator.
 * @param      beaconClock          Beacon clock.
 * @param      latestProcessResult  Latest sync task processing result, i.e.,
 *                                  the return value of `ETHLightClientStoreProcessUpdatesByRange`,
 *                                  `ETHLightClientStoreProcessFinalityUpdate`, or
 *                                  `ETHLightClientStoreProcessOptimisticUpdate`, for latest task.
 *                                  If the data for the sync task could not be fetched, set to `1`.
 *
 * @return Number of milliseconds until `ETHLightClientStoreGetNextSyncTask`
 *         should be called again to obtain the next light client sync task.
 */
ETH_RESULT_USE_CHECK
int ETHLightClientStoreGetMillisecondsToNextSyncTask(
    const ETHLightClientStore *store,
    ETHRandomNumber *rng,
    const ETHBeaconClock *beaconClock,
    int latestProcessResult);

/**
 * Processes light client update data.
 *
 * - This processes the response data for a sync task of kind
 *   `kETHLcSyncKind_UpdatesByRange`, as indicated by
 *   `ETHLightClientStoreGetNextSyncTask`. After processing, call
 *   `ETHLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
 *   until a new sync task becomes available.
 *
 * @param      store                Light client store.
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      forkDigests          Fork digests cache.
 * @param      genesisValRoot       Genesis validators root.
 * @param      beaconClock          Beacon clock.
 * @param      startPeriod          `startPeriod` parameter associated with the sync task.
 * @param      count                `count` parameter associated with the sync task.
 * @param      mediaType            HTTP `Content-Type` associated with `updatesBytes`;
 *                                  `application/json` for JSON, `application/octet-stream` for SSZ.
 * @param      updatesBytes         Buffer with encoded light client update data.
 * @param      numUpdatesBytes      Length of buffer.
 *
 * @return `0` - If the given `updatesBytes` is valid and sync did progress.
 * @return `1` - If the given `updatesBytes` is malformed or incompatible.
 * @return `2` - If the given `updatesBytes` did not advance sync progress.
 *
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientUpdatesByRange
 */
ETH_RESULT_USE_CHECK
int ETHLightClientStoreProcessUpdatesByRange(
    const ETHLightClientStore *store,
    const ETHConsensusConfig *cfg,
    const ETHForkDigests *forkDigests,
    const ETHRoot *genesisValRoot,
    const ETHBeaconClock *beaconClock,
    int startPeriod,
    int count,
    const char *mediaType,
    const void *updatesBytes,
    int numUpdatesBytes);

/**
 * Processes light client finality update data.
 *
 * - This processes the response data for a sync task of kind
 *   `kETHLcSyncKind_FinalityUpdate`, as indicated by
 *   `ETHLightClientStoreGetNextSyncTask`. After processing, call
 *   `ETHLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
 *   until a new sync task becomes available.
 *
 * - This also processes event data from the REST
 *   `/eth/v1/events?topics=light_client_finality_update` beacon API.
 *   Set `mediaType` to `application/json`, and `consensusVersion` to `NULL`.
 *   Events may be processed at any time, it is not necessary to call
 *   `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
 *
 * @param      store                Light client store.
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      forkDigests          Fork digests cache.
 * @param      genesisValRoot       Genesis validators root.
 * @param      beaconClock          Beacon clock.
 * @param      mediaType            HTTP `Content-Type` associated with `finUpdateBytes`;
 *                                  `application/json` for JSON, `application/octet-stream` for SSZ.
 * @param      consensusVersion     HTTP `Eth-Consensus-Version` response header
 *                                  associated with `finUpdateBytes`. `NULL` when processing event.
 * @param      finUpdateBytes       Buffer with encoded finality update data.
 * @param      numFinUpdateBytes    Length of buffer.
 *
 * @return `0` - If the given `finUpdateBytes` is valid and sync did progress.
 * @return `1` - If the given `finUpdateBytes` is malformed or incompatible.
 * @return `2` - If the given `finUpdateBytes` did not advance sync progress.
 *
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientFinalityUpdate
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
 */
ETH_RESULT_USE_CHECK
int ETHLightClientStoreProcessFinalityUpdate(
    const ETHLightClientStore *store,
    const ETHConsensusConfig *cfg,
    const ETHForkDigests *forkDigests,
    const ETHRoot *genesisValRoot,
    const ETHBeaconClock *beaconClock,
    const char *mediaType,
    const char *_Nullable consensusVersion,
    const void *finUpdateBytes,
    int numFinUpdateBytes);

/**
 * Processes light client optimistic update data.
 *
 * - This processes the response data for a sync task of kind
 *   `kETHLcSyncKind_OptimisticUpdate`, as indicated by
 *   `ETHLightClientStoreGetNextSyncTask`. After processing, call
 *   `ETHLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
 *   until a new sync task becomes available.
 *
 * - This also processes event data from the REST
 *   `/eth/v1/events?topics=light_client_optimistic_update` beacon API.
 *   Set `mediaType` to `application/json`, and `consensusVersion` to `NULL`.
 *   Events may be processed at any time, it is not necessary to call
 *   `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
 *
 * @param      store                Light client store.
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      forkDigests          Fork digests cache.
 * @param      genesisValRoot       Genesis validators root.
 * @param      beaconClock          Beacon clock.
 * @param      mediaType            HTTP `Content-Type` associated with `optUpdateBytes`;
 *                                  `application/json` for JSON, `application/octet-stream` for SSZ.
 * @param      consensusVersion     HTTP `Eth-Consensus-Version` response header
 *                                  associated with `optUpdateBytes`. `NULL` when processing event.
 * @param      optUpdateBytes       Buffer with encoded optimistic update data.
 * @param      numOptUpdateBytes    Length of buffer.
 *
 * @return `0` - If the given `optUpdateBytes` is valid and sync did progress.
 * @return `1` - If the given `optUpdateBytes` is malformed or incompatible.
 * @return `2` - If the given `optUpdateBytes` did not advance sync progress.
 *
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientOptimisticUpdate
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
 */
ETH_RESULT_USE_CHECK
int ETHLightClientStoreProcessOptimisticUpdate(
    const ETHLightClientStore *store,
    const ETHConsensusConfig *cfg,
    const ETHForkDigests *forkDigests,
    const ETHRoot *genesisValRoot,
    const ETHBeaconClock *beaconClock,
    const char *mediaType,
    const char *_Nullable consensusVersion,
    const void *optUpdateBytes,
    int numOptUpdateBytes);

/**
 * Light client header.
 */
typedef struct ETHLightClientHeader ETHLightClientHeader;

/**
 * Obtains the latest finalized header of a given light client store.
 *
 * - The returned value is allocated in the given light client store.
 *   It must neither be released nor written to, and the light client store
 *   must not be released while the returned value is in use.
 *
 * @param      store                Light client store.
 *
 * @return Latest finalized header.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
 */
ETH_RESULT_USE_CHECK
const ETHLightClientHeader *ETHLightClientStoreGetFinalizedHeader(
    const ETHLightClientStore *store);

/**
 * Indicates whether or not the next sync committee is currently known.
 *
 * - The light client sync process ensures that the next sync committee
 *   is obtained in time, before it starts signing light client data.
 *   To stay in sync, use `ETHLightClientStoreGetNextSyncTask` and
 *   `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
 *
 * @param      store                Light client store.
 *
 * @return Whether or not the next sync committee is currently known.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#is_next_sync_committee_known
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/light-client.md
 */
ETH_RESULT_USE_CHECK
bool ETHLightClientStoreIsNextSyncCommitteeKnown(const ETHLightClientStore *store);

/**
 * Obtains the latest optimistic header of a given light client store.
 *
 * - The returned value is allocated in the given light client store.
 *   It must neither be released nor written to, and the light client store
 *   must not be released while the returned value is in use.
 *
 * @param      store                Light client store.
 *
 * @return Latest optimistic header.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
 */
ETH_RESULT_USE_CHECK
const ETHLightClientHeader *ETHLightClientStoreGetOptimisticHeader(
    const ETHLightClientStore *store);

/**
 * Calculates the safety threshold for a given light client store.
 *
 * - Light client data can only update the optimistic header if it is signed
 *   by more sync committee participants than the safety threshold indicates.
 *
 * - The finalized header is not affected by the safety threshold;
 *   light client data can only update the finalized header if it is signed
 *   by a supermajority of the sync committee, regardless of safety threshold.
 *
 * @param      store                Light client store.
 *
 * @return Light client store safety threshold.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#get_safety_threshold
 */
ETH_RESULT_USE_CHECK
int ETHLightClientStoreGetSafetyThreshold(const ETHLightClientStore *store);

/**
 * Creates a shallow copy of a given light client header.
 *
 * - The copy must be destroyed with `ETHLightClientHeaderDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      header               Light client header.
 *
 * @return Pointer to a shallow copy of the given header.
 */
ETH_RESULT_USE_CHECK
ETHLightClientHeader *ETHLightClientHeaderCreateCopy(const ETHLightClientHeader *header);

/**
 * Destroys a light client header.
 *
 * - The light client header must no longer be used after destruction.
 *
 * @param      header               Light client header.
 */
void ETHLightClientHeaderDestroy(ETHLightClientHeader *header);

/**
 * Computes the beacon block Merkle root for a given light client header.
 *
 * - The Merkle root must be destroyed with `ETHRootDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      header               Light client header.
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 *
 * @return Pointer to a copy of the given header's beacon block root.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#hash_tree_root
 */
ETH_RESULT_USE_CHECK
ETHRoot *ETHLightClientHeaderCopyBeaconRoot(
    const ETHLightClientHeader *header,
    const ETHConsensusConfig *cfg);

/**
 * Beacon block header.
 */
typedef struct ETHBeaconBlockHeader ETHBeaconBlockHeader;

/**
 * Obtains the beacon block header of a given light client header.
 *
 * - The returned value is allocated in the given light client header.
 *   It must neither be released nor written to, and the light client header
 *   must not be released while the returned value is in use.
 *
 * @param      header               Light client header.
 *
 * @return Beacon block header.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beaconblockheader
 */
ETH_RESULT_USE_CHECK
const ETHBeaconBlockHeader *ETHLightClientHeaderGetBeacon(
    const ETHLightClientHeader *header);

/**
 * Obtains the slot number of a given beacon block header.
 *
 * @param      beacon               Beacon block header.
 *
 * @return Slot number.
 */
ETH_RESULT_USE_CHECK
int ETHBeaconBlockHeaderGetSlot(const ETHBeaconBlockHeader *beacon);

/**
 * Obtains the proposer validator registry index
 * of a given beacon block header.
 *
 * @param      beacon               Beacon block header.
 *
 * @return Proposer validator registry index.
 */
ETH_RESULT_USE_CHECK
int ETHBeaconBlockHeaderGetProposerIndex(const ETHBeaconBlockHeader *beacon);

/**
 * Obtains the parent beacon block Merkle root of a given beacon block header.
 *
 * - The returned value is allocated in the given beacon block header.
 *   It must neither be released nor written to, and the beacon block header
 *   must not be released while the returned value is in use.
 *
 * @param      beacon               Beacon block header.
 *
 * @return Parent beacon block root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHBeaconBlockHeaderGetParentRoot(const ETHBeaconBlockHeader *beacon);

/**
 * Obtains the beacon state Merkle root of a given beacon block header.
 *
 * - The returned value is allocated in the given beacon block header.
 *   It must neither be released nor written to, and the beacon block header
 *   must not be released while the returned value is in use.
 *
 * @param      beacon               Beacon block header.
 *
 * @return Beacon state root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHBeaconBlockHeaderGetStateRoot(const ETHBeaconBlockHeader *beacon);

/**
 * Obtains the beacon block body Merkle root of a given beacon block header.
 *
 * - The returned value is allocated in the given beacon block header.
 *   It must neither be released nor written to, and the beacon block header
 *   must not be released while the returned value is in use.
 *
 * @param      beacon               Beacon block header.
 *
 * @return Beacon block body root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHBeaconBlockHeaderGetBodyRoot(const ETHBeaconBlockHeader *beacon);

/**
 * Computes the execution block hash for a given light client header.
 *
 * - The hash must be destroyed with `ETHRootDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      header               Light client header.
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 *
 * @return Pointer to a copy of the given header's execution block hash.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#executionpayloadheader
 */
ETH_RESULT_USE_CHECK
ETHRoot *ETHLightClientHeaderCopyExecutionHash(
    const ETHLightClientHeader *header,
    const ETHConsensusConfig *cfg);

/**
 * Execution payload header.
 */
typedef struct ETHExecutionPayloadHeader ETHExecutionPayloadHeader;

/**
 * Obtains the execution payload header of a given light client header.
 *
 * - The returned value is allocated in the given light client header.
 *   It must neither be released nor written to, and the light client header
 *   must not be released while the returned value is in use.
 *
 * @param      header               Light client header.
 *
 * @return Execution payload header.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#executionpayloadheader
 */
ETH_RESULT_USE_CHECK
const ETHExecutionPayloadHeader *ETHLightClientHeaderGetExecution(
    const ETHLightClientHeader *header);

/**
 * Obtains the parent execution block hash of a given
 * execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Parent execution block hash.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHExecutionPayloadHeaderGetParentHash(
    const ETHExecutionPayloadHeader *execution);

/**
 * Execution address.
 */
typedef struct {
    uint8_t bytes[20];
} ETHExecutionAddress;

/**
 * Obtains the fee recipient address of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Fee recipient execution address.
 */
ETH_RESULT_USE_CHECK
const ETHExecutionAddress *ETHExecutionPayloadHeaderGetFeeRecipient(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the state MPT root of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution state root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHExecutionPayloadHeaderGetStateRoot(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the receipts MPT root of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution receipts root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHExecutionPayloadHeaderGetReceiptsRoot(
    const ETHExecutionPayloadHeader *execution);

/**
 * Execution logs Bloom.
 */
typedef struct {
    uint8_t bytes[256];
} ETHLogsBloom;

/**
 * Obtains the logs Bloom of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution logs Bloom.
 */
ETH_RESULT_USE_CHECK
const ETHLogsBloom *ETHExecutionPayloadHeaderGetLogsBloom(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the previous randao mix of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Previous randao mix.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHExecutionPayloadHeaderGetPrevRandao(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the execution block number of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution block number.
 */
ETH_RESULT_USE_CHECK
int ETHExecutionPayloadHeaderGetBlockNumber(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the gas limit of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Gas limit.
 */
ETH_RESULT_USE_CHECK
int ETHExecutionPayloadHeaderGetGasLimit(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the gas used of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Gas used.
 */
ETH_RESULT_USE_CHECK
int ETHExecutionPayloadHeaderGetGasUsed(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the timestamp of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution block timestamp.
 */
ETH_RESULT_USE_CHECK
int ETHExecutionPayloadHeaderGetTimestamp(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the extra data buffer of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 * @param[out] numBytes             Length of buffer.
 *
 * @return Buffer with execution block extra data.
 */
ETH_RESULT_USE_CHECK
const void *ETHExecutionPayloadHeaderGetExtraDataBytes(
    const ETHExecutionPayloadHeader *execution,
    int *numBytes);

/**
 * UInt256 (little-endian)
 */
typedef struct {
    uint8_t bytes[32];
} ETHUInt256;

/**
 * Obtains the base fee per gas of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Base fee per gas.
 */
ETH_RESULT_USE_CHECK
const ETHUInt256 *ETHExecutionPayloadHeaderGetBaseFeePerGas(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the blob gas used of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Blob gas used.
 */
ETH_RESULT_USE_CHECK
int ETHExecutionPayloadHeaderGetBlobGasUsed(
    const ETHExecutionPayloadHeader *execution);

/**
 * Obtains the excess blob gas of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Excess blob gas.
 */
ETH_RESULT_USE_CHECK
int ETHExecutionPayloadHeaderGetExcessBlobGas(
    const ETHExecutionPayloadHeader *execution);

/**
 * Execution block header.
 */
typedef struct ETHExecutionBlockHeader ETHExecutionBlockHeader;

/**
 * Verifies that a JSON execution block header is valid and that it matches
 * the given `executionHash`.
 *
 * - The JSON-RPC `eth_getBlockByHash` with params `[executionHash, false]`
 *   may be used to obtain execution block header data for a given execution
 *   block hash. Pass the response's `result` property as `blockHeaderJson`.
 *
 * - The execution block header must be destroyed with
 *   `ETHExecutionBlockHeaderDestroy` once no longer needed,
 *   to release memory.
 *
 * @param      executionHash        Execution block hash.
 * @param      blockHeaderJson      Buffer with JSON encoded header. NULL-terminated.
 *
 * @return Pointer to an initialized execution block header - If successful.
 * @return `NULL` - If the given `blockHeaderJson` is malformed or incompatible.
 *
 * @see https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbyhash
 */
ETH_RESULT_USE_CHECK
ETHExecutionBlockHeader *ETHExecutionBlockHeaderCreateFromJson(
    const ETHRoot *executionHash,
    const char *blockHeaderJson);

/**
 * Destroys an execution block header.
 *
 * - The execution block header must no longer be used after destruction.
 *
 * @param      executionBlockHeader Execution block header.
 */
void ETHExecutionBlockHeaderDestroy(ETHExecutionBlockHeader *executionBlockHeader);

/**
 * Obtains the transactions MPT root of a given execution block header.
 *
 * - The returned value is allocated in the given execution block header.
 *   It must neither be released nor written to, and the execution block
 *   header must not be released while the returned value is in use.
 *
 * @param      executionBlockHeader Execution block header.
 *
 * @return Execution transactions root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHExecutionBlockHeaderGetTransactionsRoot(
    const ETHExecutionBlockHeader *executionBlockHeader);

/**
 * Obtains the withdrawals MPT root of a given execution block header.
 *
 * - The returned value is allocated in the given execution block header.
 *   It must neither be released nor written to, and the execution block
 *   header must not be released while the returned value is in use.
 *
 * @param      executionBlockHeader Execution block header.
 *
 * @return Execution withdrawals root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHExecutionBlockHeaderGetWithdrawalsRoot(
    const ETHExecutionBlockHeader *executionBlockHeader);

/**
 * Withdrawal sequence.
 */
typedef struct ETHWithdrawals ETHWithdrawals;

/**
 * Obtains the withdrawal sequence of a given execution block header.
 *
 * - The returned value is allocated in the given execution block header.
 *   It must neither be released nor written to, and the execution block
 *   header must not be released while the returned value is in use.
 *
 * @param      executionBlockHeader Execution block header.
 *
 * @return Withdrawal sequence.
 */
ETH_RESULT_USE_CHECK
const ETHWithdrawals *ETHExecutionBlockHeaderGetWithdrawals(
    const ETHExecutionBlockHeader *executionBlockHeader);

/**
 * Transaction sequence.
 */
typedef struct ETHTransactions ETHTransactions;

/**
 * Verifies that JSON transactions data is valid and that it matches
 * the given `transactionsRoot`.
 *
 * - The JSON-RPC `eth_getBlockByHash` with params `[executionHash, true]`
 *   may be used to obtain transactions data for a given execution
 *   block hash. Pass `result.transactions` as `transactionsJson`.
 *
 * - The transaction sequence must be destroyed with
 *   `ETHTransactionsDestroy` once no longer needed,
 *   to release memory.
 *
 * @param      transactionsRoot     Execution transactions root.
 * @param      transactionsJson     Buffer with JSON transactions list. NULL-terminated.
 *
 * @return Pointer to an initialized transaction sequence - If successful.
 * @return `NULL` - If the given `transactionsJson` is malformed or incompatible.
 *
 * @see https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbyhash
 */
ETH_RESULT_USE_CHECK
ETHTransactions *ETHTransactionsCreateFromJson(
    const ETHRoot *transactionsRoot,
    const char *transactionsJson);

/**
 * Destroys a transaction sequence.
 *
 * - The transaction sequence must no longer be used after destruction.
 *
 * @param      transactions         Transaction sequence.
 */
void ETHTransactionsDestroy(ETHTransactions *transactions);

/**
 * Indicates the total number of transactions in a transaction sequence.
 *
 * - Individual transactions may be inspected using `ETHTransactionsGet`.
 *
 * @param      transactions         Transaction sequence.
 *
 * @return Number of available transactions.
 */
ETH_RESULT_USE_CHECK
int ETHTransactionsGetCount(const ETHTransactions *transactions);

/**
 * Transaction.
 */
typedef struct ETHTransaction ETHTransaction;

/**
 * Obtains an individual transaction by sequential index
 * in a transaction sequence.
 *
 * - The returned value is allocated in the given transaction sequence.
 *   It must neither be released nor written to, and the transaction
 *   sequence must not be released while the returned value is in use.
 *
 * @param      transactions         Transaction sequence.
 * @param      transactionIndex     Sequential transaction index.
 *
 * @return Transaction.
 */
ETH_RESULT_USE_CHECK
const ETHTransaction *ETHTransactionsGet(
    const ETHTransactions *transactions,
    int transactionIndex);

/**
 * Obtains the transaction hash of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Transaction hash.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHTransactionGetHash(const ETHTransaction *transaction);

/**
 * Obtains the chain ID of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Chain ID.
 */
ETH_RESULT_USE_CHECK
const ETHUInt256 *ETHTransactionGetChainId(const ETHTransaction *transaction);

/**
 * Obtains the from address of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return From execution address.
 */
ETH_RESULT_USE_CHECK
const ETHExecutionAddress *ETHTransactionGetFrom(const ETHTransaction *transaction);

/**
 * Obtains the nonce of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Nonce.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHTransactionGetNonce(const ETHTransaction *transaction);

/**
 * Obtains the max priority fee per gas of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Max priority fee per gas.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHTransactionGetMaxPriorityFeePerGas(const ETHTransaction *transaction);

/**
 * Obtains the max fee per gas of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Max fee per gas.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHTransactionGetMaxFeePerGas(const ETHTransaction *transaction);

/**
 * Obtains the gas of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Gas.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHTransactionGetGas(const ETHTransaction *transaction);

/**
 * Indicates whether or not a transaction is creating a contract.
 *
 * @param      transaction          Transaction.
 *
 * @return Whether or not the transaction is creating a contract.
 */
ETH_RESULT_USE_CHECK
bool ETHTransactionIsCreatingContract(const ETHTransaction *transaction);

/**
 * Obtains the to address of a transaction.
 *
 * - If the transaction is creating a contract, this function returns
 *   the address of the new contract.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return To execution address.
 */
ETH_RESULT_USE_CHECK
const ETHExecutionAddress *ETHTransactionGetTo(const ETHTransaction *transaction);

/**
 * Obtains the value of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Value.
 */
ETH_RESULT_USE_CHECK
const ETHUInt256 *ETHTransactionGetValue(const ETHTransaction *transaction);

/**
 * Obtains the input of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 * @param[out] numBytes             Length of buffer.
 *
 * @return Buffer with input.
 */
ETH_RESULT_USE_CHECK
const void *ETHTransactionGetInputBytes(
    const ETHTransaction *transaction,
    int *numBytes);

/**
 * Transaction access list.
 */
typedef struct ETHAccessList ETHAccessList;

/**
 * Obtains the access list of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Transaction access list.
 */
ETH_RESULT_USE_CHECK
const ETHAccessList *ETHTransactionGetAccessList(const ETHTransaction *transaction);

/**
 * Indicates the total number of access tuples in a transaction access list.
 *
 * - Individual access tuples may be inspected using `ETHAccessListGet`.
 *
 * @param      accessList           Transaction access list.
 *
 * @return Number of available access tuples.
 */
ETH_RESULT_USE_CHECK
int ETHAccessListGetCount(const ETHAccessList *accessList);

/**
 * Access tuple.
 */
typedef struct ETHAccessTuple ETHAccessTuple;

/**
 * Obtains an individual access tuple by sequential index
 * in a transaction access list.
 *
 * - The returned value is allocated in the given transaction access list.
 *   It must neither be released nor written to, and the transaction
 *   access list must not be released while the returned value is in use.
 *
 * @param      accessList           Transaction access list.
 * @param      accessTupleIndex     Sequential access tuple index.
 *
 * @return Access tuple.
 */
ETH_RESULT_USE_CHECK
const ETHAccessTuple *ETHAccessListGet(
    const ETHAccessList *accessList,
    int accessTupleIndex);

/**
 * Obtains the address of an access tuple.
 *
 * - The returned value is allocated in the given access tuple.
 *   It must neither be released nor written to, and the access tuple
 *   must not be released while the returned value is in use.
 *
 * @param      accessTuple          Access tuple.
 *
 * @return Address.
 */
ETH_RESULT_USE_CHECK
const ETHExecutionAddress *ETHAccessTupleGetAddress(const ETHAccessTuple *accessTuple);

/**
 * Indicates the total number of storage keys in an access tuple.
 *
 * - Individual storage keys may be inspected using
 *   `ETHAccessTupleGetStorageKey`.
 *
 * @param      accessTuple          Access tuple.
 *
 * @return Number of available storage keys.
 */
ETH_RESULT_USE_CHECK
int ETHAccessTupleGetNumStorageKeys(const ETHAccessTuple *accessTuple);

/**
 * Obtains an individual storage key by sequential index
 * in an access tuple.
 *
 * - The returned value is allocated in the given transaction access tuple.
 *   It must neither be released nor written to, and the transaction
 *   access tuple must not be released while the returned value is in use.
 *
 * @param      accessTuple          Access tuple.
 * @param      storageKeyIndex      Sequential storage key index.
 *
 * @return Storage key.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHAccessTupleGetStorageKey(
    const ETHAccessTuple *accessTuple,
    int storageKeyIndex);

/**
 * Obtains the max fee per blob gas of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 *
 * @return Max fee per blob gas.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHTransactionGetMaxFeePerBlobGas(const ETHTransaction *transaction);

/**
 * Indicates the total number of blob versioned hashes of a transaction.
 *
 * - Individual blob versioned hashes may be inspected using
 *   `ETHTransactionGetBlobVersionedHash`.
 *
 * @param      transaction          Transaction.
 *
 * @return Number of available blob versioned hashes.
 */
ETH_RESULT_USE_CHECK
int ETHTransactionGetNumBlobVersionedHashes(const ETHTransaction *transaction);

/**
 * Obtains an individual blob versioned hash by sequential index
 * in a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 * @param      versionedHashIndex   Sequential blob versioned hash index.
 *
 * @return Blob versioned hash.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHTransactionGetBlobVersionedHash(
    const ETHTransaction *transaction,
    int versionedHashIndex);

/**
 * Obtains the signature of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 * @param[out] numBytes             Length of buffer.
 *
 * @return Buffer with signature.
 */
ETH_RESULT_USE_CHECK
const void *ETHTransactionGetSignatureBytes(
    const ETHTransaction *transaction,
    int *numBytes);

/**
 * Obtains the raw byte representation of a transaction.
 *
 * - The returned value is allocated in the given transaction.
 *   It must neither be released nor written to, and the transaction
 *   must not be released while the returned value is in use.
 *
 * @param      transaction          Transaction.
 * @param[out] numBytes             Length of buffer.
 *
 * @return Buffer with raw transaction data.
 */
ETH_RESULT_USE_CHECK
const void *ETHTransactionGetBytes(
    const ETHTransaction *transaction,
    int *numBytes);

/**
 * Receipt sequence.
 */
typedef struct ETHReceipts ETHReceipts;

/**
 * Verifies that JSON receipts data is valid and that it matches
 * the given `receiptsRoot`.
 *
 * - The JSON-RPC `eth_getTransactionReceipt` may be used to obtain
 *   receipts data for a given transaction hash. For verification, it is
 *   necessary to obtain the receipt for _all_ transactions within a block.
 *   Pass a JSON array containing _all_ receipt's `result` as `receiptsJson`.
 *   The receipts need to be in the same order as the `transactions`.
 *
 * - The receipt sequence must be destroyed with `ETHReceiptsDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      receiptsRoot         Execution receipts root.
 * @param      receiptsJson         Buffer with JSON receipts list. NULL-terminated.
 * @param      transactions         Transaction sequence.
 *
 * @return Pointer to an initialized receipt sequence - If successful.
 * @return `NULL` - If the given `receiptsJson` is malformed or incompatible.
 *
 * @see https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
 */
ETH_RESULT_USE_CHECK
ETHReceipts *ETHReceiptsCreateFromJson(
    const ETHRoot *receiptsRoot,
    const char *receiptsJson,
    const ETHTransactions *transactions);

/**
 * Destroys a receipt sequence.
 *
 * - The receipt sequence must no longer be used after destruction.
 *
 * @param      receipts             Receipt sequence.
 */
void ETHReceiptsDestroy(ETHReceipts *receipts);

/**
 * Indicates the total number of receipts in a receipt sequence.
 *
 * - Individual receipts may be inspected using `ETHReceiptsGet`.
 *
 * @param      receipts             Receipt sequence.
 *
 * @return Number of available receipts.
 */
ETH_RESULT_USE_CHECK
int ETHReceiptsGetCount(const ETHReceipts *receipts);

/**
 * Receipt.
 */
typedef struct ETHReceipt ETHReceipt;

/**
 * Obtains an individual receipt by sequential index
 * in a receipt sequence.
 *
 * - The returned value is allocated in the given receipt sequence.
 *   It must neither be released nor written to, and the receipt
 *   sequence must not be released while the returned value is in use.
 *
 * @param      receipts             Receipt sequence.
 * @param      receiptIndex         Sequential receipt index.
 *
 * @return Receipt.
 */
ETH_RESULT_USE_CHECK
const ETHReceipt *ETHReceiptsGet(
    const ETHReceipts *receipts,
    int receiptIndex);

/**
 * Indicates whether or not a receipt has a status code.
 *
 * @param      receipt              Receipt.
 *
 * @return Whether or not the receipt has a status code.
 *
 * @see https://eips.ethereum.org/EIPS/eip-658
 */
ETH_RESULT_USE_CHECK
bool ETHReceiptHasStatus(const ETHReceipt *receipt);

/**
 * Obtains the intermediate post-state root of a receipt with no status code.
 *
 * - If the receipt has a status code, this function returns a zero hash.
 *
 * - The returned value is allocated in the given receipt.
 *   It must neither be released nor written to, and the receipt
 *   must not be released while the returned value is in use.
 *
 * @param      receipt              Receipt.
 *
 * @return Intermediate post-state root.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHReceiptGetRoot(const ETHReceipt *receipt);

/**
 * Obtains the status code of a receipt with a status code.
 *
 * - If the receipt has no status code, this function returns true.
 *
 * @param      receipt              Receipt.
 *
 * @return Status code.
 *
 * @see https://eips.ethereum.org/EIPS/eip-658
 */
ETH_RESULT_USE_CHECK
bool ETHReceiptGetStatus(const ETHReceipt *receipt);

/**
 * Obtains the gas used of a receipt.
 *
 * - The returned value is allocated in the given receipt.
 *   It must neither be released nor written to, and the receipt
 *   must not be released while the returned value is in use.
 *
 * @param      receipt              Receipt.
 *
 * @return Gas used.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHReceiptGetGasUsed(const ETHReceipt *receipt);

/**
 * Obtains the logs Bloom of a receipt.
 *
 * - The returned value is allocated in the given receipt.
 *   It must neither be released nor written to, and the receipt
 *   must not be released while the returned value is in use.
 *
 * @param      receipt              Receipt.
 *
 * @return Logs Bloom.
 */
ETH_RESULT_USE_CHECK
const ETHLogsBloom *ETHReceiptGetLogsBloom(const ETHReceipt *receipt);

/**
 * Log sequence.
 */
typedef struct ETHLogs ETHLogs;

/**
 * Obtains the logs of a receipt.
 *
 * - The returned value is allocated in the given receipt.
 *   It must neither be released nor written to, and the receipt
 *   must not be released while the returned value is in use.
 *
 * @param      receipt              Receipt.
 *
 * @return Log sequence.
 */
ETH_RESULT_USE_CHECK
const ETHLogs *ETHReceiptGetLogs(const ETHReceipt *receipt);

/**
 * Indicates the total number of logs in a log sequence.
 *
 * - Individual logs may be inspected using `ETHLogsGet`.
 *
 * @param      logs                 Log sequence.
 *
 * @return Number of available logs.
 */
ETH_RESULT_USE_CHECK
int ETHLogsGetCount(const ETHLogs *logs);

/**
 * Log.
 */
typedef struct ETHLog ETHLog;

/**
 * Obtains an individual log by sequential index in a log sequence.
 *
 * - The returned value is allocated in the given log sequence.
 *   It must neither be released nor written to, and the log sequence
 *   must not be released while the returned value is in use.
 *
 * @param      logs                 Log sequence.
 * @param      logIndex             Sequential log index.
 *
 * @return Log.
 */
ETH_RESULT_USE_CHECK
const ETHLog *ETHLogsGet(
    const ETHLogs *logs,
    int logIndex);

/**
 * Obtains the address of a log.
 *
 * - The returned value is allocated in the given log.
 *   It must neither be released nor written to, and the log
 *   must not be released while the returned value is in use.
 *
 * @param      log                  Log.
 *
 * @return Address.
 */
ETH_RESULT_USE_CHECK
const ETHExecutionAddress *ETHLogGetAddress(const ETHLog *log);

/**
 * Indicates the total number of topics in a log.
 *
 * - Individual topics may be inspected using `ETHLogGetTopic`.
 *
 * @param      log                  Log.
 *
 * @return Number of available topics.
 */
ETH_RESULT_USE_CHECK
int ETHLogGetNumTopics(const ETHLog *log);

/**
 * Obtains an individual topic by sequential index in a log.
 *
 * - The returned value is allocated in the given log.
 *   It must neither be released nor written to, and the log
 *   must not be released while the returned value is in use.
 *
 * @param      log                  Log.
 * @param      topicIndex           Sequential topic index.
 *
 * @return Topic.
 */
ETH_RESULT_USE_CHECK
const ETHRoot *ETHLogGetTopic(
    const ETHLog *log,
    int topicIndex);

/**
 * Obtains the data of a log.
 *
 * - The returned value is allocated in the given log.
 *   It must neither be released nor written to, and the log
 *   must not be released while the returned value is in use.
 *
 * @param      log                  Log.
 * @param[out] numBytes             Length of buffer.
 *
 * @return Buffer with data.
 */
ETH_RESULT_USE_CHECK
const void *ETHLogGetDataBytes(
    const ETHLog *log,
    int *numBytes);

/**
 * Obtains the raw byte representation of a receipt.
 *
 * - The returned value is allocated in the given receipt.
 *   It must neither be released nor written to, and the receipt
 *   must not be released while the returned value is in use.
 *
 * @param      receipt              Receipt.
 * @param[out] numBytes             Length of buffer.
 *
 * @return Buffer with raw receipt data.
 */
ETH_RESULT_USE_CHECK
const void *ETHReceiptGetBytes(
    const ETHReceipt *receipt,
    int *numBytes);

/**
 * Indicates the total number of withdrawals in a withdrawal sequence.
 *
 * - Individual withdrawals may be inspected using `ETHWithdrawalsGet`.
 *
 * @param      withdrawals          Withdrawal sequence.
 *
 * @return Number of available withdrawals.
 */
ETH_RESULT_USE_CHECK
int ETHWithdrawalsGetCount(const ETHWithdrawals *withdrawals);

/**
 * Withdrawal.
 */
typedef struct ETHWithdrawal ETHWithdrawal;

/**
 * Obtains an individual withdrawal by sequential index
 * in a withdrawal sequence.
 *
 * - The returned value is allocated in the given withdrawal sequence.
 *   It must neither be released nor written to, and the withdrawal
 *   sequence must not be released while the returned value is in use.
 *
 * @param      withdrawals          Withdrawal sequence.
 * @param      withdrawalIndex      Sequential withdrawal index.
 *
 * @return Withdrawal.
 */
ETH_RESULT_USE_CHECK
const ETHWithdrawal *ETHWithdrawalsGet(
    const ETHWithdrawals *withdrawals,
    int withdrawalIndex);

/**
 * Obtains the index of a withdrawal.
 *
 * - The returned value is allocated in the given withdrawal.
 *   It must neither be released nor written to, and the withdrawal
 *   must not be released while the returned value is in use.
 *
 * @param      withdrawal           Withdrawal.
 *
 * @return Index.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHWithdrawalGetIndex(const ETHWithdrawal *withdrawal);

/**
 * Obtains the validator index of a withdrawal.
 *
 * - The returned value is allocated in the given withdrawal.
 *   It must neither be released nor written to, and the withdrawal
 *   must not be released while the returned value is in use.
 *
 * @param      withdrawal           Withdrawal.
 *
 * @return Validator index.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHWithdrawalGetValidatorIndex(const ETHWithdrawal *withdrawal);

/**
 * Obtains the address of a withdrawal.
 *
 * - The returned value is allocated in the given withdrawal.
 *   It must neither be released nor written to, and the withdrawal
 *   must not be released while the returned value is in use.
 *
 * @param      withdrawal           Withdrawal.
 *
 * @return Address.
 */
ETH_RESULT_USE_CHECK
const ETHExecutionAddress *ETHWithdrawalGetAddress(const ETHWithdrawal *withdrawal);

/**
 * Obtains the amount of a withdrawal.
 *
 * - The returned value is allocated in the given withdrawal.
 *   It must neither be released nor written to, and the withdrawal
 *   must not be released while the returned value is in use.
 *
 * @param      withdrawal           Withdrawal.
 *
 * @return Amount.
 */
ETH_RESULT_USE_CHECK
const uint64_t *ETHWithdrawalGetAmount(const ETHWithdrawal *withdrawal);

/**
 * Obtains the raw byte representation of a withdrawal.
 *
 * - The returned value is allocated in the given withdrawal.
 *   It must neither be released nor written to, and the withdrawal
 *   must not be released while the returned value is in use.
 *
 * @param      withdrawal           Withdrawal.
 * @param[out] numBytes             Length of buffer.
 *
 * @return Buffer with raw withdrawal data.
 */
ETH_RESULT_USE_CHECK
const void *ETHWithdrawalGetBytes(
    const ETHWithdrawal *withdrawal,
    int *numBytes);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
