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
#define ECL_RESULT_USE_CHECK __attribute__((warn_unused_result))
#else
#define ECL_RESULT_USE_CHECK
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
typedef struct ECLRandomNumber ECLRandomNumber;

/**
 * Creates a new cryptographically secure random number generator.
 *
 * - The cryptographically secure random number generator must be destroyed
 *   using `ECLRandomNumberDestroy` once no longer needed, to release memory.
 *
 * @return Pointer to an initialized cryptographically secure random number
 *         generator context - If successful.
 * @return `NULL` - If an error occurred.
 */
ECL_RESULT_USE_CHECK
ECLRandomNumber *ECLRandomNumberCreate(void);

/**
 * Destroys a cryptographically secure random number generator.
 *
 * - The cryptographically secure random number generator
 *   must no longer be used after destruction.
 *
 * @param      rng                  Cryptographically secure random number generator.
 */
void ECLRandomNumberDestroy(ECLRandomNumber *rng);

/**
 * Ethereum Consensus Layer network configuration.
 */
typedef struct ECLNetworkConfig ECLNetworkConfig;

/**
 * Creates a new Ethereum Consensus Layer network configuration
 * based on the given `config.yaml` file content from an
 * Ethereum network definition.
 *
 * - The Ethereum Consensus Layer network configuration must be destroyed
 *   using `ECLNetworkConfigDestroy` once no longer needed, to release memory.
 *
 * @param      configFileContent    `config.yaml` file content. NULL-terminated.
 *
 * @return Pointer to an initialized Ethereum Consensus Layer network configuration
 *         based on the given `config.yaml` file content - If successful.
 * @return `NULL` - If the given `config.yaml` is malformed or incompatible.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/configs/README.md
 */
ECL_RESULT_USE_CHECK
ECLNetworkConfig *ECLNetworkConfigCreateFromYaml(const char *configFileContent);

/**
 * Destroys an Ethereum Consensus Layer network configuration.
 *
 * - The Ethereum Consensus Layer network configuration
 *   must no longer be used after destruction.
 *
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 */
void ECLNetworkConfigDestroy(ECLNetworkConfig *cfg);

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
ECL_RESULT_USE_CHECK
const char *ECLNetworkConfigGetConsensusVersionAtEpoch(const ECLNetworkConfig *cfg, int epoch);

/**
 * Beacon state.
 */
typedef struct ECLBeaconState ECLBeaconState;

/**
 * Creates a new beacon state based on its SSZ encoded representation.
 *
 * - The beacon state must be destroyed using `ECLBeaconStateDestroy`
 *   once no longer needed, to release memory.
 *
 * - When loading a `genesis.ssz` file from an Ethereum network definition,
 *   use `ECLNetworkConfigGetConsensusVersionAtEpoch` with `epoch = 0`
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
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/bellatrix/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/capella/beacon-chain.md#beaconstate
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/configs/README.md
 */
ECL_RESULT_USE_CHECK
ECLBeaconState *ECLBeaconStateCreateFromSsz(
    const ECLNetworkConfig *cfg,
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
void ECLBeaconStateDestroy(ECLBeaconState *state);

/**
 * Merkle root.
 */
typedef uint8_t ECLRoot[32];

/**
 * Copies the `genesis_validators_root` field from a beacon state.
 *
 * - The genesis validators root must be destroyed using `ECLRootDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      state                Beacon state.
 *
 * @return Pointer to a copy of the given beacon state's genesis validators root.
 */
ECL_RESULT_USE_CHECK
ECLRoot *ECLBeaconStateCopyGenesisValidatorsRoot(const ECLBeaconState *state);

/**
 * Destroys a Merkle root.
 *
 * - The Merkle root must no longer be used after destruction.
 *
 * @param      root                 Merkle root.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#custom-types
 */
void ECLRootDestroy(ECLRoot *root);

/**
 * Fork digests cache.
 */
typedef struct ECLForkDigests ECLForkDigests;

/**
 * Creates a fork digests cache for a given beacon state.
 *
 * - The fork digests cache must be destroyed using `ECLForkDigestsDestroy`
 *    once no longer needed, to release memory.
 *
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 * @param      state                Beacon state.
 *
 * @return Pointer to an initialized fork digests cache based on the beacon state.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#compute_fork_digest
 */
ECL_RESULT_USE_CHECK
ECLForkDigests *ECLForkDigestsCreateFromState(
    const ECLNetworkConfig *cfg, const ECLBeaconState *state);

/**
 * Destroys a fork digests cache.
 *
 * - The fork digests cache must no longer be used after destruction.
 *
 * @param      forkDigests          Fork digests cache.
 */
void ECLForkDigestsDestroy(ECLForkDigests *forkDigests);

/**
 * Beacon clock.
 */
typedef struct ECLBeaconClock ECLBeaconClock;

/**
 * Creates a beacon clock for a given beacon state's `genesis_time` field.
 *
 * - The beacon clock must be destroyed using `ECLBeaconClockDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      state                Beacon state.
 *
 * @return Pointer to an initialized beacon clock based on the beacon state.
 */
ECL_RESULT_USE_CHECK
ECLBeaconClock *ECLBeaconClockCreateFromState(const ECLBeaconState *state);

/**
 * Destroys a beacon clock.
 *
 * - The beacon clock must no longer be used after destruction.
 *
 * @param      beaconClock          Beacon clock.
 */
void ECLBeaconClockDestroy(ECLBeaconClock *beaconClock);

/**
 * Indicates the slot number for the current wall clock time.
 *
 * @param      beaconClock          Beacon clock.
 *
 * @return Slot number for the current wall clock time - If genesis has occurred.
 * @return `0` - If genesis is still pending.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#custom-types
 */
ECL_RESULT_USE_CHECK
int ECLBeaconClockGetSlot(const ECLBeaconClock *beaconClock);

/**
 * Light client store.
 */
typedef struct ECLLightClientStore ECLLightClientStore;

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
 * - After creating a light client store, `ECLLightClientStoreGetNextSyncTask`
 *   may be used to determine what further REST beacon API requests to perform
 *   for keeping the light client store in sync with the Ethereum network.
 *
 * - Once synced the REST `/eth/v1/events?topics=light_client_finality_update`
 *   `&topics=light_client_optimistic_update` beacon API provides the most
 *   recent light client data. Data from this endpoint is always JSON encoded
 *   and may be processed with `ECLLightClientStoreProcessFinalityUpdate` and
 *   `ECLLightClientStoreProcessOptimisticUpdate`.
 *
 * - The light client store must be destroyed using
 *   `ECLLightClientStoreDestroy` once no longer needed, to release memory.
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
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/light-client.md
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/weak-subjectivity.md#weak-subjectivity-period
 */
ECL_RESULT_USE_CHECK
ECLLightClientStore *ECLLightClientStoreCreateFromBootstrap(
    const ECLNetworkConfig *cfg,
    const ECLRoot *trustedBlockRoot,
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
void ECLLightClientStoreDestroy(ECLLightClientStore *store);

/** Sync task to fulfill using `/eth/v1/beacon/light_client/updates`. */
extern int kECLLcSyncKind_UpdatesByRange;
/** Sync task to fulfill using `/eth/v1/beacon/light_client/finality_update`. */
extern int kECLLcSyncKind_FinalityUpdate;
/** Sync task to fulfill using `/eth/v1/beacon/light_client/optimistic_update`. */
extern int kECLLcSyncKind_OptimisticUpdate;

/**
 * Obtains the next task for keeping a light client store in sync
 * with the Ethereum network.
 *
 * - When using the REST beacon API to fulfill a sync task, setting the
 *   `Accept: application/octet-stream` HTTP header in the request
 *   selects the more compact SSZ representation.
 *
 * - After fetching the requested light client data and processing it with the
 *   appropriate handler, `ECLLightClientStoreGetMillisecondsToNextSyncTask`
 *   may be used to obtain a delay until a new sync task becomes available.
 *   Once the delay is reached, call `ECLLightClientStoreGetNextSyncTask`
 *   again to obtain the next sync task.
 *
 * - Once synced the REST `/eth/v1/events?topics=light_client_finality_update`
 *   `&topics=light_client_optimistic_update` beacon API provides the most
 *   recent light client data. Data from this endpoint is always JSON encoded
 *   and may be processed with `ECLLightClientStoreProcessFinalityUpdate` and
 *   `ECLLightClientStoreProcessOptimisticUpdate`. Events may be processed at
 *   any time and do not require re-computing the delay until next sync task
 *   with `ECLLightClientStoreGetMillisecondsToNextSyncTask`.
 *
 * @param      store                Light client store.
 * @param      beaconClock          Beacon clock.
 * @param[out] startPeriod          `start_period` query parameter, if applicable.
 * @param[out] count                `count` query parameter, if applicable.
 *
 * @return `kECLLcSyncKind_UpdatesByRange` - If the next sync task is fulfillable
 *         using REST `/eth/v1/beacon/light_client/updates` beacon API.
 *         The `startPeriod` and `count` parameters contain additional request info.
 *         `/eth/v1/beacon/light_client/updates?start_period={startPeriod}`
 *         `&count={count}`.
 *         Process the response with `ECLLightClientStoreProcessUpdatesByRange`.
 * @return `kECLLcSyncKind_FinalityUpdate` - If the next sync task is fulfillable
 *         using REST `/eth/v1/beacon/light_client/finality_update` beacon API.
 *         Process the response with `ECLLightClientStoreProcessFinalityUpdate`.
 *         The `startPeriod` and `count` parameters are unused for this sync task.
 * @return `kECLLcSyncKind_OptimisticUpdate` - If the next sync task is fulfillable
 *         using REST `/eth/v1/beacon/light_client/optimistic_update` beacon API.
 *         Process the response with `ECLLightClientStoreProcessOptimisticUpdate`.
 *         The `startPeriod` and `count` parameters are unused for this sync task.
 *
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientUpdatesByRange
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientFinalityUpdate
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientOptimisticUpdate
 * @see https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
 */
ECL_RESULT_USE_CHECK
int ECLLightClientStoreGetNextSyncTask(
    const ECLLightClientStore *store,
    const ECLBeaconClock *beaconClock,
    int *startPeriod,
    int *count);

/**
 * Indicates the delay until a new light client sync task becomes available.
 * Once the delay is reached, call `ECLLightClientStoreGetNextSyncTask`
 * to obtain the next sync task.
 *
 * @param      store                Light client store.
 * @param      rng                  Cryptographically secure random number generator.
 * @param      beaconClock          Beacon clock.
 * @param      latestProcessResult  Latest sync task processing result, i.e.,
 *                                  the return value of `ECLLightClientStoreProcessUpdatesByRange`,
 *                                  `ECLLightClientStoreProcessFinalityUpdate`, or
 *                                  `ECLLightClientStoreProcessOptimisticUpdate`, for latest task.
 *                                  If the data for the sync task could not be fetched, set to `1`.
 *
 * @return Number of milliseconds until `ECLLightClientStoreGetNextSyncTask`
 *         should be called again to obtain the next light client sync task.
 */
ECL_RESULT_USE_CHECK
int ECLLightClientStoreGetMillisecondsToNextSyncTask(
    const ECLLightClientStore *store,
    ECLRandomNumber *rng,
    const ECLBeaconClock *beaconClock,
    int latestProcessResult);

/**
 * Processes light client update data.
 *
 * - This processes the response data for a sync task of kind
 *   `kECLLcSyncKind_UpdatesByRange`, as indicated by
 *   `ECLLightClientStoreGetNextSyncTask`. After processing, call
 *   `ECLLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
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
ECL_RESULT_USE_CHECK
int ECLLightClientStoreProcessUpdatesByRange(
    const ECLLightClientStore *store,
    const ECLNetworkConfig *cfg,
    const ECLForkDigests *forkDigests,
    const ECLRoot *genesisValRoot,
    const ECLBeaconClock *beaconClock,
    int startPeriod,
    int count,
    const char *mediaType,
    const void *updatesBytes,
    int numUpdatesBytes);

/**
 * Processes light client finality update data.
 *
 * - This processes the response data for a sync task of kind
 *   `kECLLcSyncKind_FinalityUpdate`, as indicated by
 *   `ECLLightClientStoreGetNextSyncTask`. After processing, call
 *   `ECLLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
 *   until a new sync task becomes available.
 *
 * - This also processes event data from the REST
 *   `/eth/v1/events?topics=light_client_finality_update` beacon API.
 *   Set `mediaType` to `application/json`, and `consensusVersion` to `NULL`.
 *   Events may be processed at any time, it is not necessary to call
 *   `ECLLightClientStoreGetMillisecondsToNextSyncTask`.
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
ECL_RESULT_USE_CHECK
int ECLLightClientStoreProcessFinalityUpdate(
    const ECLLightClientStore *store,
    const ECLNetworkConfig *cfg,
    const ECLForkDigests *forkDigests,
    const ECLRoot *genesisValRoot,
    const ECLBeaconClock *beaconClock,
    const char *mediaType,
    const char *_Nullable consensusVersion,
    const void *finUpdateBytes,
    int numFinUpdateBytes);

/**
 * Processes light client optimistic update data.
 *
 * - This processes the response data for a sync task of kind
 *   `kECLLcSyncKind_OptimisticUpdate`, as indicated by
 *   `ECLLightClientStoreGetNextSyncTask`. After processing, call
 *   `ECLLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
 *   until a new sync task becomes available.
 *
 * - This also processes event data from the REST
 *   `/eth/v1/events?topics=light_client_optimistic_update` beacon API.
 *   Set `mediaType` to `application/json`, and `consensusVersion` to `NULL`.
 *   Events may be processed at any time, it is not necessary to call
 *   `ECLLightClientStoreGetMillisecondsToNextSyncTask`.
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
ECL_RESULT_USE_CHECK
int ECLLightClientStoreProcessOptimisticUpdate(
    const ECLLightClientStore *store,
    const ECLNetworkConfig *cfg,
    const ECLForkDigests *forkDigests,
    const ECLRoot *genesisValRoot,
    const ECLBeaconClock *beaconClock,
    const char *mediaType,
    const char *_Nullable consensusVersion,
    const void *optUpdateBytes,
    int numOptUpdateBytes);

/**
 * Light client header.
 */
typedef struct ECLLightClientHeader ECLLightClientHeader;

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
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
 */
ECL_RESULT_USE_CHECK
const ECLLightClientHeader *ECLLightClientStoreGetFinalizedHeader(
    const ECLLightClientStore *store);

/**
 * Indicates whether or not the next sync committee is currently known.
 *
 * - The light client sync process ensures that the next sync committee
 *   is obtained in time, before it starts signing light client data.
 *   To stay in sync, use `ECLLightClientStoreGetNextSyncTask` and
 *   `ECLLightClientStoreGetMillisecondsToNextSyncTask`.
 *
 * @param      store                Light client store.
 *
 * @return Whether or not the next sync committee is currently known.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/sync-protocol.md#is_next_sync_committee_known
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/light-client.md
 */
ECL_RESULT_USE_CHECK
bool ECLLightClientStoreIsNextSyncCommitteeKnown(const ECLLightClientStore *store);

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
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
 */
ECL_RESULT_USE_CHECK
const ECLLightClientHeader *ECLLightClientStoreGetOptimisticHeader(
    const ECLLightClientStore *store);

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
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/sync-protocol.md#get_safety_threshold
 */
ECL_RESULT_USE_CHECK
int ECLLightClientStoreGetSafetyThreshold(const ECLLightClientStore *store);

/**
 * Computes the beacon block Merkle root for a given light client header.
 *
 * - The Merkle root must be destroyed using `ECLRootDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      header               Light client header.
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 *
 * @return Pointer to a copy of the given header's beacon block root.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#hash_tree_root
 */
ECL_RESULT_USE_CHECK
ECLRoot *ECLLightClientHeaderCopyBeaconRoot(
    const ECLLightClientHeader *header,
    const ECLNetworkConfig *cfg);

/**
 * Beacon block header.
 */
typedef struct ECLBeaconBlockHeader ECLBeaconBlockHeader;

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
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#beaconblockheader
 */
ECL_RESULT_USE_CHECK
const ECLBeaconBlockHeader *ECLLightClientHeaderGetBeacon(
    const ECLLightClientHeader *header);

/**
 * Obtains the slot number of a given beacon block header.
 *
 * @param      beacon               Beacon block header.
 *
 * @return Slot number.
 */
ECL_RESULT_USE_CHECK
int ECLBeaconBlockHeaderGetSlot(const ECLBeaconBlockHeader *beacon);

/**
 * Obtains the proposer validator registry index
 * of a given beacon block header.
 *
 * @param      beacon               Beacon block header.
 *
 * @return Proposer validator registry index.
 */
ECL_RESULT_USE_CHECK
int ECLBeaconBlockHeaderGetProposerIndex(const ECLBeaconBlockHeader *beacon);

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
ECL_RESULT_USE_CHECK
const ECLRoot *ECLBeaconBlockHeaderGetParentRoot(const ECLBeaconBlockHeader *beacon);

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
ECL_RESULT_USE_CHECK
const ECLRoot *ECLBeaconBlockHeaderGetStateRoot(const ECLBeaconBlockHeader *beacon);

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
ECL_RESULT_USE_CHECK
const ECLRoot *ECLBeaconBlockHeaderGetBodyRoot(const ECLBeaconBlockHeader *beacon);

/**
 * Computes the execution block hash for a given light client header.
 *
 * - The hash must be destroyed using `ECLRootDestroy`
 *   once no longer needed, to release memory.
 *
 * @param      header               Light client header.
 * @param      cfg                  Ethereum Consensus Layer network configuration.
 *
 * @return Pointer to a copy of the given header's execution block hash.
 *
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/deneb/beacon-chain.md#executionpayloadheader
 */
ECL_RESULT_USE_CHECK
ECLRoot *ECLLightClientHeaderCopyExecutionHash(
    const ECLLightClientHeader *header,
    const ECLNetworkConfig *cfg);

/**
 * Execution payload header.
 */
typedef struct ECLExecutionPayloadHeader ECLExecutionPayloadHeader;

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
 * @see https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/deneb/beacon-chain.md#executionpayloadheader
 */
ECL_RESULT_USE_CHECK
const ECLExecutionPayloadHeader *ECLLightClientHeaderGetExecution(
    const ECLLightClientHeader *header);

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
ECL_RESULT_USE_CHECK
const ECLRoot *ECLExecutionPayloadHeaderGetParentHash(
    const ECLExecutionPayloadHeader *execution);

/**
 * Execution address.
 */
typedef uint8_t ECLExecutionAddress[20];

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
ECL_RESULT_USE_CHECK
const ECLExecutionAddress *ECLExecutionPayloadHeaderGetFeeRecipient(
    const ECLExecutionPayloadHeader *execution);

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
ECL_RESULT_USE_CHECK
const ECLRoot *ECLExecutionPayloadHeaderGetStateRoot(
    const ECLExecutionPayloadHeader *execution);

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
ECL_RESULT_USE_CHECK
const ECLRoot *ECLExecutionPayloadHeaderGetReceiptsRoot(
    const ECLExecutionPayloadHeader *execution);

/**
 * Execution logs bloom.
 */
typedef uint8_t ECLLogsBloom[256];

/**
 * Obtains the logs bloom of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution logs bloom.
 */
ECL_RESULT_USE_CHECK
const ECLLogsBloom *ECLExecutionPayloadHeaderGetLogsBloom(
    const ECLExecutionPayloadHeader *execution);

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
ECL_RESULT_USE_CHECK
const ECLRoot *ECLExecutionPayloadHeaderGetPrevRandao(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the execution block number of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution block number.
 */
ECL_RESULT_USE_CHECK
int ECLExecutionPayloadHeaderGetBlockNumber(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the gas limit of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Gas limit.
 */
ECL_RESULT_USE_CHECK
int ECLExecutionPayloadHeaderGetGasLimit(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the gas used of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Gas used.
 */
ECL_RESULT_USE_CHECK
int ECLExecutionPayloadHeaderGetGasUsed(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the timestamp of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Execution block timestamp.
 */
ECL_RESULT_USE_CHECK
int ECLExecutionPayloadHeaderGetTimestamp(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the extra data buffer of a given execution payload header.
 *
 * - The returned value is allocated in the given execution payload header.
 *   It must neither be released nor written to, and the execution payload
 *   header must not be released while the returned value is in use.
 *
 * - Use `ECLExecutionPayloadHeaderGetNumExtraDataBytes`
 *   to obtain the length of the buffer.
 *
 * @param      execution            Execution payload header.
 *
 * @return Buffer with execution block extra data.
 */
ECL_RESULT_USE_CHECK
const void *ECLExecutionPayloadHeaderGetExtraDataBytes(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the extra data buffer's length of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Length of execution block extra data.
 */
ECL_RESULT_USE_CHECK
int ECLExecutionPayloadHeaderGetNumExtraDataBytes(
    const ECLExecutionPayloadHeader *execution);

/**
 * UInt256 (little-endian)
 */
typedef uint8_t ECLUInt256[32];

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
ECL_RESULT_USE_CHECK
const ECLUInt256 *ECLExecutionPayloadHeaderGetBaseFeePerGas(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the data gas used of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Data gas used.
 */
ECL_RESULT_USE_CHECK
int ECLExecutionPayloadHeaderGetDataGasUsed(
    const ECLExecutionPayloadHeader *execution);

/**
 * Obtains the excess data gas of a given execution payload header.
 *
 * @param      execution            Execution payload header.
 *
 * @return Excess data gas.
 */
ECL_RESULT_USE_CHECK
int ECLExecutionPayloadHeaderGetExcessDataGas(
    const ECLExecutionPayloadHeader *execution);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
