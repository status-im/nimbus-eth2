/**
 * beacon_chain
 * Copyright (c) 2023 Status Research & Development GmbH
 * Licensed and distributed under either of
 *   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
 *   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
 * at your option. This file may not be copied, modified, or distributed except according to those terms.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnimbus_lc.h"

#define check(condition) \
    do { \
        if (!(condition)) { \
            printf("assertion failed: %s - %s @ %s:%d", \
                #condition, __func__, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

#ifndef __DIR__
#define __DIR__ "."
#endif

ETH_RESULT_USE_CHECK
static void *readEntireFile(const char *path, int *numBytes)
{
    int err;

    FILE *file = fopen(path, "rb");
    check(file);

    err = fseek(file, 0, SEEK_END);
    check(!err);

    long size = ftell(file);
    check(size >= 0);

    err = fseek(file, 0, SEEK_SET);
    check(!err);

    char *buffer = malloc((size_t) size + 1);
    check(buffer);

    size_t actualSize = fread(buffer, 1, (size_t) size, file);
    check(actualSize == (size_t) size);

    buffer[size] = '\0';

    fclose(file);

    if (numBytes) {
        check(size <= INT_MAX);
        *numBytes = (int) actualSize;
    }
    return buffer;
}

ETH_RESULT_USE_CHECK
static ETHConsensusConfig *loadCfg(const char *path)
{
    void *fileContent = readEntireFile(path, /* numBytes: */ NULL);
    ETHConsensusConfig *cfg = ETHConsensusConfigCreateFromYaml(fileContent);
    check(cfg);
    free(fileContent);
    return cfg;
}

ETH_RESULT_USE_CHECK
static ETHBeaconState *loadGenesis(const ETHConsensusConfig *cfg, const char *path)
{
    const char *consensusFork = ETHConsensusConfigGetConsensusVersionAtEpoch(cfg, /* epoch: */ 0);
    check(consensusFork);

    int numSszBytes;
    void *sszBytes = readEntireFile(path, &numSszBytes);
    ETHBeaconState *state = ETHBeaconStateCreateFromSsz(
        cfg, consensusFork, sszBytes, numSszBytes);
    check(state);
    free(sszBytes);

    return state;
}

static void printHexString(const void *bytes, int numBytes)
{
    const uint8_t *bytes_ = bytes;
    printf("0x");
    for (int i = 0; i < numBytes; i++) {
        printf("%02x", bytes_[i]);
    }
}

static void printHexStringReversed(const void *bytes, int numBytes)
{
    const uint8_t *bytes_ = bytes;
    printf("0x");
    for (int i = numBytes - 1; i >= 0; i--) {
        printf("%02x", bytes_[i]);
    }
}

static void printGweiString(const ETHUInt256 *wei)
{
    ETHUInt256 value;
    memcpy(&value, wei, sizeof value);

    char weiString[80];
    int o = 0;
    for (;;) {
        bool isZero = true;
        for (size_t i = 0; i < sizeof value; i++) {
            if (value.bytes[i]) {
                isZero = false;
                break;
            }
        }
        if (isZero) {
            break;
        }

        uint8_t remainder = 0;
        for (int i = sizeof value - 1; i >= 0; i--) {
            uint16_t temp = (uint16_t) ((uint16_t) remainder << 8) | value.bytes[i];
            value.bytes[i] = (uint8_t) (temp / 10);
            remainder = temp % 10;
        }
        weiString[o++] = '0' + (char) remainder;
    }
    if (!o) {
        weiString[o++] = '0';
    }

    if (o < 9) {
        printf("0");
    } else {
        while (o > 9) {
            printf("%c", weiString[--o]);
        }
    }
    int z = 0;
    while (z < o && weiString[z] == '0') {
        z++;
    }
    if (o > z) {
        printf(".");
        while (o > z) {
            printf("%c", weiString[--o]);
        }
    }
}

static void visualizeHeader(const ETHLightClientHeader *header, const ETHConsensusConfig *cfg)
{
    ETHRoot *beaconRoot = ETHLightClientHeaderCopyBeaconRoot(header, cfg);
    printf("  - beacon: ");
    printHexString(beaconRoot, sizeof *beaconRoot);
    printf("\n");
    ETHRootDestroy(beaconRoot);

    const ETHBeaconBlockHeader *beacon = ETHLightClientHeaderGetBeacon(header);

    int beaconSlot = ETHBeaconBlockHeaderGetSlot(beacon);
    printf("    - slot: %d\n", beaconSlot);

    int beaconProposerIndex = ETHBeaconBlockHeaderGetProposerIndex(beacon);
    printf("    - proposer_index: %d\n", beaconProposerIndex);

    const ETHRoot *beaconParentRoot = ETHBeaconBlockHeaderGetParentRoot(beacon);
    printf("    - parent_root: ");
    printHexString(beaconParentRoot, sizeof *beaconParentRoot);
    printf("\n");

    const ETHRoot *beaconStateRoot = ETHBeaconBlockHeaderGetStateRoot(beacon);
    printf("    - state_root: ");
    printHexString(beaconStateRoot, sizeof *beaconStateRoot);
    printf("\n");

    const ETHRoot *beaconBodyRoot = ETHBeaconBlockHeaderGetBodyRoot(beacon);
    printf("    - body_root: ");
    printHexString(beaconBodyRoot, sizeof *beaconBodyRoot);
    printf("\n");

    ETHRoot *executionHash = ETHLightClientHeaderCopyExecutionHash(header, cfg);
    printf("  - execution: ");
    printHexString(executionHash, sizeof *executionHash);
    printf("\n");
    ETHRootDestroy(executionHash);

    const ETHExecutionPayloadHeader *execution = ETHLightClientHeaderGetExecution(header);

    const ETHRoot *executionParentHash = ETHExecutionPayloadHeaderGetParentHash(execution);
    printf("    - parent_hash: ");
    printHexString(executionParentHash, sizeof *executionParentHash);
    printf("\n");

    const ETHExecutionAddress *executionFeeRecipient =
        ETHExecutionPayloadHeaderGetFeeRecipient(execution);
    printf("    - fee_recipient: ");
    printHexString(executionFeeRecipient, sizeof *executionFeeRecipient);
    printf("\n");

    const ETHRoot *executionStateRoot = ETHExecutionPayloadHeaderGetStateRoot(execution);
    printf("    - state_root: ");
    printHexString(executionStateRoot, sizeof *executionStateRoot);
    printf("\n");

    const ETHRoot *executionReceiptsRoot = ETHExecutionPayloadHeaderGetReceiptsRoot(execution);
    printf("    - receipts_root: ");
    printHexString(executionReceiptsRoot, sizeof *executionReceiptsRoot);
    printf("\n");

    const ETHLogsBloom *executionLogsBloom = ETHExecutionPayloadHeaderGetLogsBloom(execution);
    printf("    - logs_bloom: ");
    printHexString(executionLogsBloom, sizeof *executionLogsBloom);
    printf("\n");

    const ETHRoot *executionPrevRandao = ETHExecutionPayloadHeaderGetPrevRandao(execution);
    printf("    - prev_randao: ");
    printHexString(executionPrevRandao, sizeof *executionPrevRandao);
    printf("\n");

    int executionBlockNumber = ETHExecutionPayloadHeaderGetBlockNumber(execution);
    printf("    - block_number: %d\n", executionBlockNumber);

    int executionGasLimit = ETHExecutionPayloadHeaderGetGasLimit(execution);
    printf("    - gas_limit: %d\n", executionGasLimit);

    int executionGasUsed = ETHExecutionPayloadHeaderGetGasUsed(execution);
    printf("    - gas_used: %d\n", executionGasUsed);

    int executionTimestamp = ETHExecutionPayloadHeaderGetTimestamp(execution);
    printf("    - timestamp: %d\n", executionTimestamp);

    int numExecutionExtraDataBytes;
    const void *executionExtraDataBytes =
        ETHExecutionPayloadHeaderGetExtraDataBytes(execution, &numExecutionExtraDataBytes);
    printf("    - extra_data: ");
    printHexString(executionExtraDataBytes, numExecutionExtraDataBytes);
    printf("\n");

    const ETHUInt256 *executionBaseFeePerGas = ETHExecutionPayloadHeaderGetBaseFeePerGas(execution);
    printf("    - base_fee_per_gas: ");
    printGweiString(executionBaseFeePerGas);
    printf(" Gwei\n");

    int executionBlobGasUsed = ETHExecutionPayloadHeaderGetBlobGasUsed(execution);
    printf("    - blob_gas_used: %d\n", executionBlobGasUsed);

    int executionExcessBlobGas = ETHExecutionPayloadHeaderGetExcessBlobGas(execution);
    printf("    - excess_blob_gas: %d\n", executionExcessBlobGas);
}

ETH_RESULT_USE_CHECK
int main(void)
{
    NimMain();

    ETHRandomNumber *rng = ETHRandomNumberCreate();
    check(rng);
    ETHConsensusConfig *cfg = loadCfg(__DIR__ "/test_files/config.yaml");
    ETHBeaconState *genesisState = loadGenesis(cfg, __DIR__ "/test_files/genesis.ssz");
    ETHRoot *genesisValRoot = ETHBeaconStateCopyGenesisValidatorsRoot(genesisState);
    ETHForkDigests *forkDigests = ETHForkDigestsCreateFromState(cfg, genesisState);
    ETHBeaconClock *beaconClock = ETHBeaconClockCreateFromState(genesisState);
    ETHBeaconStateDestroy(genesisState);
    printf("Current slot: %d\n", ETHBeaconClockGetSlot(beaconClock));
    printf("\n");

    const ETHRoot trustedBlockRoot = {{
        0x15, 0xcf, 0x56, 0xeb, 0xf8, 0x87, 0xed, 0xe9,
        0xcf, 0x3f, 0xc1, 0x0a, 0x26, 0xec, 0x83, 0x82,
        0x86, 0x28, 0x93, 0x2c, 0x10, 0x0e, 0x42, 0xc9,
        0x8c, 0x84, 0xf8, 0x3d, 0xa7, 0x10, 0xc8, 0x63
    }};
    int numBootstrapBytes;
    void *bootstrapBytes = readEntireFile(__DIR__ "/test_files/bootstrap.ssz", &numBootstrapBytes);
    ETHLightClientStore *store = ETHLightClientStoreCreateFromBootstrap(
        cfg, &trustedBlockRoot,
        "application/octet-stream", "capella", bootstrapBytes, numBootstrapBytes);
    check(store);
    free(bootstrapBytes);

    int startPeriod;
    int count;
    int syncKind = ETHLightClientStoreGetNextSyncTask(store, beaconClock, &startPeriod, &count);
    check(syncKind == kETHLcSyncKind_UpdatesByRange);
    check(startPeriod == 800);
    check(count > 0 && count <= 128);
    printf("Sync task: UpdatesByRange(%d, %d)\n", startPeriod, count);

    int latestProcessResult;

    int numUpdatesBytes;
    void *updatesBytes = readEntireFile(__DIR__ "/test_files/updates.ssz", &numUpdatesBytes);
    latestProcessResult = ETHLightClientStoreProcessUpdatesByRange(
        store, cfg, forkDigests, genesisValRoot, beaconClock,
        startPeriod, count, "application/octet-stream", updatesBytes, numUpdatesBytes);
    check(!latestProcessResult);
    free(updatesBytes);

    int millisecondsToNextSyncTask = ETHLightClientStoreGetMillisecondsToNextSyncTask(
        store, rng, beaconClock, latestProcessResult);
    printf("Next sync task: %d.%03ds\n",
        millisecondsToNextSyncTask / 1000,
        millisecondsToNextSyncTask % 1000);

    int numFinUpdateBytes;
    void *finUpdateBytes = readEntireFile(__DIR__ "/test_files/finUpdate.ssz", &numFinUpdateBytes);
    latestProcessResult = ETHLightClientStoreProcessFinalityUpdate(
        store, cfg, forkDigests, genesisValRoot, beaconClock,
        "application/octet-stream", "capella", finUpdateBytes, numFinUpdateBytes);
    check(!latestProcessResult);
    free(finUpdateBytes);

    int numOptUpdateBytes;
    void *optUpdateBytes = readEntireFile(__DIR__ "/test_files/optUpdate.ssz", &numOptUpdateBytes);
    latestProcessResult = ETHLightClientStoreProcessOptimisticUpdate(
        store, cfg, forkDigests, genesisValRoot, beaconClock,
        "application/octet-stream", "capella", optUpdateBytes, numOptUpdateBytes);
    check(!latestProcessResult);
    free(optUpdateBytes);

    finUpdateBytes = readEntireFile(__DIR__ "/test_files/finUpdate.json", &numFinUpdateBytes);
    latestProcessResult = ETHLightClientStoreProcessFinalityUpdate(
        store, cfg, forkDigests, genesisValRoot, beaconClock,
        "application/json", /* consensusVersion: */ NULL, finUpdateBytes, numFinUpdateBytes);
    check(!latestProcessResult);
    free(finUpdateBytes);

    optUpdateBytes = readEntireFile(__DIR__ "/test_files/optUpdate.json", &numOptUpdateBytes);
    latestProcessResult = ETHLightClientStoreProcessOptimisticUpdate(
        store, cfg, forkDigests, genesisValRoot, beaconClock,
        "application/json", /* consensusVersion: */ NULL, optUpdateBytes, numOptUpdateBytes);
    check(!latestProcessResult);
    free(optUpdateBytes);

    printf("\n");

    printf("- finalized_header\n");
    visualizeHeader(ETHLightClientStoreGetFinalizedHeader(store), cfg);

    bool isNextSyncCommitteeKnown = ETHLightClientStoreIsNextSyncCommitteeKnown(store);
    printf("- next_sync_committee: %s\n", isNextSyncCommitteeKnown ? "known" : "unknown");

    printf("- optimistic_header\n");
    visualizeHeader(ETHLightClientStoreGetOptimisticHeader(store), cfg);

    int safetyThreshold = ETHLightClientStoreGetSafetyThreshold(store);
    printf("- safety_threshold: %d\n", safetyThreshold);

    ETHLightClientHeader *copiedHeader =
        ETHLightClientHeaderCreateCopy(ETHLightClientStoreGetFinalizedHeader(store));

    ETHLightClientStoreDestroy(store);
    ETHBeaconClockDestroy(beaconClock);
    ETHForkDigestsDestroy(forkDigests);
    ETHRootDestroy(genesisValRoot);
    ETHConsensusConfigDestroy(cfg);
    ETHRandomNumberDestroy(rng);

    ETHRoot *copiedExecutionHash = ETHLightClientHeaderCopyExecutionHash(copiedHeader, cfg);
    void *blockHeaderJson = readEntireFile(
        __DIR__ "/test_files/executionBlockHeader.json", /* numBytes: */ NULL);
    ETHExecutionBlockHeader *executionBlockHeader =
        ETHExecutionBlockHeaderCreateFromJson(copiedExecutionHash, blockHeaderJson);
    check(executionBlockHeader);
    free(blockHeaderJson);
    ETHRootDestroy(copiedExecutionHash);
    ETHLightClientHeaderDestroy(copiedHeader);

    printf("- finalized_header (execution block header):\n");

    const ETHRoot *executionTransactionsRoot =
        ETHExecutionBlockHeaderGetTransactionsRoot(executionBlockHeader);
    printf("    - transactions_root: ");
    printHexString(executionTransactionsRoot, sizeof *executionTransactionsRoot);
    printf("\n");

    const ETHRoot *executionWithdrawalsRoot =
        ETHExecutionBlockHeaderGetWithdrawalsRoot(executionBlockHeader);
    printf("    - withdrawals_root: ");
    printHexString(executionWithdrawalsRoot, sizeof *executionWithdrawalsRoot);
    printf("\n");

    ETHExecutionBlockHeaderDestroy(executionBlockHeader);

    ETHRoot sampleTransactionsRoot = {{
        0x73, 0x36, 0x36, 0xe8, 0x0e, 0x47, 0x60, 0x09,
        0xd1, 0xc8, 0x9f, 0x81, 0xaa, 0x64, 0xe1, 0xfd,
        0xf7, 0xff, 0x36, 0xd6, 0x04, 0x6e, 0x95, 0x6c,
        0x39, 0xed, 0xcd, 0x6c, 0x95, 0x2d, 0xce, 0xc2,
    }};
    void *sampleTransactionsJson = readEntireFile(
        __DIR__ "/test_files/transactions.json", /* numBytes: */ NULL);
    ETHTransactions *transactions =
        ETHTransactionsCreateFromJson(&sampleTransactionsRoot, sampleTransactionsJson);
    check(transactions);
    free(sampleTransactionsJson);

    ETHRoot sampleReceiptsRoot = {{
        0x51, 0x4d, 0xdf, 0xd7, 0xf8, 0x33, 0xfb, 0x2a,
        0x4f, 0x60, 0xed, 0x49, 0xdf, 0xc7, 0x9c, 0x07,
        0xb6, 0x9c, 0x37, 0xef, 0xd1, 0xa5, 0x97, 0xca,
        0x42, 0x76, 0x23, 0xff, 0xa1, 0x79, 0x49, 0xae,
    }};
    void *sampleReceiptsJson = readEntireFile(
        __DIR__ "/test_files/receipts.json", /* numBytes: */ NULL);
    ETHReceipts *receipts =
        ETHReceiptsCreateFromJson(&sampleReceiptsRoot, sampleReceiptsJson);
    check(receipts);
    free(sampleReceiptsJson);

    int numTransactions = ETHTransactionsGetCount(transactions);
    int numReceipts = ETHReceiptsGetCount(receipts);
    check(numTransactions == numReceipts);
    printf("\nSample transactions:\n");
    for (int transactionIndex = 0; transactionIndex < numTransactions; transactionIndex++) {
        const ETHTransaction *transaction = ETHTransactionsGet(transactions, transactionIndex);
        const ETHReceipt *receipt = ETHReceiptsGet(receipts, transactionIndex);

        const ETHRoot *transactionHash = ETHTransactionGetHash(transaction);
        printf("- ");
        printHexString(transactionHash, sizeof *transactionHash);
        printf("\n");

        const ETHUInt256 *transactionChainId = ETHTransactionGetChainId(transaction);
        printf("    - chain_id: ");
        printHexStringReversed(transactionChainId, sizeof *transactionChainId);
        printf("\n");

        const ETHExecutionAddress *transactionFrom = ETHTransactionGetFrom(transaction);
        printf("    - from: ");
        printHexString(transactionFrom, sizeof *transactionFrom);
        printf("\n");

        const uint64_t *transactionNonce = ETHTransactionGetNonce(transaction);
        printf("    - nonce: %" PRIu64 "\n", *transactionNonce);

        const uint64_t *transactionMaxPriorityFeePerGas =
            ETHTransactionGetMaxPriorityFeePerGas(transaction);
        printf("    - max_priority_fee_per_gas: %" PRIu64 "\n", *transactionMaxPriorityFeePerGas);

        const uint64_t *transactionMaxFeePerGas = ETHTransactionGetMaxFeePerGas(transaction);
        printf("    - max_fee_per_gas: %" PRIu64 "\n", *transactionMaxFeePerGas);

        const uint64_t *transactionGas = ETHTransactionGetGas(transaction);
        printf("    - gas: %" PRIu64 "\n", *transactionGas);

        bool transactionIsCreatingContract = ETHTransactionIsCreatingContract(transaction);
        const ETHExecutionAddress *transactionTo = ETHTransactionGetTo(transaction);
        if (transactionIsCreatingContract) {
            printf("    - contract_address: ");
        } else {
            printf("    - to: ");
        }
        printHexString(transactionTo, sizeof *transactionTo);
        printf("\n");

        const ETHUInt256 *transactionValue = ETHTransactionGetValue(transaction);
        printf("    - value: ");
        printGweiString(transactionValue);
        printf(" Gwei\n");

        int numTransactionInputBytes;
        const void *transactionInputBytes =
            ETHTransactionGetInputBytes(transaction, &numTransactionInputBytes);
        printf("    - input: ");
        printHexString(transactionInputBytes, numTransactionInputBytes);
        printf("\n");

        const ETHAccessList *transactionAccessList = ETHTransactionGetAccessList(transaction);
        printf("    - access_list:\n");
        int numAccessTuples = ETHAccessListGetCount(transactionAccessList);
        for (int accessTupleIndex = 0; accessTupleIndex < numAccessTuples; accessTupleIndex++) {
            const ETHAccessTuple *accessTuple =
                ETHAccessListGet(transactionAccessList, accessTupleIndex);

            const ETHExecutionAddress *accessTupleAddress = ETHAccessTupleGetAddress(accessTuple);
            printf("        - ");
            printHexString(accessTupleAddress, sizeof *accessTupleAddress);
            printf("\n");

            int numStorageKeys = ETHAccessTupleGetNumStorageKeys(accessTuple);
            for (int storageKeyIndex = 0; storageKeyIndex < numStorageKeys; storageKeyIndex++) {
                const ETHRoot *storageKey =
                    ETHAccessTupleGetStorageKey(accessTuple, storageKeyIndex);
                printf("            - ");
                printHexString(storageKey, sizeof *storageKey);
                printf("\n");
            }
        }

        const uint64_t *transactionMaxFeePerBlobGas =
            ETHTransactionGetMaxFeePerBlobGas(transaction);
        printf("    - max_fee_per_blob_gas: %" PRIu64 "\n", *transactionMaxFeePerBlobGas);

        printf("    - blob_versioned_hashes:\n");
        int numBlobVersionedHashes = ETHTransactionGetNumBlobVersionedHashes(transaction);
        for (int hashIndex = 0; hashIndex < numBlobVersionedHashes; hashIndex++) {
            const ETHRoot *blobVersionedHash =
                ETHTransactionGetBlobVersionedHash(transaction, hashIndex);
            printf("        - ");
            printHexString(blobVersionedHash, sizeof *blobVersionedHash);
            printf("\n");
        }

        int numTransactionSignatureBytes;
        const void *transactionSignatureBytes =
            ETHTransactionGetSignatureBytes(transaction, &numTransactionSignatureBytes);
        printf("    - signature: ");
        printHexString(transactionSignatureBytes, numTransactionSignatureBytes);
        printf("\n");

        int numTransactionBytes;
        const void *transactionBytes = ETHTransactionGetBytes(transaction, &numTransactionBytes);
        printf("    - bytes: ");
        printHexString(transactionBytes, numTransactionBytes);
        printf("\n");

        printf("    - receipt:\n");

        bool receiptHasStatus = ETHReceiptHasStatus(receipt);
        if (!receiptHasStatus) {
            const ETHRoot *receiptRoot = ETHReceiptGetRoot(receipt);
            printf("        - root: ");
            printHexString(receiptRoot, sizeof *receiptRoot);
            printf("\n");
        } else {
            bool receiptStatus = ETHReceiptGetStatus(receipt);
            printf("        - status: %d\n", receiptStatus);
        }

        const uint64_t *receiptGasUsed = ETHReceiptGetGasUsed(receipt);
        printf("        - gas_used: %" PRIu64 "\n", *receiptGasUsed);

        const ETHLogsBloom *receiptLogsBloom = ETHReceiptGetLogsBloom(receipt);
        printf("        - logs_bloom: ");
        printHexString(receiptLogsBloom, sizeof *receiptLogsBloom);
        printf("\n");

        const ETHLogs *receiptLogs = ETHReceiptGetLogs(receipt);
        printf("        - logs:\n");
        int numLogs = ETHLogsGetCount(receiptLogs);
        for (int logIndex = 0; logIndex < numLogs; logIndex++) {
            const ETHLog *log = ETHLogsGet(receiptLogs, logIndex);

            const ETHExecutionAddress *logAddress = ETHLogGetAddress(log);
            printf("            - address: ");
            printHexString(logAddress, sizeof *logAddress);
            printf("\n");

            printf("                - topics:\n");
            int numTopics = ETHLogGetNumTopics(log);
            for (int topicIndex = 0; topicIndex < numTopics; topicIndex++) {
                const ETHRoot *topic = ETHLogGetTopic(log, topicIndex);
                printf("                    - ");
                printHexString(topic, sizeof *topic);
                printf("\n");
            }

            int numLogDataBytes;
            const void *logDataBytes = ETHLogGetDataBytes(log, &numLogDataBytes);
            printf("                - data: ");
            printHexString(logDataBytes, numLogDataBytes);
            printf("\n");
        }

        int numReceiptBytes;
        const void *receiptBytes = ETHReceiptGetBytes(receipt, &numReceiptBytes);
        printf("        - bytes: ");
        printHexString(receiptBytes, numReceiptBytes);
        printf("\n");
    }

    ETHReceiptsDestroy(receipts);
    ETHTransactionsDestroy(transactions);

    return 0;
}
