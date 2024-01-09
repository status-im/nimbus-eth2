2024-01-08 v24.1.1
==================

Nimbus `v24.1.1` is a hotfix addressing a problem introduced in the `v24.1.0` release. Nimbus was crashing immediately after being connected to an execution layer node which is not fully synced. All users of `v24.1.0` are advised to upgrade at their earliest convenience.

2024-01-04 v24.1.0
==================

Nimbus `v24.1.0` is a `low-urgency` upgrade bringing full support for the upcoming Cancun-Deneb hard-fork on the Goerli testnet and introducing the `/eth/v3/validator/blocks/{slot}` Beacon API end-point that greatly simplifies the implementation of profit-optimising validator clients.

### Improvements

* Nimbus now includes the latest Goerli-Prater metadata, scheduling the Cancun-Deneb hard-fork:
  https://github.com/status-im/nimbus-eth2/pull/5680

* The Nimbus beacon node now supports the `/eth/v3/validator/blocks/{slot}` Beacon API end-point:
  https://github.com/status-im/nimbus-eth2/pull/5474
  https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Validator/produceBlockV3

* Nimbus now accepts POST requests to the `/eth/v1/beacon/states/{state_id}/validators` and `/eth/v1/beacon/states/{state_id}/validator_balances` Beacon API end-points:
  https://github.com/status-im/nimbus-eth2/pull/5632
  https://github.com/ethereum/beacon-APIs/pull/367

* Nimbus now follows the latest specification regarding the deprecated `/eth/v1/validator/blinded_blocks/{slot}` Beacon API end-point:
  https://github.com/status-im/nimbus-eth2/pull/5639

* Nimbus now uses the latest set of bootstrap nodes for the Gnosis chain:
  https://github.com/status-im/nimbus-eth2/pull/5656

### Fixes

* Nimbus was sending unnecessary redundant `forkChoiceUpdated` notifications to the execution layer:
  https://github.com/status-im/nimbus-eth2/pull/5635

* Nimbus was returning incorrect responses on requests for blocks at empty slots when working with ERA files:
  https://github.com/status-im/nimbus-eth2/pull/5641

* The Nimbus validator client was not sending Builder API registration messages at the correct time:
  https://github.com/status-im/nimbus-eth2/pull/5663

* Nimbus was ignoring a specified `--jwt-secret` option when no `--el` option was provided and the default localhost URL was being used:
  https://github.com/status-im/nimbus-eth2/pull/5671
  https://github.com/status-im/nimbus-eth2/issues/5665

### Breaking Changes

* Machine consumers of Nimbus logs should be updated, as the abbreviated value of the `NOTICE` log level has been renamed from `NOT` to `NTC`:
  https://github.com/status-im/nimbus-eth2/pull/5634


2023-11-28 v23.11.0
===================

Nimbus `v23.11.0` is a `low-urgency` upgrade bringing enhanced support for the Obol DVT middleware, further profit optimisations for the Nimbus validator client and a simplified and safe alternative to the trusted node sync.

### Improvements

* The new options `external-beacon-api-url`, `trusted-block-root` and `trusted-state-root` enable simple bootstrapping through the light client protocol and a non-trusted Beacon API provider:
  https://nimbus.guide/start-syncing.html#checkpoint-sync
  https://github.com/status-im/nimbus-eth2/pull/5545

* Improved scoring algorithms allow the Nimbus validator client to maximize block rewards when working with multiple beacon nodes:
  https://github.com/status-im/nimbus-eth2/pull/5447

* Nimbus now supports the `/eth/v1/validator/beacon_committee_selections` and `/eth/v1/validator/sync_committee_selections` Beacon API endpoints used by the Charon Obol middleware:
  https://github.com/status-im/nimbus-eth2/pull/5375

* Efficient bulk write operations to the slashing protection database bring significant performance improvements when operating very large number of validators on a single machine (e.g. more than 10K):
  https://github.com/status-im/nimbus-eth2/pull/5604

* Nimbus now disconnects peers who are behaving poorly with respect to the beacon chain request/response protocols and peers who are exceeding the GossipSub rate limits:
  https://github.com/status-im/nimbus-eth2/pull/5579
  https://github.com/status-im/nimbus-eth2/pull/5482

* The Nimbus guide now features light and dark themes:
  https://github.com/status-im/nimbus-eth2/pull/5564

* Nimbus now honours the `MIN_EPOCHS_FOR_BLOCK_REQUESTS` network configuration parameter:
  https://github.com/status-im/nimbus-eth2/pull/5590

### Fixes

* The REST API endpoint `/eth/v1/node/peers_count` was producing an incorrectly encoded numeric response:
  https://github.com/status-im/nimbus-eth2/pull/5548

* The REST API endpoint `eth/v2/beacon/blocks` was not handling the `broadcast_validation` parameter in accordance to the spec:
  https://github.com/status-im/nimbus-eth2/issues/5531

* The validator client slashing database was not pruned:
  https://github.com/status-im/nimbus-eth2/pull/5551

* Light clients following the event stream of light client updates delivered through the REST API or the P2P protocols were at risk of getting stuck due to missing notifications for certain key events:
  https://github.com/status-im/nimbus-eth2/pull/5602
  https://github.com/ethereum/consensus-specs/pull/3549

* Regression in v23.10.0 was preventing the Nimbus validator client from registering its validators with the external builder when no validators have been attached to the associated beacon node, effectively disabling the usage of the builder:
  https://github.com/status-im/nimbus-eth2/pull/5603

* Nimbus was not retrying certain syncing requests after receiving an invalid response from a peer:
  https://github.com/status-im/nimbus-eth2/pull/5615

* A theoretical possibility where Nimbus may fail to start after a clean shutdown has been addressed:
  https://github.com/status-im/nimbus-eth2/pull/5617


2023-11-06 v23.10.1
===================

Nimbus `v23.10.1` is a `low-urgency` hotfix release addressing a peer scoring issue introduced in the `v23.10.0` release. The issue manifests under specific network circumstances as a buildup of gossip topics with a low number of peers. Affected users are advised to upgrade at their earliest convenience.


2023-10-17 v23.10.0
===================

Nimbus `v23.10.0` is a `low-urgency` upgrade focusing on stability and performance improvements. The performance improvements will be most impactful on networks with a large number of validators such as the [Holešky testnet](https://github.com/eth-clients/holesky).

### Improvements

* Faster attestation packing algorithm reduces the risk of orphaned block proposals:
  https://github.com/status-im/nimbus-eth2/pull/5471

* Nimbus now adjusts its own the file descriptor limits on start-up in order to reduce the risk of running out of file descriptors:
  https://github.com/status-im/nimbus-eth2/pull/5436

* The Keymanager API now imports keystores faster when they are encrypted with the same password and salt (this is typical for keystores produced by the `staking-deposit-cli` tool):
  https://github.com/status-im/nimbus-eth2/pull/5443

* The Beacon API now emits the spec-mandated `finalized` field on all relevant endpoints:
  https://github.com/status-im/nimbus-eth2/pull/5422

* Faster SSZ hashing speed reduces the overall CPU usage of the client:
  https://github.com/status-im/nimbus-eth2/pull/5463

* The list of mainnet bootstrap nodes has been expanded:
  https://github.com/status-im/nimbus-eth2/pull/5472

* A more efficient algorithm for calculating the list of block proposers during the epoch reduces the rist of missed validator duties during the first slot of the epoch:
  https://github.com/status-im/nimbus-eth2/pull/5414

* Nimbus now produces more detailed error messages when it fails to load validator keystores:
  https://github.com/status-im/nimbus-eth2/pull/5480

* The options `--verifying-web3-signer-url` and `--proven-block-property` can be used in place of `--web3-signer-url` to leverage the support for the experimental Verifying Web3Signer protocol extension:
  https://nimbus.guide/web3signer.html#verifying-web3signer
  https://github.com/status-im/nimbus-eth2/pull/5504

### Fixes

* A rarely occurring file descriptor leak was degrading the performance of Nimbus over time in certain environments:
  https://github.com/status-im/nimbus-eth2/pull/5394

* Nimbus was not properly maintaining connectivity to peers specified through the `--direct-peer` option. Besides the format `/ip4/<address>/tcp/<port>/p2p/<peerId-public-key>`, the option now also accepts ENR addresses:
  https://github.com/status-im/nimbus-eth2/pull/5427

* Nimbus was rejecting some valid sync committee contributions during the first slot of every sync committee period (once per 27 hours):
  https://github.com/status-im/nimbus-eth2/pull/5408

* The Nimbus validator client will no longer crash when the indicated beacon node hostname cannot be resolved:
  https://github.com/status-im/nimbus-eth2/pull/5388

* The fork-choice algorithm was performing certain computations multiple times:
  https://github.com/status-im/nimbus-eth2/pull/5437

* Nimbus was sending unnecessary validator registrations to the builders when configured with multiple per-validator builder preferences:
  https://github.com/status-im/nimbus-eth2/pull/5431

* The Nimbus validator client was not able to process responses from a Teku beacon node replying to the `/eth/v1/validator/liveness/{epoch}` endpoint, due to the presence of additional non-standardized fields:
  https://github.com/status-im/nimbus-eth2/pull/5418

* The Beacon API was using non-compliant HTTP status codes in case of invalid requests to certain endpoints:
  https://github.com/status-im/nimbus-eth2/pull/5422


2023-09-25 v23.9.1
==================

Nimbus `v23.9.1` is a `low-urgency` point release that corrects the [Holešky testnet](https://github.com/eth-clients/holesky) metadata after the [failed start](https://twitter.com/parithosh_j/status/1702816780542984504) on 15th of September. If you want to participate in the network, please update your client before the genesis event on 28th of September, 12:00 UTC.

2023-09-08 v23.9.0
==================

Nimbus `v23.9.0` is a `low-urgency` upgrade providing full support for the upcoming [Holešky testnet](https://github.com/eth-clients/holesky) and simplifying the required configuration for using [remote signers](https://nimbus.guide/web3signer.html).

We've been hard at work researching and developing a GossipSub protocol upgrade, designed to vastly improve bandwidth and latency, especially when dealing with the upcoming larger [EIP-4844 blob messages](https://www.eip4844.com/). This release introduces the initial steps towards this upgrade, along with CPU optimizations and enhanced DDoS protection.

### Improvements

* The GossipSub implementation of Nimbus now consumes less bandwidth and CPU cycles, while improving upon the existing DoS protections through better peer scoring:
  https://github.com/status-im/nimbus-eth2/pull/5229

* The new `--web3-signer-url` command-line option can be used to connect Nimbus to one or more remote signers without requiring any remote keystore files to be created. The list of validators attached to each remote signer is obtained automatically through the [`/api/v1/eth2/publicKeys`](https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Public-Key/operation/ETH2_LIST) Web3Signer API endpoint:
  https://github.com/status-im/nimbus-eth2/pull/5366
  https://github.com/status-im/nimbus-eth2/pull/5385
  https://github.com/status-im/nimbus-eth2/pull/5389

* Nimbus now supports the upcoming Holešky testnet:
  https://nimbus.guide/holesky.html
  https://github.com/status-im/nimbus-eth2/pull/5337

* Faster validator registry processing reduces the time spent by Nimbus in state transitions and replays:
  https://github.com/status-im/nimbus-eth2/pull/5412

### Fixes

* The `deposits exit` command was failing due to incorrect parsing of certain fields in the response of the `/eth/v1/config/spec` endpoint:
  https://github.com/status-im/nimbus-eth2/pull/5370
  https://github.com/status-im/nimbus-eth2/pull/5371


2023-08-23 v23.8.0
==================

Nimbus `v23.8.0` is a `low-urgency` upgrade focusing on performance and stability improvements, aiming to address the increasing number of validators on mainnet and upcoming testnets such as Holesky.

Please note that this version enables the [new attestation subnet subscription logic](https://github.com/ethereum/consensus-specs/pull/3312), proposed in the Ethereum 1.4 consensus spec. This will significantly reduce the CPU usage and the consumed network bandwidth on beacon nodes with many validators, but it will slightly increase them on nodes with a single validator. The `--subscribe-all-subnets` option can still be used on powerful hardware configurations to produce potentially more profitable blocks by processing all attestations directly instead of relying on aggregators.

The upgraded BLST library now identifies your CPU model and selects the most efficient instruction set at run-time which significantly speeds up docker and binary builds. We have tested this on a wide range of hardware, but should the CPU incorrectly advertise extensions it does not have, a downgrade might be necessary while we investigate.

### Improvements

* Optimised algorithms and improved thread scheduling strategy allow Nimbus to process 40% more incoming attestations on typical hardware configurations:
  https://github.com/status-im/nimbus-eth2/pull/5288
  https://github.com/status-im/nimbus-eth2/pull/5176

* Faster state replays and lower latency Beacon API responses are now possible due to lower overhead when loading any kind of data from the Nimbus database. This was achieved through more efficient SSZ deserialization routines, the elimination of redundant CRC checks during data decompression and more precise cache invalidation:
  https://github.com/status-im/nimbus-eth2/pull/5207
  https://github.com/status-im/nimbus-eth2/pull/5264
  https://github.com/status-im/nimbus-eth2/pull/5282

* A more optimised SSZ hash tree root implementation brings faster state replays, block processing and other performance-critical operations in Nimbus:
  https://github.com/status-im/nim-ssz-serialization/pull/53
  https://github.com/status-im/nimbus-eth2/pull/5292

* Nimbus now performs less memory allocations during state transitions, reducing the risk of delays induced by Nim garbage collection:
  https://github.com/status-im/nimbus-eth2/pull/5235

* The BLST library has been upgraded to its latest version. Nimbus is now using a more optimal approach to aggregate signature verification:
  https://github.com/status-im/nimbus-eth2/pull/5272
  https://github.com/status-im/nimbus-eth2/pull/5268

* Nimbus now supports the Chiado Gnosis testnet:
  https://github.com/status-im/nimbus-eth2/pull/5208

* BearSSL has been upgraded to version 0.2.1:
  https://github.com/status-im/nimbus-eth2/pull/5298

### Fixes

* Nimbus was not compliant with the latest Web3Signer specification when requesting block signatures:
  https://github.com/status-im/nimbus-eth2/pull/5294

* The Nimbus beacon node was frequently crashing immediately after block proposal when using a validator client and an external builder:
  https://github.com/status-im/nimbus-eth2/pull/5295

* The Nimbus validator client was crashing in certain situations after a request to the beacon node has timed out:
  https://github.com/status-im/nimbus-eth2/pull/5297

* Nimbus was failing to load a built-in genesis state of a supported network on certain ARM CPUs:
  https://github.com/status-im/nimbus-eth2/pull/5244

* When optimistically synced, Nimbus was sending unnecessary `forkChoiceUpdated` notifications for already finalized blocks:
  https://github.com/status-im/nimbus-eth2/pull/5248

### Removed functionality

* The builder API is no longer supported in network simulations and custom testnets, based on the Bellatrix specification:
  https://github.com/status-im/nimbus-eth2/pull/5162
  https://github.com/status-im/nimbus-eth2/pull/5203
  https://github.com/status-im/nimbus-eth2/pull/5251
  https://github.com/status-im/nimbus-eth2/pull/5262
  https://github.com/status-im/nimbus-eth2/pull/5272


2023-07-19 v23.7.0
==================

Nimbus `v23.7.0` is a `low-urgency` upgrade, bringing advanced profit optimisation capabilities to the Nimbus validator client and addressing risk factors that can contribute to poorer validator performance.

### Improvements

* The Nimbus validator client now uses a scoring algorithm capable of selecting the most optimal attestation data when working with multiple beacon nodes:
  https://github.com/status-im/nimbus-eth2/pull/5101

* The Nimbus validator client now synchronizes its clock with the Nimbus beacon node in order to eliminate any risks for poor validator performance stemming from de-synchronized clocks:
  https://github.com/status-im/nimbus-eth2/pull/4846

* The `/eth/v1/beacon/states/{state_id}/*` family of REST end-points now support queries by state root as long as the state is within the most recent 8192 slots (approximately 27 hours):
  https://github.com/status-im/nimbus-eth2/pull/5155

* Improved validation of blocks during syncing allows Nimbus to optimize the initial syncing target of the execution layer node:
  https://github.com/status-im/nimbus-eth2/pull/5169

* The Nimbus light client is now available a C library for easy reuse and embedding in other software (alpha release):
  https://github.com/status-im/nimbus-eth2/pull/5122

### Fixes

* Due to multiple reports of slow start-up times on certain hardware configurations, caused by the one-time initial pruning performed by Nimbus v23.6.0 and v23.6.1, this functionality has been temporarily disabled:
  https://github.com/status-im/nimbus-eth2/pull/5191

* The block monitoring performed by the Nimbus validator client was permanently interrupted in certain situations after a timed out request to the beacon node:
  https://github.com/status-im/nimbus-eth2/pull/5109

* Nimbus now uses the most up-to-date bootstrap nodes for the Gnosis chain:
  https://github.com/status-im/nimbus-eth2/pull/5175

* Nimbus has addressed a minor risk for missed block proposals at epoch boundaries due to multiple compounding risk factors:
  https://github.com/status-im/nimbus-eth2/pull/5195
  https://github.com/status-im/nimbus-eth2/pull/5196
  https://github.com/status-im/nimbus-eth2/pull/5194


2023-06-26 v23.6.1
==================

Nimbus `v23.6.1` is a `low-urgency` point release significantly improving the performance of database pruning on Nimbus instances that have accumulated history prior to April 2021 (Nimbus 1.1.0). Affected users are advised to upgrade as soon as possible in order to reduce the risk of missed attestations and blocks.

### Fixes

* The legacy Nimbus database is not subjected to pruning due to the high I/O cost of the operations:
  https://github.com/status-im/nimbus-eth2/pull/5116


2023-06-20 v23.6.0
==================

Nimbus `v23.6.0` is a `medium-urgency` upgrade, further improving the efficiency and the standards-compliance of Nimbus while laying out the foundations for the upcoming Deneb hard-fork.

### Improvements

* The `--history:prune` option is now enabled by default.

* Nimbus can now process untimely attestations without triggering expensive state replays, resulting in increased resilience
  https://github.com/status-im/nimbus-eth2/pull/4911

* The Keymanager API can now be used to perform voluntary exits:
  https://github.com/status-im/nimbus-eth2/pull/5020
  https://ethereum.github.io/keymanager-APIs/?urls.primaryName=dev#/Voluntary%20Exit

* The Nimbus validator client now leverages the more efficient support for SSZ responses of the Beacon API:
  https://github.com/status-im/nimbus-eth2/pull/4999

### Fixes

* The support for interacting with the Beacon API from CORS-enabled clients has been restored:
  https://github.com/status-im/nimbus-eth2/pull/5028

* The Nimbus beacon node will no longer inappropriately report `el_offline=true` when fully synced:
  https://github.com/status-im/nimbus-eth2/pull/4991

* The Nimbus validator client will no longer occasionally fail to perform sync committee duties in the first slot of every epoch:
  https://github.com/status-im/nimbus-eth2/pull/5083
  https://github.com/status-im/nimbus-eth2/pull/5084

* Nimbus will no longer refuse to import certain valid SPDIR files (slashing protection interchange format):
  https://github.com/status-im/nimbus-eth2/pull/4997

* The Nimbus behavior differed in minor ways from the Ethereum's fork-choice and honest validator specifications:
  https://github.com/status-im/nimbus-eth2/pull/4992
  https://github.com/status-im/nimbus-eth2/pull/5002

* The Nimbus beacon node was leaking a small amount of memory during a build-up of peer-to-peer block syncing requests:
  https://github.com/status-im/nimbus-eth2/pull/4697

* The Nimbus validator client is now compatible with Lighthouse beacon nodes as it no longer exceeds the maximum allowed number of validator indices per request to the `/eth/v1/beacon/states/{state_id}/validators` endpoint:
  https://github.com/status-im/nimbus-eth2/pull/5082

  We are deeply grateful to @jshufro for contributing important fixes in two consecutive Nimbus releases!

### Removed functionality

* The implementation of the phase0-specific Beacon API endpoint `/eth/v1/debug/beacon/heads` has been removed:
  https://github.com/status-im/nimbus-eth2/pull/5058

* The Web3Signer support for performing the phase0-specific V1 block signing requests has been removed:
  https://github.com/status-im/nimbus-eth2/pull/5014


2023-05-18 v23.5.1
==================

Nimbus `v23.5.1` is a `medium-urgency` point release improving the compatibility of Nimbus with 3rd party validator clients and beacon nodes and introducing the support for incremental pruning. If you are still not using the `--history:prune` option, we recommend testing it in a non-production environment, as it will be enabled by default in our next release.

### Breaking changes

* The Nimbus validator client no longer accepts under-specified beacon node URLs that doesn't include a port number or a protocol scheme. When a protocol scheme is specified, Nimbus now uses the default port for the selected protocol (80 for HTTP and 443 for HTTPS):

  https://github.com/status-im/nimbus-eth2/pull/4921

### Improvements

* The history pruning is now incremental and no longer results in start-up delays when the `--history:prune` option is enabled on an existing node:
  https://github.com/status-im/nimbus-eth2/pull/4887

* Nimbus now uses the withdrawal address of the validator as a default choice for the fee recipient address if the user has not provided any value in the configuration:
  https://github.com/status-im/nimbus-eth2/pull/4968

* Nimbus now supports the upcoming Capella hard-fork in the Gnosis network:
  https://github.com/status-im/nimbus-eth2/pull/4936

### Fixes

* The Capella-related properties `MAX_BLS_TO_EXECUTION_CHANGES`, `MAX_WITHDRAWALS_PER_PAYLOAD`, `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` and `DOMAIN_BLS_TO_EXECUTION_CHANGE` were missing from the `/eth/v1/config/spec` REST API end-point:
  https://github.com/status-im/nimbus-eth2/pull/4925

* The `/eth/v1/validator/blinded_blocks/{slot}` was supplying incorrectly encoded response when requested to return SSZ data:
  https://github.com/status-im/nimbus-eth2/pull/4943

* The safety checks associated with the `--weak-subjectivity-checkpoint` parameter are now compliant with the latest Ethereum specs:
  https://github.com/status-im/nimbus-eth2/pull/4923

* The Nimbus validator client was using HTTP pipelining which is not supported by all beacon node implementations:
  https://github.com/status-im/nimbus-eth2/pull/4950

* The "Connection to EL node degraded" warning is now printed only after sufficiently persistent connectivity issues with the EL client:
  https://github.com/status-im/nimbus-eth2/pull/4960

* After being only briefly disconnected from the execution layer client, the Nimbus beacon node was prematurely setting the `execution_optimistic` flag when returning validator duties:
  https://github.com/status-im/nimbus-eth2/pull/4955

* Nimbus now allows the builder to respond 500ms later than the spec-mandated timeout in order to account for possible additional delays introduced by proxies such as mev-boost:
  https://github.com/status-im/nimbus-eth2/pull/4964

* During sync committee period transitions, for a brief period of time there was a low risk of producing an invalid sync committee contribution:
  https://github.com/status-im/nimbus-eth2/pull/4953

* Nimbus `v23.5.0` introduced an unintended backwards-incompatible change in the parsing of remote keystores which is addressed in this release:
  https://github.com/status-im/nimbus-eth2/pull/4967


2023-05-09 v23.5.0
==================

Nimbus `v23.5.0` is a `medium-urgency` upgrade that addresses a critical issue which was introduced in the previous version (`v23.4.0`). The issue was causing missed block proposals for users who were utilizing an external builder.

### Improvements

* After Nimbus completes a trusted node sync executed with the `--trusted-block-root` flag, it will enable signature verification of all backfilled blocks, thereby reducing the assumed trust in the specified beacon node URL to merely expected data availability rather than expected data authenticity:

  https://github.com/status-im/nimbus-eth2/pull/4858

* The `/eth/v1/node/syncing` BeaconAPI endpoint now supports the standardized `el_offline` property:

  https://github.com/status-im/nimbus-eth2/pull/4860
  https://github.com/ethereum/beacon-APIs/pull/290

* The `secp256k1` library has been upgraded to version `0.3.1`.

* Nimbus now supports an experimental extension of the Web3Signer protocol, allowing the signer server to verify certain properties of the signed block, such as the specified fee recipient:

  https://nimbus.guide/web3signer.html#verifying-web3signer
  https://github.com/status-im/nimbus-eth2/pull/4775
  https://github.com/status-im/nimbus-eth2/pull/4912

### Fixes

* Nimbus was submitting blocks with incorrect state root to the attached external builder which resulted in missed block proposals:

  https://github.com/status-im/nimbus-eth2/pull/4889

* Nimbus was skipping block proposals due to an inappropriate triggering of the slashing protection logic when an external builder was providing a block with insufficient value to be selected under the new `--local-block-value-boost` mechanism:

  https://github.com/status-im/nimbus-eth2/pull/4894

* Nimbus was crashing after certain unsuccessful requests to the external block builder:

  https://github.com/status-im/nimbus-eth2/pull/4890

* The Nimbus validator client was failing to perform sync committee duties when attached to multiple beacon nodes and when some of them were only optimistically synced:

  https://github.com/status-im/nimbus-eth2/pull/4878

* The `--trusted-block-root` option was not visible in the `trustedNodeSync` help listing:

  https://github.com/status-im/nimbus-eth2/pull/4859

* Nimbus was experiencing sporadic request time outs when being connected to the execution client over HTTP. Under specific circumstances this was introducing risk for missed attestation:

  https://github.com/status-im/nimbus-eth2/commit/d784672c107f846163082262334d4d7a4e625bd5

* The required traffic to the execution client was reduced by preventing the sending of the same block multiple times:

  https://github.com/status-im/nimbus-eth2/pull/4850


2023-04-25 v23.4.0
==================

Nimbus `v23.4.0` is a `medium-urgency` upgrade addressing a number of low probability risks for missed block proposals, bringing performance improvements in setups relying on the Nimbus validator client, and introducing some exciting new capabilities of the Nimbus light client and Builder API implementations.

### Improvements

* Nimbus now obtains blocks from the configured builder and execution layer nodes without providing timing advantage to any source. You can use the newly added `--local-block-value-boost` option to give preference to the best block provided by an execution layer node, as long as its value is within the specified percentage of the value advertised by the best external builder. Setting this flag to a non-zero value is recommended because the usage of an external builder introduces an additional risk that the advertised block won't be published by the builder:

  https://github.com/status-im/nimbus-eth2/pull/4749
  https://github.com/status-im/nimbus-eth2/pull/4795
  https://github.com/status-im/nimbus-eth2/pull/4847

* Nimbus now supports the standardized Builder API liveness failsafe mechanism:

  https://github.com/status-im/nimbus-eth2/pull/4746

* The `--sync-light-client` option is now enabled by default, providing significant speedups in beacon chain syncing and re-syncing:

  https://github.com/status-im/nimbus-eth2/pull/4805

* The `trustedNodeSync` command features a new `--trusted-block-root` option that leverages the Nimbus light client in order to minimize the required trust in the specified Beacon API endpoint. After downloading the state snapshot, the light client will verify that it conforms to the established consensus in the network. Note that the provided `--trusted-block-root` should be somewhat recent, and that additional security precautions such as comparing the state root against block explorers are still recommended.

  https://github.com/status-im/nimbus-eth2/pull/4736

* Improved scheduling mechanisms in the Nimbus validator client deliver stability and performance improvements:

  https://github.com/status-im/nimbus-eth2/pull/4743

* The `deposits exit` command can now be used to perform voluntary exits for multiple validators at once:

  https://github.com/status-im/nimbus-eth2/pull/4855
  https://nimbus.guide/voluntary-exit.html

* Nimbus now supports the [`/eth/v1/beacon/states/{state_id}/randao`](https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/getStateRandao) REST API endpoint:

  https://github.com/status-im/nimbus-eth2/pull/4799

* Nimbus now uses only the Capella-enabled `engine_forkchoiceUpdatedV2` endpoint in all communication with the execution layer:

  https://github.com/status-im/nimbus-eth2/pull/4817

### Fixes

* Nimbus has addressed a risk of missed block proposal due to incorrectly computed withdrawals at epoch boundaries:

  https://github.com/status-im/nimbus-eth2/pull/4820

* Nimbus has addressed a low probability risk of missed block proposals when the configured builder doesn't respond in time:

  https://github.com/status-im/nimbus-eth2/pull/4764/

* Nimbus has addressed a low probability risk of missed block proposals when a late block triggers a chain re-org while an `engine_forkchoiceUpdated` request to the execution layer is in flight:

  https://github.com/status-im/nimbus-eth2/pull/4800

* Nimbus will no longer experience occasional response timeouts when performing a large number of concurrent HTTP requests (e.g. when configured to operate with a large number of remote keystores):

  https://github.com/status-im/nim-presto/pull/44
  https://github.com/status-im/nim-chronos/pull/324
  https://github.com/status-im/nimbus-eth2/pull/4779

* The Nimbus validator client will no longer crash on start-up when supplied with incorrect beacon node configuration:

  https://github.com/status-im/nimbus-eth2/pull/4765

* Nimbus will no longer crash when there is a network mismatch between the imported slashing protection database and the specified data directory:

  https://github.com/status-im/nimbus-eth2/pull/4791

* Inactive validators will no longer affect the initial GossipSub topic subscriptions:

  https://github.com/status-im/nimbus-eth2/pull/4793

* Failed or timed out request to `engine_exchangeTransitionConfigurationV1` will no longer degrade the status of the connection to the execution layer:

  https://github.com/status-im/nimbus-eth2/pull/4831


2023-03-22 v23.3.2
==================

Nimbus `v23.3.2` is a `low-urgency`, but mandatory upgrade providing full-support for the upcoming Capella hard-fork on Mainnet. Please upgrade at your earliest convenience - **before the 12th of April**.

### Improvements

* The `deposits exit` can now be executed with a path to a keystore file that was generated by `deposit-staking-cli` or `ethdo`. All users are advised to use this method for exiting, due to a [known issue](https://github.com/status-im/nimbus-eth2/issues/4216) preventing the other formerly supported methods from working:

  https://nimbus.guide/voluntary-exit.html
  https://github.com/status-im/nimbus-eth2/pull/4753

* The metrics `beacon_light_client_finality_update_received`, `beacon_light_client_finality_update_dropped`, `beacon_light_client_optimistic_update_received` and `beacon_light_client_optimistic_update_dropped` provide information regarding the observed light client gossip traffic:

  https://github.com/status-im/nimbus-eth2/pull/4745

* Nimbus now recognizes the `/eth/v1/validator/beacon_committee_selections` and `/eth/v1/validator/sync_committee_selections` Beacon API end-points in accordance to the latest spec:

  https://github.com/status-im/nimbus-eth2/pull/4760

### Fixes

* Nimbus will no longer report warnings such as "Connection to EL node degraded" when paired with an execution node that hasn't been synced up to the deployment block of the validator deposit contract:

  https://github.com/status-im/nimbus-eth2/pull/4761

* Nimbus was sporadically triggering an inappropriate assertion error under normal operating conditions:

  https://github.com/status-im/nimbus-eth2/pull/4759


2023-03-14 v23.3.1
==================

Nimbus `v23.3.1` is a `medium-urgency` point release addressing a number of accidental configuration handling breaking changes that were shipped in the `v23.3.0` release. It also improves the stability of Nimbus when paired with a Besu execution client and improves the fault-tolerance when driving multiple execution clients.

### Fixes

* Nimbus was performing `eth_getLogs` request with parameters that were exceeding the default `--rpc-max-logs-range=1000` limit on Besu. This was a non-fatal issue that resulted in slower deposit syncing speed and the frequent warning message "Connection to EL node degraded". The limit will be increased in the next mainnet release of Besu, but Nimbus `v23.3.1` honours the existing limit at the cost of a slightly slower syncing speed with all other execution clients:

  https://github.com/status-im/nimbus-eth2/commit/6fb48aca7dedc7ba3c6b2f2ae8a4926ddcf7a00e

* `v23.3.0` did not support Engine API URLs which don't specify a protocol in the URL (e.g. `http`, `https`, `ws` or `wss`). `v23.3.1` is backwards-compatible with all previous Nimbus releases:

  https://github.com/status-im/nimbus-eth2/commit/3a35809a02b4fbe23b2dc843806ec81f67521c6d

* `v23.3.0` produced a parsing error on TOML configuration files that specify the `web3-url` parameter as an array of strings. `v23.3.1` is backwards-compatible with all previous Nimbus releases and introduces a new more convenient way for specifying the Engine API configuration in TOML:

  https://nimbus.guide/eth1.html#running-multiple-execution-clients
  https://github.com/status-im/nimbus-eth2/commit/46f48269ef899f19cd9932b27d30c68e2ccf035b

* `v23.3.0` removed the hidden configuration option `--web3-force-polling` which remained in use by some users. `v23.3.1` restores the option as a deprecated one. Please note that all hidden configuration options are intended for use only by the Nimbus development team for testing purposes:

  https://github.com/status-im/nimbus-eth2/commit/ee610cbf34cebea24576c25bf6702de4205a260a

* The release addresses a potential crash triggered by Engine API connections experiencing frequent error responses:

  https://github.com/status-im/nimbus-eth2/commit/d899a6a834c083a62e1246eade5027a7019ace82

* The release addresses a potential issue where a single non-synced execution client may cause the Nimbus sync state to revert to `synced/opt`, even when all validator duties can be performed through the remaining execution clients that are still synced:

  https://github.com/status-im/nimbus-eth2/commit/d899a6a834c083a62e1246eade5027a7019ace82


2023-03-11 v23.3.0
==================

Nimbus `v23.3.0` is a `low-urgency` upgrade bringing full support for the upcoming Capella hard-fork on the Goerli testnet. Keep an eye out for future mainnet releases!

### Improvements

* You can increase the resilience of your setup and eliminate any downtime during upgrade procedures of the execution client by allowing your beacon node to manage multiple execution clients. To enable this mode, just specify multiple URLs through the `--el` option (alias of `--web3-url`) when starting your beacon node:

  ```sh
  ./run-mainnet-beacon-node.sh \
    --el=http://127.0.0.1:8551 \
    --el=ws://other:8551 \
    --jwt-secret=/tmp/jwtsecret
  ```

  As long as any of execution clients remains operational and fully synced, Nimbus will keep performing all validator duties. To carry out an upgrade procedure without any downtime, just restart the execution clients one by one, waiting for each instance to re-sync before moving to the next one.

  If you use this mode with different execution client implementations, Nimbus will act as an execution layer consensus violation detector, preventing the publishing of blocks that may trigger a catastrophic partitioning in the network.

  https://github.com/status-im/nimbus-eth2/pull/4465
  https://nimbus.guide/eth1.html

* The metrics `engine_api_responses`, `engine_api_request_duration_seconds` and `engine_api_timeouts` provide statistics about latency and response status codes for all requests sent to each individual execution layer URL:

  https://github.com/status-im/nimbus-eth2/pull/4465
  https://github.com/status-im/nimbus-eth2/pull/4707

* Nimbus will now attempt to connect to a locally running execution client even when the options `--el` and `--jwt-secret` are not specified. This is made possible by the following proposed standard:

  https://github.com/ethereum/execution-apis/pull/302

  Please note that the standard hasn't been implemented in any execution client yet.

* Nimbus now support the latest version of the Builder API, adding support for the Capella hard-fork:

  https://github.com/status-im/nimbus-eth2/pull/4643

* Improved diagnostic messages and more spec-compliant behavior of the Nimbus validator client when being paired with a non-synced or optimistically synced beacon nodes:

  https://github.com/status-im/nimbus-eth2/pull/4643
  https://github.com/status-im/nimbus-eth2/pull/4657
  https://github.com/status-im/nimbus-eth2/pull/4673

* The Sqlite3 database engine has been upgraded to version 3.40.1:

  https://github.com/status-im/nimbus-eth2/pull/4649

### Fixes

* The doppelganger detection now acts safer after a period of lost network connectivity

  https://github.com/status-im/nimbus-eth2/pull/4616

* The doppelganger detection now acts safer in the presence of out-of-order responses from the beacon node:

  https://github.com/status-im/nimbus-eth2/pull/4691

* Nimbus can now export ERA files for the Sepolia network:

  https://github.com/status-im/nimbus-eth2/pull/4689

* The `--history=prune` mode will no longer interfere with serving light client data for the full retention period as mandated by the spec:

  https://github.com/status-im/nimbus-eth2/pull/4702

* Nimbus now downloads a longer range of recent execution blocks in order to avoid potential situations where our `Eth1Data` votes fail to agree with the honest majority in the network:

  https://github.com/status-im/nimbus-eth2/pull/4588

* Nimbus has addressed a potential interruption of deposit syncing when connected to Geth over WebSocket:

  https://github.com/status-im/nimbus-eth2/pull/4708


2023-02-16 v23.2.0
==================

Nimbus `v23.2.0` is a `low-urgency` upgrade providing full support for the upcoming
Capella hard-fork on the Sepolia testnet. Keep an eye out for future mainnet releases!

### Improvements

* Status now provides an APT repository that will host the latest version of the
  Nimbus beacon node and validator client software:
  https://apt.status.im/

* The `deposits import` command now provides the option `--method=single-salt` which
  will significantly improve the keystore loading speed on start-up on beacon nodes
  and validator clients running with a very large number of validators. Please see
  the documentation provided in the Nimbus guide in order to understand the security
  implications of using the option:
  https://nimbus.guide/keys.html#optimised-import-for-a-large-number-of-validators
  https://github.com/status-im/nimbus-eth2/pull/4372

* More efficient sync committee caching strategies bring 20-30% of syncing
  speed improvement post Altair:
  https://github.com/status-im/nimbus-eth2/pull/4592

* Nimbus performs fewer interactions with the EL node during optimistic syncing
  which further improves the syncing speed:
  https://github.com/status-im/nimbus-eth2/pull/4591

* The Keymanager API now supports all `gas_limit` end-points:
  https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit
  https://github.com/status-im/nimbus-eth2/pull/4612

* Nimbus serves light client updates up to the retention period mandated by
  the spec even when pruning is enabled:
  https://github.com/status-im/nimbus-eth2/pull/4499

* The Linux packages of Nimbus no longer depend on `lsb-release`:
  https://github.com/status-im/nimbus-eth2/pull/4597

* The list of bootstrap nodes for the Gnosis network has been expanded:
  https://github.com/status-im/nimbus-eth2/pull/4603

* Nimbus now performs fewer `forkchoiceUpdated` Engine API calls with lower risk
  of reporting conflicting data to the EL node:
  https://github.com/status-im/nimbus-eth2/pull/4609
  https://github.com/status-im/nimbus-eth2/pull/4614
  https://github.com/status-im/nimbus-eth2/pull/4623

### Fixes

* Nimbus will no longer suffer from performance issues when a large number of
  non-active validators are imported in the beacon node or the validator client:
  https://github.com/status-im/nimbus-eth2/pull/4590

* Nimbus will no longer crash when it fails to resolve the hostname of a remote
  validator imported through the Keymanager API:
  https://github.com/status-im/nimbus-eth2/pull/4590

* The Nimbus validator client won't attempt to perform sync committee duties when
  the attached beacon node is only optimistically synced:
  https://github.com/status-im/nimbus-eth2/pull/4622


2023-01-25 v23.1.1
==================

Nimbus `v23.1.1` is a `high-urgency` hotfix for users who have already enabled block
history pruning after upgrading to `v22.3.0`. It fixes an issue where the client may
fail to start after the database has been pruned.

### Fixes:

* A crash on start-up after running the client with `--history:prune` option - "backfill block must have a summary".
  https://github.com/status-im/nimbus-eth2/pull/4554

* The `validator-monitor-details` option was accidentally enabled by default in 23.1.0,
  which lead to significant increase in resource usage.


2023-01-18 v23.1.0
==================

Nimbus `v23.1.0` is a `low-urgency` upgrade, introducing support for on-the-fly database pruning making the storage requirements of Nimbus much more predictable on long-term time scales. When pruning is enabled, a typical beacon node expected to consume around 60 to 70 GB of storage. To take advantage of the new functionality without facing any downtime, users are advised to sync a fresh node through trusted node sync which now features a quicker history backfilling implementation.

### Improvements

* After a trusted node sync, Nimbus requires less time to complete the block
  backfilling process by downloading the minimum number of historical blocks
  mandated by the spec:

  https://github.com/status-im/nimbus-eth2/pull/4421

* Nimbus is able to sync in optimistic mode with the network even when not
  paired with an execution layer client. Please note that this mode is not
  suitable for validating:

  https://github.com/status-im/nimbus-eth2/pull/4458

* A new `--history=<archive|prune>` configuration parameter controls the
  retention of old historic blocks in the database of the client. Enabling
  pruning on an existing installation will introduce a significant delay
  on the first run, while history pruning is taking place, so we recommend
  starting with a fresh database by executing a trusted node sync:

  https://nimbus.guide/history.html
  https://github.com/status-im/nimbus-eth2/pull/4445

* The validator monitor is now considered out of BETA and enabled by default.
  To keep the number of created metrics to a reasonable level on installations
  with large number of validators, the default implies the previous behavior
  of the `validator-monitor-totals` flag:

  https://github.com/status-im/nimbus-eth2/pull/4468

* Full support for the latest Capella/Shanghai devnets:

  https://notes.ethereum.org/@bbusa/Zhejiang#Nimbus

### Fixes

* Out of date metadata for the Gnosis network bootstrap nodes:

  https://github.com/status-im/nimbus-eth2/pull/4460

* Potential hanging of the client caused by inappropriate activation
  of the TTD block detection on beacon nodes created after the merge:

  https://github.com/status-im/nimbus-eth2/pull/4486

* Inappropriate case-sensitivity in the `--log-level` parameter, accidentally introduced in the 22.12.0 release.

  https://github.com/status-im/nimbus-eth2/pull/4523


2022-12-21 v22.12.0
===================

Nimbus `v22.12.0` is a `medium-urgency` release which improves the doppelganger detection in the Nimbus validator through the use of standardized APIs that are compatible with all third-party beacon nodes. Furthermore, it addresses several inconsistencies in the behavior between the stand-alone beacon node and the validator client. This release also allows users of trusted node sync to skip downloading the entire history of validator deposits by syncing against a server that supports the standardized `/eth/v1/beacon/deposit_snapshot` REST endpoint.

### Improvements

* 60% more efficient block replaying speed brings faster REST responses and
  more resilience on the network in the face of heavy forking activity and
  non-finalization:

  https://github.com/status-im/nimbus-eth2/pull/4435

* Support for obtaining a deposit snapshot during trusted node sync from
  servers supporting the standardized `/eth/v1/beacon/deposit_snapshot`
  REST endpoint:

  https://github.com/status-im/nimbus-eth2/pull/4303

* Official docker images for the Nimbus validator client are now available:

  https://hub.docker.com/r/statusim/nimbus-validator-client
  https://github.com/status-im/nimbus-eth2/pull/4439

* The `skip_randao_verification` query parameter is now also supported in
  the `/eth/v1/validator/blinded_blocks/{slot}` API endpoint:

  https://github.com/status-im/nimbus-eth2/pull/4435

* The doppelganger detection in the Nimbus validator client is now based on
  the standardized `/eth/v1/validator/liveness/{epoch}` REST endpoint:

  https://github.com/status-im/nimbus-eth2/pull/4381

* The validator client will now use with the standard exit code `129` in
  case of detected doppelganger on the network:

  https://github.com/status-im/nimbus-eth2/pull/4398

### Fixes

* A potential false-positive in the doppelganger detection logic:

  https://github.com/status-im/nimbus-eth2/pull/4398

* A potential hang in trusted node sync:

  https://github.com/status-im/nimbus-eth2/pull/4303

### Breaking changes:

* The built-in support for the Ropsten testnet has been removed:

  https://github.com/status-im/nimbus-eth2/pull/4280

  You can still connect to the Ropsten network by specifying its
  metadata directory on the command line through the `--network`
  parameter.

* The `statusim/nimbus-eth2` docker image no longer includes the
  `nimbus_validator_client` binary and the shell scripts included
  in the release tarballs. Please use the new dedicated image for
  the Nimbus validator client.


2022-12-12 v22.11.1
===================

Nimbus `v22.11.1` is a `high-urgency` hotfix for all users who are
running validators backed by remote keystores and web3signer.
This update addresses a compatibility issue that may result in
missed block proposals. If you are not using a remote signer,
you can safely skip this release.

### Fixes

* Incompatible encoding used in the web3signer block signing requests
  after the merge:
  https://github.com/status-im/nimbus-eth2/pull/4407

* Ignored `graffiti` option of the validator client:
  https://github.com/status-im/nimbus-eth2/pull/4417


2022-11-30 v22.11.0
===================

Nimbus `v22.11.0` is a `low-urgency` release, bringing the first
production-ready version of the [Nimbus validator client][1].
The validator client will enable advanced users such as professional
institutional operators to take advantage of features such as support
for [redundant beacon nodes][2], [enhanced validator privacy][3] and
[distributed keystores][4]. Meanwhile, existing users still can use
the streamlined stand-alone beacon node setup, as this mode of operation
will continue to be supported and improved.

[1]: https://nimbus.guide/validator-client.html
[2]: https://nimbus.guide/validator-client-options.html#multiple-beacon-nodes
[3]: https://nimbus.guide/validator-client-options.html#sentry-node-setup
[4]: https://github.com/status-im/nimbus-eth2/issues/3416

### Improvements

* The Nimbus validator client graduates from BETA to production-ready
  status after numerous improvements and fixes:

  https://nimbus.guide/validator-client.html

* The Nimbus beacon node is now compatible with validator clients
  taking advantage of the `/eth/v1/beacon/blinded_blocks` end-point:

  https://github.com/status-im/nimbus-eth2/pull/4286

* The validator keystore loading during start-up is now 3x faster:

  https://github.com/status-im/nimbus-eth2/pull/4301

* The doppelganger detection now protects validators added
  on the fly through the Keymanager API:

  https://github.com/status-im/nimbus-eth2/pull/4304

* Fine-tuned internal task scheduling can provide better
  quality-of-service protections for performing all validator
  duties in the presence of syncing peers performing large
  number of concurrent block download requests:

  https://github.com/status-im/nimbus-eth2/pull/4254

* The `--optimistic` mode of the beacon node allows you to
  stay synced with the network even without an execution layer
  node:

  https://nimbus.guide/optimistic-sync.html#optimistic-mode
  https://github.com/status-im/nimbus-eth2/pull/4262

  Please note that this mode is less secure and intended only
  for non-critical information retrieval through the Beacon API.

* The Nimbus build for the Gnosis chain (available  when compiling
  from source) has full support for the upcoming merge:

  https://github.com/status-im/nimbus-eth2/pull/4330
  https://forum.gnosis.io/t/gip-16-gnosis-chain-xdai-gnosis-merge/1904

* The stand-alone light client (available when compiling from source)
  now preserves progress between restarts:

  https://github.com/status-im/nimbus-eth2/pull/4371

### Fixes

* A small risk for missing block proposals was present under heavy
  forking activity in the network due to potential inclusion of
  inappropriate attestations in the produced blocks:

  https://github.com/status-im/nimbus-eth2/pull/4273

* A new batching approach for the registration of validators in the
  builder network will prevent the creation of requests of excessive
  size that might be rejected by the network. This was a problem
  affecting testnet nodes running with thousands of validators:

  https://github.com/status-im/nimbus-eth2/pull/4364


### Deprecated features

* The `--finalized-checkpoint-block` has been deprecated.
  The client will now download only the latest finalized state
  during trusted node sync:

  https://github.com/status-im/nimbus-eth2/pull/4251

* The end-points `/eth/v1/beacon/blocks/{block_id}`, `/eth/v1/debug/beacon/states/{state_id}`, and `/eth/v1/validator/blocks/{slot}`
  have been deprecated since they are no longer usable since
  the Altair hard-fork:

  https://github.com/status-im/nimbus-eth2/pull/4279


2022-10-14 v22.10.1
===================

Nimbus `v22.10.1` is a `low-urgency` point release introducing support for the official light client REST API and improving the stability of Nimbus when paired with an external block builder.

### Improvements

* Support for the official light client REST API:
  https://github.com/ethereum/beacon-APIs/pull/247
  https://github.com/status-im/nimbus-eth2/pull/4213
  https://github.com/status-im/nimbus-eth2/pull/4232

### Fixes:

* Nimbus was slowly leaking file descriptors when paired with an external builder:
  https://github.com/status-im/nimbus-eth2/pull/4235

* Nimbus could potentially crash under a poor network connectivity to the external builder:
  https://github.com/status-im/nimbus-eth2/pull/4222


2022-10-03 v22.10.0
===================

Nimbus `v22.10.0` is a `medium-urgency` release, continuing our briefly accelerated release schedule and bringing further stability and performance improvements after the merge.

### Improvements

* Faster block production, bringing practical benefits on low-powered devices such as the Raspberry Pi:
  https://github.com/status-im/nimbus-eth2/pull/4184
  https://github.com/status-im/nimbus-eth2/pull/4196

* The Nimbus validator client can now work with multiple beacon nodes with configurable responsibilities:
  https://github.com/status-im/nimbus-eth2/pull/4113
  https://github.com/status-im/nimbus-eth2/issues/4140

* The `/eth/v2/validator/blocks/{slot}` API now features an optional `randao_reveal` parameter in accordance to the latest Beacon API spec:
  https://github.com/ethereum/beacon-APIs/pull/222
  https://github.com/status-im/nimbus-eth2/pull/3837

* The `/eth/v1/beacon/blocks` API now supports SSZ-encoded payloads:
  https://github.com/status-im/nimbus-eth2/pull/4154

* The new metrics `beacon_block_builder_proposed`, `beacon_block_builder_missed_with_fallback` and `beacon_block_builder_missed_without_fallback` can help you track the successful and failed attempts to use the configured external block builder:
  https://github.com/status-im/nimbus-eth2/pull/4158

### Fixes

* Rare, but critical conditions manifesting primarily in the Goerli network were leading to an unrecoverable database corruption:
  https://github.com/status-im/nimbus-eth2/pull/4174
  https://github.com/status-im/nimbus-eth2/pull/4192

* If the chain was re-orged while Nimbus is shut down, this created a low risk that the client may become stuck on a non-canonical block:
  https://github.com/status-im/nimbus-eth2/pull/4161

* Nimbus was not serving the best possible light client updates when back-filling after a trusted node sync:
  https://github.com/status-im/nimbus-eth2/pull/4195

### Upcoming breaking changes

* The pre-altair REST API paths `/eth2/beacon_chain/req/beacon_blocks_by_{range,root}/1/` are now deprecated and will be removed in the next Nimbus version. Since these APIs support only phase0 responses, it is unlikely that there are any remaining clients using them.


2022-09-20 v22.9.1
==================

Nimbus `v22.9.1` is a `medium-urgency` upgrade addressing several frequently reported issues after the merge and bringing minor performance improvements in the post-merge world.

### Breaking changes

* Nimbus no longer supports the non-standard `/api/` prefix for the Beacon REST API. All users should migrate to the standardized `/eth/` prefix:
  https://github.com/status-im/nimbus-eth2/pull/4115

### Improvements

* Implemented the `/eth/v1/validator/register_validator`, enabling the use of an external block builder when the Nimbus beacon node is used with a validator client:
  https://github.com/status-im/nimbus-eth2/pull/4115

* The expensive TTD block detection is no longer performed when the client is launched after the merge:
  https://github.com/status-im/nimbus-eth2/pull/4152
  https://github.com/status-im/nimbus-eth2/pull/4129

* Peer scoring improvements will result in a more stable peer connectivity during syncing:
  https://github.com/status-im/nimbus-eth2/pull/3381
  https://github.com/status-im/nimbus-eth2/pull/4090

* The Nimbus peer metrics can now properly track the number of Lodestar peers:
  https://github.com/status-im/nimbus-eth2/pull/4108

* Fee recipient configuration, applied through the Keymanager API remains active even after disabling the Keymanager API in a consecutive run:
  https://github.com/status-im/nimbus-eth2/pull/4078

* Improved support for working with custom networks:
  https://github.com/status-im/nimbus-eth2/pull/4132
  https://github.com/status-im/nimbus-eth2/pull/4134

### Fixes

* Using an HTTP connection to the EL client will no longer result in sporadic crashes:
  https://github.com/status-im/nimbus-eth2/pull/4125

* Nimbus will no longer trigger warnings or errors regarding an invalid terminal block hash during transition configuration exchanges:
  https://github.com/status-im/nimbus-eth2/pull/4126

* The initial transition configuration exchange is performed after a short delay to give more time for the EL client to initialize when all services are started at the same time:
  https://github.com/status-im/nimbus-eth2/pull/4114

* The Nimbus beacon node service installed by our DEB and RPM packages will now use the correct Engine API port by default (8551 instead of 8546):
  https://github.com/status-im/nimbus-eth2/pull/4099

* Nimbus has better compatibility now with various beacon API servers used for trusted node sync (such as Prysm and Alchemy):
  https://github.com/status-im/nimbus-eth2/pull/4133
  https://github.com/status-im/nimbus-eth2/pull/4139

* Nimbus was delivering incorrect head block details through the events API:
  https://github.com/status-im/nimbus-eth2/issues/4119
  https://github.com/status-im/nimbus-eth2/pull/4141

* Nimbus can now import keystores exported from ethdo or Prysm:
  https://github.com/status-im/nimbus-eth2/pull/4149


2022-09-07 v22.9.0
==================

Nimbus `v22.9.0` is a `high-urgency` upgrade that fixes a critical pre-TTD block production issue affecting users that restarted their node after Bellatrix. It also improves compatibility with Besu, Prysm and slow block builders and provides a speed boost in block processing important for those running on Raspberry Pi and similar hardware.

With the merge drawing near, the focus of this release has been to include low risk changes that improve stability and compatibility - if you are unsure whether to upgrade, do reach out to us in discord to discuss your particular deployment.

A shout out to our great community for reporting and helping diagnose the issues that led up to this release - in particular Michael Sproul (Lighthouse) and Joe Clapis (Rocket Pool).

### Improvements

* Allow more time for block builder to deliver block
  [#4088](https://github.com/status-im/nimbus-eth2/pull/4088)

* Improve Bellatrix block processing performance
  [#4085](https://github.com/status-im/nimbus-eth2/pull/4085) and [#4082](https://github.com/status-im/nimbus-eth2/pull/4082)

* Optimize execution layer calls when not producing blocks, improving Besu performance and compatiblity
  [#4055](https://github.com/status-im/nimbus-eth2/pull/4055)

* Revise timing of execution layer configuration call, resolving warnings that no consensus client is present on Geth and Besu
  [#4077](https://github.com/status-im/nimbus-eth2/pull/4077)

* Log `Exchanged engine configuration` when first connected to correctly configured execution engine
  [#4096](https://github.com/status-im/nimbus-eth2/pull/4096)

* Switch to `nim-websock` for websocket connections, resolving delays when payloads exceed 1mb
  [#4061](https://github.com/status-im/nimbus-eth2/pull/4061)

### Fixes

* Fix pre-TTD block proposals on nodes that (re-)started after Bellatrix
  [#4094](https://github.com/status-im/nimbus-eth2/issues/4094)

* Fix gossip message id, improving connectivity health with Prysm
  [#4076](https://github.com/status-im/nimbus-eth2/pull/4076)

* Improve handling of blocks deemed invalid by the execution layer
  [#4081](https://github.com/status-im/nimbus-eth2/pull/4081)

* Fix a rare crash that could happen when execution layer disconnected
  [#4095](https://github.com/status-im/nimbus-eth2/pull/4095)

2022-08-31 v22.8.2
==================

Nimbus `v22.8.2` is a `low-urgency` hotfix release, eliminating a risk for potential crash during block production that was introduced in the `v22.8.1` release. You can safely skip this release if you haven't enabled DEBUG logging on your beacon node, as the risk exists only when DEBUG logging is enabled.

### Improvements:

* Reduced CPU usage for validator registration when using an external builder:
  https://github.com/status-im/nimbus-eth2/pull/4040

### Fixes:

* A potential crash during block production when DEBUG logging is enabled:
  https://github.com/status-im/nimbus-eth2/pull/4054


2022-08-30 v22.8.1
==================

Nimbus `v22.8.1` is a `high-urgency` upgrade, improving the stability and performance of Nimbus in post-merge networks. Upgrading is highly recommended due to improved timing of the interactions with the execution engine which may lead to higher profitability from block production, especially for users running Nethermind.

### Improvements

* More timely block proposals in the presence of a non-responsive builder node:
  https://github.com/status-im/nimbus-eth2/pull/4012

* More timely delivery of fork-choice update information to the execution client, enabling the production of more profitable blocks:
  https://github.com/status-im/nimbus-eth2/pull/4012

* Improved SHA256 hashing performance resulting in a minor overall CPU usage reduction:
  https://github.com/status-im/nimbus-eth2/pull/4017

* Reduced latency in the light client when following the head of the chain optimistically:
  https://github.com/status-im/nimbus-eth2/pull/4002

* Spec-compliant delivery of the "safe block hash" property of the "fork-choice update" messages sent to the Engine API:
  https://github.com/status-im/nimbus-eth2/pull/4010

* Relax overly aggressive gossip filtering conditions for incoming blocks:
  https://github.com/status-im/nimbus-eth2/pull/4044

* New metrics `beacon_block_production_errors` and`beacon_block_payload_errors` for detecting non-healthy operation of the Engine API:
  https://github.com/status-im/nimbus-eth2/pull/4036

### Fixes

* Sporadic loss of connectivity to the execution engine in the presence of large payloads:
  https://github.com/status-im/nimbus-eth2/pull/4028

* Inappropriate loss of connectivity to honest peers in the presence of a non-responding execution client:
  https://github.com/status-im/nimbus-eth2/pull/4020

* A loophole allowing the inclusion of very old and invalid slashing and exit messages within blocks:
  https://github.com/status-im/nimbus-eth2/pull/4013

* Confusing error message when trusted node sync is executed with an invalid REST URL:
  https://github.com/status-im/nimbus-eth2/pull/4024


2022-08-23 v22.8.0
==================

Nimbus `v22.8.0` is a `medium` urgency release, featuring full support for the upcoming mainnet merge! All users should upgrade at their earliest convenient, but no later than 5th of September.

> Since the network will go through the Bellatrix hard-fork on Sept 6, 2022, 11:34:47am UTC, failure to upgrade in time will result in inactivity penalties.

Please note that once the network reaches the terminal total difficulty (currently estimated to happen between 13th and 15th of September), it will no longer be possible to operate a beacon node without pairing it with a single non-shared merge-ready execution client. Nimbus is fully compatible will all execution clients and the required configuration steps for all of them are the same. Please refer to our merge guide for more details:

https://nimbus.guide/merge.html

To raise awareness of the required configuration changes, once the Bellatrix fork is activated on 6th of September, Nimbus will refuse to start unless a properly configured and authenticated Engine API end-point is provided through the command-line options `--web3-url` and `--jwt-secret`. If you need more time to complete the transition, you can temporarily run the beacon node with the command-line option `--require-engine-api-in-bellatrix=no`, but please note that such a setup will stop working once the network TTD is reached!

We would like to say a huge THANK YOU to all of our users who provided immensely valuable feedback in the many months of hard work leading to the merge and to all the fellow research and implementation teams who made this historic release possible!

Onwards and happy merging!

### Breaking changes

* Nimbus will refuse to start unless connected to a properly configured execution client in Bellatrix-enabled networks:
  https://github.com/status-im/nimbus-eth2/pull/4006

* The custom error code returned by Nimbus when a validator doppelganger is detected has been changed from 1031 to 129 to improve compatibility with `systemd`:
  https://github.com/status-im/nimbus-eth2/pull/3977

### Improvements

* Support for external block builders (a.k.a. MEV):
  https://github.com/status-im/nimbus-eth2/pull/3883

* Beta release for the Nimbus stand-alone light client, which can be used to drive any execution client without requiring a full-blown beacon node:
  https://nimbus.guide/light-client-data.html

* The first spec-compliant implementation of the LibP2P protocols for serving light client data:
  https://nimbus.guide/light-client-data.html

* Keystore locking prevents accidentally loading the same validator keys in multiple instances of the Nimbus beacon node and the Nimbus validator client, thus eliminating a potential slashing risk:
  https://github.com/status-im/nimbus-eth2/pull/3907

* Debian and RPM packages for the Nimbus beacon node and the Nimbus validator client are now available as part of the release. In the near future, Status will also provide a package repository, offering a more convenient installation:
  https://github.com/status-im/nimbus-eth2/pull/3974
  https://github.com/status-im/infra-nimbus/issues/79

* Improved performance on networks with heavy forking activity through a reduction of the required state replays:
  https://github.com/status-im/nimbus-eth2/pull/3990

* The Nimbus validator client now supports validator activity metrics such as `beacon_attestations_sent`, `beacon_aggregates_sent`, `beacon_attestation_sent_delay`, `beacon_blocks_sent`, `beacon_blocks_sent_delay`, `beacon_sync_committee_messages_sent`, `beacon_sync_committee_message_sent_delay`, `beacon_sync_committee_contributions_sent`:
  https://github.com/status-im/nimbus-eth2/pull/3915

* The sync status displayed in the Nimbus status bar and certain log messages now describes the state of the client more accurately (optimistically synced vs fully synced):
  https://github.com/status-im/nimbus-eth2/pull/3987

### Fixes

* Spec violation in the expected payload of the `/eth/v1/validator/prepare_beacon_proposer` Beacon API end-point:
  https://github.com/status-im/nimbus-eth2/pull/3938

* Invalid empty execution payloads being produced when the execution client is not responding:
  https://github.com/status-im/nimbus-eth2/pull/3991

* Potentially incorrect Eth1 block votes, disagreeing with the forming majority:
  https://github.com/status-im/nimbus-eth2/pull/3944

* More resilient deposit synchronization when Nimbus is paired with a highly loaded execution client:
  https://github.com/status-im/nimbus-eth2/pull/3943
  https://github.com/status-im/nimbus-eth2/pull/3957

* A potential delay in detecting the terminal total difficulty block:
  https://github.com/status-im/nimbus-eth2/pull/3956

* Missing Gossip filtering rule for sync committee contributions resulting in unnecessary traffic:
  https://github.com/status-im/nimbus-eth2/pull/3941

* Compatibility issue preventing trusted node sync from Lodestar nodes:
  https://github.com/status-im/nimbus-eth2/pull/3934

* A potential crash while processing rare gossip messages such as slashings and exits:
  https://github.com/status-im/nimbus-eth2/issues/3965

* Inappropriate attestations sent by the validator client when the connected beacon node is only optimistically synced:
  https://github.com/status-im/nimbus-eth2/pull/3968


2022-07-26 v22.7.0
==================

Nimbus `v22.7.0` is a `low` urgency release packing everything necessary for the [upcoming Prater/Goerli merge](https://wenmerge.com/) and introducing the [Nimbus validator client](https://nimbus.guide/validator-client.html) (currently in BETA).

### Other Improvements

* Support for fee recipient management through the [Keymanager API](https://ethereum.github.io/keymanager-APIs/#/Fee%20Recipient) and
  through the [`/eth/v1/validator/prepare_beacon_proposer`](https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconProposer) Beacon API end-point:
  https://github.com/status-im/nimbus-eth2/pull/3864
  https://github.com/status-im/nimbus-eth2/pull/3901

* Support for the post-merge optimistic sync specification:
  https://github.com/status-im/nimbus-eth2/pull/3793

* More comprehensive spec-compliance in our fork-choice implementation:
  https://github.com/status-im/nimbus-eth2/pull/3849

* More spec-compliant handling of `QUANTITY` values within the Engine API responses:
  https://github.com/status-im/nim-web3/pull/55
  https://github.com/status-im/nimbus-eth2/issues/3844

* The `Slot end` log message now includes information regarding current and
  upcoming sync committee duties to help you identify the most appropriate
  time to restart the client during an upgrade:
  https://github.com/status-im/nimbus-eth2/pull/3854

* Specifying a `WEB3_URL` environment variable is no longer mandatory
  when launching beacon nodes with the `run-*-beacon-node.sh` scripts:
  https://github.com/status-im/nimbus-eth2/pull/3810

* The `--finalized-checkpoint-state` and the `--finalized-checkpoint-block`
  command-line parameters can no longer be used with certain invalid inputs:
  https://github.com/status-im/nimbus-eth2/pull/3858

* Specifying `--network=goerli` is now equivalent to specifying `--network=prater`:
  https://github.com/status-im/nimbus-eth2/pull/3874

### Fixes

* A risk for invalid block proposals during high forking activity in the
  network due to inappropriate inclusion of attestations from other forks:
  https://github.com/status-im/nimbus-eth2/pull/3893

* Interrupted tracking of deposits, triggered by a non-responsive web3 end-point:
  https://github.com/status-im/nimbus-eth2/pull/3905

* Inappropriate error returned by the REST API when broadcasting of Gossip
  messages is not immediately possible:
  https://github.com/status-im/nimbus-eth2/pull/3843

* Rare conditions under which P2P connections were closed inappropriately:
  https://github.com/status-im/nimbus-eth2/pull/3795

* Potential inaccuracies in the `next_action_wait` metric:
  https://github.com/status-im/nimbus-eth2/pull/3862


2022-06-29 v22.6.1
==================

Nimbus `v22.6.1` is a `low-urgency` release which comes pre-configured with the correct TTD value for the Sepolia network and improves the behavior of Nimbus in merge testnets.

### Improvement

* Allow testing the Engine API JWT credentials even before the merge:
  https://github.com/status-im/nimbus-eth2/pull/3786

### Fixes

* Lack of detection of the connected execution client's network when attached to the Engine API port:
  https://github.com/status-im/nimbus-eth2/pull/3804

* Logic error leading to a premature start of the `exchange transition configuration` Engine API requests:
  https://github.com/status-im/nimbus-eth2/pull/3809

* Inappropriate inclusion of the `execution_optimistic` field in REST responses before the merge:
  https://github.com/status-im/nimbus-eth2/pull/3807


2022-06-20 v22.6.0
==================

Nimbus `v22.6.0` brings support for the merge testnets Ropsten and Sepolia (please stay tuned for TTD announcements for the latter) and a lot of polish where we've taken the time to address a long list of UX improvements and bug fixes suggested or reported by our users. We are deeply grateful to everybody who contributed valuable feedback for this release.

### Improvements

* TTD detection and Panda art for the merge!
  https://github.com/status-im/nimbus-eth2/pull/3670
  https://github.com/status-im/nimbus-eth2/pull/3745

* The execution layer priority fees recipient address can be configured individually for each validator:
  https://github.com/status-im/nimbus-eth2/pull/3652

* Through better defaults, the parameters `--rest-url`, `--trusted-node-url` can be omitted if the targeted node is running on the same machine:
  https://github.com/status-im/nimbus-eth2/pull/3689

* Improved spec-compliance with the Beacon API and the Engine API as defined after the merge:
  https://github.com/status-im/nimbus-eth2/pull/3679
  https://github.com/status-im/nimbus-eth2/pull/3780

* The custom error code `129` will signal a detected doppelganger on the network. This can be handled in the Nimbus's service supervisor to prevent an automatic restart:
  https://github.com/status-im/nimbus-eth2/pull/3728

* The Nimbus status bar can be configured to display the current version number:
  https://github.com/status-im/nimbus-eth2/pull/3747

* Specifying the `--terminal-total-difficulty-override` parameter is no longer necessary for the Ropsten network:
  https://github.com/status-im/nimbus-eth2/pull/3754

* Built-in support for the Sepolia network which will launch on June 20th and reach TTD shortly after:
  https://github.com/status-im/nimbus-eth2/pull/3762

* More robust syncing with the connected execution layer node in Bellatrix-enabled networks:
  https://github.com/status-im/nimbus-eth2/pull/3759

* The `web3 test` command is now compatible with nodes that have been configured to serve only the Engine API:
  https://github.com/status-im/nimbus-eth2/pull/3761

### Fixes

* A rare crash triggered when using a HTTP web3 URL:
  https://github.com/status-im/nimbus-eth2/pull/3669

* ERA checkpoint sync failing with "Backfill block must have a summary":
  https://github.com/status-im/nimbus-eth2/pull/3675

* Incorrect sync progress indicator shortly after a trusted node sync:
  https://github.com/status-im/nimbus-eth2/pull/3736

* Incorrect values returned by the `/eth/v1/node/syncing` API under rare circumstances:
  https://github.com/status-im/nimbus-eth2/pull/3720

* Misleading log message when an attestation was not delivered to any peer:
  https://github.com/status-im/nimbus-eth2/pull/3737

* Incorrect handling of case-sensitive web3 URLs:
  https://github.com/status-im/nimbus-eth2/pull/3757

* Incorrect encoding of the `current_epoch_participation` and `previous_epoch_participation` fields in the REST requests returning `BeaconState` results:
  https://github.com/status-im/nimbus-eth2/pull/3776

* Incorrect URL for the Keymanager delete keystores request:
  https://github.com/status-im/nimbus-eth2/pull/3727

* Non-standard encoding required by the Keymanager API for the import keystores request:
  https://github.com/status-im/nimbus-eth2/pull/3768

* A significant source of omitted events in the REST events API:
  https://github.com/status-im/nimbus-eth2/pull/3664

* Incorrect parsing of the `weak-subjectivity-checkpoint` parameter:
  https://github.com/status-im/nimbus-eth2/pull/3765

* Lack of support for trailing commas in lists and inline tables in the TOML config files:
  https://github.com/status-im/nim-toml-serialization/pull/47


### Removed functionality

* The Nimbus-specific JSON-RPC service which was deprecated in version v22.3.0 is now removed. If you are currently relying on the JSON-RPC API, please consider switching to the official [REST API](https://nimbus.guide/rest-api.html). Using any of the `--rpc` flags will now result in a warning:
  https://github.com/status-im/nimbus-eth2/pull/3656


2022-05-30 v22.5.2
==================

Nimbus `v22.5.2` is a `low-urgency` maintenance release updating Ropsten testnet support.

### Fixes:

* Modify proposer boost from 70% to 40% to improve network consensus:
  https://github.com/status-im/nimbus-eth2/commit/14dc3855f6cd06579294322a6ed206f678c8530f

* Update Ropsten TTD to a large enough number it can't be readily triggered by mining:
  https://github.com/status-im/nimbus-eth2/pull/3668

2022-05-20 v22.5.1
==================

Nimbus `v22.5.1` is a `low-urgency` maintenance release addressing a Web3 compatibility regression and introducing Ropsten testnet support.

### Improvements:

* Support for the Ropsten testnet, intended for merge testing:
  https://github.com/status-im/nimbus-eth2/pull/3648

### Fixes:

* Restore compatibility with certain Web3 endpoints:
  https://github.com/status-im/nimbus-eth2/pull/3645

* More spec-compliant handling of JSON fields in REST, for better compatibility with added and optional fields:
  https://github.com/status-im/nimbus-eth2/pull/3647

2022-05-17 v22.5.0
==================

Nimbus `v22.5.0` is a `low-urgency` maintenance release. It implements the proposer boosting fork-choice policy and is compliant with the latest [Bellatrix specifications](https://github.com/ethereum/consensus-specs#bellatrix-also-known-as-the-merge). It also provides an early preview of our built-in support for [BLS threshold signatures](https://notes.ethereum.org/@djrtwo/blst-rfp) (via regular Web3Signer instances): this marks the first step of our long-term [secret-shared validators roadmap](https://github.com/status-im/nimbus-eth2/issues/3416) which enables node operators / staking pools to deploy Nimbus in secure high availability setups (guaranteeing ~100% uptime).

### Improvements:

* A safer fork-choice algorithm which implements the proposer boosting policy:
  https://github.com/ethereum/consensus-specs/pull/2353
  https://github.com/status-im/nimbus-eth2/pull/3565

* A completely revamped snappy implementation which brings significant speed-ups:
  https://github.com/status-im/nimbus-eth2/pull/3564

* Support for the latest Bellatrix specifications (a.k.a. The Merge) + all Kiln testnets:
  https://github.com/status-im/nimbus-eth2/pull/3590

* An initial preview release fеaturing built-in support for distributed keystores, (part of our [secret shared validators roadmap]( https://github.com/status-im/nimbus-eth2/issues/3416)):
  https://github.com/status-im/nimbus-eth2/pull/3616

* Reduced CPU usage when serving blocks to other syncing clients:
  https://github.com/status-im/nimbus-eth2/pull/3598

* A more spec-compliant implementation of the `/eth/v1/config/spec` REST end-point (implementing the v1.1.10 version of the spec):
  https://github.com/status-im/nimbus-eth2/pull/3614

* Improved compatibility with all versions of Web3Signer:
  https://github.com/status-im/nimbus-eth2/pull/3640

### We've fixed:

* The potential for missed block proposals in the case where an invalid deposit is submitted to the deposit contract:
  https://github.com/status-im/nimbus-eth2/pull/3607
  https://github.com/status-im/nimbus-eth2/pull/3639

* A crash triggered by the use of Web3Signer remote keystores:
  https://github.com/status-im/nimbus-eth2/pull/3616

* A rare crash triggered when Nimbus is performing a large number of concurrent HTTP requests:
  https://github.com/status-im/nim-chronos/pull/272
  https://github.com/status-im/nim-chronos/pull/273


2022-04-12 v22.4.0
==================

Nimbus `v22.4.0` is a `low-urgency` upgrade which brings with it further optimisations, and better user experience around [trusted node sync](https://nimbus.guide/trusted-node-sync.html). It lays the foundations for upcoming the merge hard-fork which will be fully supported in our next release (`v22.5.0`).

### Improvements:

* All CPU cores are now used by default: previously enabled by passing `--num-threads:0` on the command-line:
  https://github.com/status-im/nimbus-eth2/pull/3493

* 250 MB reduction in memory usage:  thanks to more efficient data structures for the finalized portion of the chain history:
  https://github.com/status-im/nimbus-eth2/pull/3513

* Higher performance historic queries (using REST API) after trusted node sync: Nimbus now re-indexes the backfilled chain of blocks:
  https://github.com/status-im/nimbus-eth2/pull/3452

*  Broadcasted attestations are more likely to be included in blocks by other nodes: thanks to a tweak to the attestation sending time:
  https://github.com/status-im/nimbus-eth2/pull/3518

* The REST API now *only* returns current and relevant information in response to VC queries: in other words, information from the recent non-finalized portion of the chain history:
  https://github.com/status-im/nimbus-eth2/pull/3538

* Better and more consistent gossip mesh health: the `--max-peers` option now works as a target that can be exceeded by the client temporarily in order to maintain good gossip mesh health; the newly introduced `--hard-max-peers` option now acts as the hard limit that should not be exceeded (default set to `max-peers * 1.5`):
  https://github.com/status-im/nimbus-eth2/pull/3346

* An [ERA files](https://our.status.im/nimbus-update-march/#era-files-a-proposed-solution-to-historical-data-queries) developer preview: ERA files are an ultra-efficient long-term storage format for finalized chain history:
  https://github.com/status-im/nimbus-eth2/blob/unstable/docs/e2store.md

### We've fixed:

* Nimbus no longer crashes when a HTTP URL is specified as a `--web3-url` end-point:
  https://github.com/status-im/nimbus-eth2/pull/3582

* The REST end-point `/eth/v1/beacon/headers` is now able to return backfilled blocks:
  https://github.com/status-im/nimbus-eth2/pull/3472

* The Nimbus status bar has been disabled on Windows in order to avoid sporadic hangs in certain terminal emulators:
  https://github.com/status-im/nimbus-eth2/pull/3484

* A large start-up delay after backfilling:
  https://github.com/status-im/nimbus-eth2/pull/3516

* A rare problem which prevented the node from starting successfully after a trusted node sync:
  https://github.com/status-im/nimbus-eth2/pull/3517

* Confusing error messages when Nimbus lacks the necessary file system permissions to create its database:
  https://github.com/status-im/nimbus-eth2/pull/3536

### Removed functionality:

* The support for the Pyrmont testnet has been removed in order to reduce the Nimbus binary size:
  https://github.com/status-im/nimbus-eth2/pull/3568


2022-03-10 v22.3.0
==================

Nimbus `v22.3.0` is a `low-urgency` upgrade that marks the beginning of a more predictable release cadence for Nimbus. Going forward, we'll be publishing a new release each month, following a feature freeze period with intensified testing and monitoring of the introduced code changes on our dispersed fleet of mainnet validators.

> Please note that the new versioning scheme is tied to the calendar. The number 22 indicates the year of the release (2022), while 3 is the month (March). The last digit is the patch number of the release and it will have a non-zero value only when we ship a hotfix during the month.

### Improvements

* Nimbus can now run as a service on Windows: use the `--run-as-service` flag:
  https://github.com/status-im/nimbus-eth2/pull/3441

* All command-line options can now be provided in a configuration file: use the `--config-file` flag:
  https://github.com/status-im/nimbus-eth2/pull/3442
  https://nimbus.guide/options.html

* Lower CPU and bandwidth usage, thanks to better handling of already-seen attestation aggregates:
  https://github.com/status-im/nimbus-eth2/pull/3439

* Reduced memory usage for nodes bootstrapped with [trusted node sync](https://nimbus.guide/trusted-node-sync.html):
  https://github.com/status-im/nimbus-eth2/pull/3429

### We've fixed:

* Reduced performance on Windows due to the use of a less efficient method for collecting stack traces
  https://github.com/status-im/nimbus-eth2/pull/3466

* Non-spec-compliant URLs in the [Keymanager APIs](https://nimbus.guide/keymanager-api.html) for handling remote keystores
  https://github.com/status-im/nimbus-eth2/commit/4c01b777736f0d5d6fe38b37a4349741f6944e4c

* Extremely slow [slashing DB import](https://nimbus.guide/migration.html#step-4---import-your-slashing-protection-history) for validators with long validation history: the import should be nearly instant now
  https://github.com/status-im/nimbus-eth2/pull/3393

* Validator index-out-of-bounds crash that was triggered upon certain requests to the `/eth/v1/beacon/states/{state_id}/validators/{validator_id}` API
  https://github.com/status-im/nimbus-eth2/issues/3463

* An off-by-one logic error preventing sync committee messages to be published in the first slot of each sync committee period
  https://github.com/status-im/nimbus-eth2/pull/3470/commits/542e645bedec7702a973dc5cdaae87175e353009

### Deprecated features:

- The [JSON-RPC](https://nimbus.guide/api.html) service (`--rpc` flag) option is now deprecated. It's scheduled for removal in version `v22.6` (i.e. June of this year). If you are currently relying on the JSON-RPC API, please consider switching to the official [REST API](https://nimbus.guide/rest-api.html).


2022-02-15 v1.7.0
=================

Nimbus `v1.7.0` is a `low-urgency` feature-packed upgrade, which brings support for [trusted node sync](https://nimbus.guide/trusted-node-sync.html) (also known as checkpoint sync) and HTTPS web3 providers.

Of particular note: the [Keymanager API](https://nimbus.guide/keymanager-api.html) now supports remote keystores (a.k.a web3signer keystores).

### Breaking changes:

- Nimbus will no longer rewrite HTTP(S) web3 URLs to their respective WebSocket alternatives. Please review your setup to ensure you are using the desired web3 end-point.

- The peer scoring has been further tuned. As such the `--max-peers` should not be set below 70. Note that Lowering `max-peers` does not significantly improve bandwidth usage, but does increase the risk of missed attestations.

### Improvements:

* [Trusted node sync](https://nimbus.guide/trusted-node-sync.html):
  https://github.com/status-im/nimbus-eth2/pull/3326

* Full support for HTTP and HTTPS web3 URLs:
  https://github.com/status-im/nimbus-eth2/pull/3354

* Nimbus now treats the first `--web3-url` as a primary and preferred web3 provider. Any extra URLs are treated as fallback providers (to be used only when the primary is offline). As soon as the primary is usable again, Nimbus will switch back to it.

* The Keymanager API now supports management of remote keystores (also known as web3signer keystores):
  https://github.com/status-im/nimbus-eth2/pull/3360
                                                                                                  * The typical memory usage of Nimbus on mainnet is now below 1GB:
  https://github.com/status-im/nimbus-eth2/pull/3293

* 128MB of savings come from exploiting a provision in the official spec, which allows clients to respond with only non-finalized blocks to network queries which request blocks by their root hash.

* Faster beacon node startup-times:
  https://github.com/status-im/nimbus-eth2/pull/3320

* The REST API is now compatible with CORS-enabled clients (e.g. browsers):
  https://github.com/status-im/nimbus-eth2/pull/3378

* Use the `--rest-allow-origin` and/or `--keymanager-allow-origin` parameters to specify the allowed origin.

* A new `--rest-url` parameter for the `deposits exit` command: https://github.com/status-im/nimbus-eth2/pull/3344, https://github.com/status-im/nimbus-eth2/pull/3318

* You can now issue exits uing any beacon node which provides the [official REST API](https://nimbus.guide/rest-api.html). The Nimbus-specific [JSON-RPC API](https://nimbus.guide/api.html) will be deprecated in our next release, with a view to completely phasing it out over the next few months.

* The REST API will now returns JSON data by default which simplifies testing the API with `curl`.

* The notable exception here is when the client requests SSZ data by supplying an `Accept: application/octet-stream` header.

* Fairer request capping strategy for block sync requests and reduced CPU usage when serving them:
  https://github.com/status-im/nimbus-eth2/pull/3358

* More accurate Nim GC memory usage metrics.

* BLST upgrade (latest version):
  https://github.com/status-im/nimbus-eth2/pull/3364

* The `web3 test` command now provides more data about the selected provided:
  https://github.com/status-im/nimbus-eth2/pull/3354

### We've fixed:

* Unnecessary CPU and bandwidth usage: https://github.com/status-im/nimbus-eth2/pull/3308
  * The result of staying subsribed to sync committee topics even when there were no validators in the committee.
* Excessive logging on beacon nodes with large numbers of validators (in particular, those with `--validator-monitor-totals` enabled): https://github.com/status-im/nimbus-eth2/pull/3332
* Deviations from the spec in the REST API; this led to sub-optimal performance when Nimbus was paired with Vouch.
* Naming inconsistencies in the "totals" metrics (this was produced by the [validator monitor](https://nimbus.guide/validator-monitor.html)).
* Non-compliant implementation of the `/eth/v1/node/health` API (we were not producing HTTP status codes as mandated by the spec).
* Unnecessary restarts of the Eth1 syncing progress when the web3 provider connection was lost during sync: https://github.com/status-im/nimbus-eth2/pull/3354


2022-01-14 v1.6.0
=================

Nimbus `v1.6.0` is a `low-urgency` performance optimisation release with improved peer management.

`v1.6.0` adds support for the `Keymanager` API (currently in BETA):

https://nimbus.guide/keymanager-api.html

As well as a comprehensive set of metrics for  validator performance monitoring:

https://nimbus.guide/validator-monitor.html

### Improvements:

* Tuned peer management: reduces the likelihood of missed attestations
    * If you've seen frequent "No peers for topic" in your logs, this release will help
* Improved buffer management in the networking layer: reduces both CPU and memory usage.
* Further optimised batch verification of gossip messages: provides a 2-fold improvement in throughput.
* Comprehensive set of metrics for live validator performance monitoring in Grafana and support for producing detailed historic reward analysis in `ncli_db` (note that `ncli_db` is available only when compiling from source at the moment).
* Support for the new Keymanager API: add, remove, and migrate validators on the fly (BETA).
*  Blazingly fast historical traversals in the REST API for beacon chain data mining: state caching brings up to a 10x speed-up in some common usage patterns (e.g. obtaining historic data slot by slot or epoch by epoch).
* 3x speed-up in snappy compression and decompression.
* Support for obtaining JSON payloads from the REST API.


2021-12-03 v1.5.5
=================

Nimbus `v1.5.5` is a `medium-urgency` bugfix release which contains a number of significant optimisations; of particular note is a **6x speed-up in epoch processing** and **2x speed up in Altair block processing**.

In addition, `v1.5.5` adds support for the `web3signer` protocol (currently in BETA).

### We've fixed:

* The potential for missed block proposals when a third-party validator client (with at least one imported validator) is used with a Nimbus beacon node (with no imported validators)
    * The web3 connection not being enabled when running third-party validator clients

* A rare condition in which the REST service becomes unavailable.
* Inappropriate error messages produced by the REST API: when a validator client is publishing the same attestations or sync committee messages through multiple beacon nodes.

### Improvements:

* 6x speed-up in epoch processing: https://github.com/status-im/nimbus-eth2/pull/3089
* 2x speed up in Altair block processing: https://github.com/status-im/nimbus-eth2/pull/3115
* A 12% (minimum) reduction in the outgoing GossipSub traffic: https://github.com/status-im/nimbus-eth2/pull/3112
* Across the board performance improvements in the REST API: https://github.com/status-im/nimbus-eth2/pull/3092
* The REST API can now report sync committee information for the next sync period: https://github.com/status-im/nimbus-eth2/pull/3133
* Added support for the web3signer protocol (beta release):
  https://github.com/status-im/nimbus-eth2/pull/3077


2021-11-09 v1.5.4
=================

Nimbus `v1.5.4` is a `medium-urgency` hotfix release. It addresses an important issue which, in rare cases, can lead to the loss of attestations and sync committee messages. This can, in turn, lead to a reduction in rewards.

Please upgrade at your earliest convenience.

### We've fixed:

* A rare issue during the construction of sync committee contributions: invalid BLS aggregate signatures were being produced under certain conditions; this had the potential to negatively affect the peer score of the node, and impact its ability to deliver gossip messages.

* A non-spec-compliant implementation of the `/eth/v1/validator/duties/sync/{epoch}` REST API.

* A crash in the `/eth/v2/debug/beacon/states` REST API call on systems with limited stack space.

### Improvements:

* A nice little performance improvement for block verification and replay.

* Improved error messages in the REST API.

* The `/eth/v1/config/spec` REST API now returns more information regarding spec config parameters.

## Other notable changes:

* The `--log-file` option is now deprecated and may be removed in a future release (if you wish to log to a file, we recommend redirecting the standard output).

  Please note that the --log-file option was previously supported only when Nimbus was built from source. If your existing configuration used the --log-file option with a binary release, upgrading to v1.5.4 will enable the log file creation (though a deprecation warning will be printed on start-up).


2021-10-21 v1.5.2
=================

Nimbus `v1.5.2` is a `high-urgency` release for all users who haven't yet upgraded to the `v1.5.x` series
which add support for the upcoming beacon chain Altair hard-fork.

Please upgrade as soon as possible - **before the 27th of October**.

For users already running `v1.5.1`, the release brings a number of important bug fixes and optimizations
and upgrading is still highly recommended.

## Notable changes

### Improvements:

* Faster ramp up of peers when starting the beacon node.

* Added new metrics for keeping track of dropped gossip messages:

  https://github.com/status-im/nimbus-eth2/commit/bf6ad41d7dfd0899527a0374009a3fcf2a32361b

* The run-*-node.sh scripts provided in out Github repository will now enable the
  --rest and --metrics options by default.

### We've fixed:

* Potential crashes triggered by certain JSON-RPC and REST API requests.

* Unnecessary source of syncing time when the beacon node is restarted after the Altair transition.

* Certain non spec-compliant responses of the REST API.


2021-10-11 v1.5.1
=================

Nimbus `v1.5.1` is a `high-urgency` release for all users who have already upgraded to `v1.5.0`. It fixes a deposit contract syncing issue manifesting as the warning message "Eth1 chain not synced". Under specific circumstances, such a failure to sync the Eth1 chain may result in missed Eth2 block proposals, so affected users are advised to upgrade as soon as possible.

For anyone still running Nimbus v1.4.x or earlier, migrating to v1.5.1 continues to be a `medium-urgency` but *mandatory* upgrade that must be installed **before October 27th**.


2021-10-04 v1.5.0
=================

Nimbus `v1.5.0` is a `medium-urgency` but  *mandatory* upgrade which adds support for the upcoming beacon chain Altair hard-fork.

Please upgrade at your earliest convenience - **before the 27th of October**.

> **N.B** You must upgrade before October 27th in order to follow the mainnet beacon chain. Failure to do so will result in downtime penalties.

This is the first hard fork for the beacon chain, and while a significant amount of testing has been conducted in the run up to this release, we recommend users regularly monitor our announcement channels ([discord]() and/or the [newsletter]()) for potential updates.

To celebrate the feature complete release candidate of our REST API, we've opened up the ports on some of our fleet nodes - don't do this at home ;)

In order to interact with these, you should point your apps and tools to:

* http://unstable.mainnet.beacon-api.nimbus.team/ - `mainnet` data, the latest `unstable` [branch](https://github.com/status-im/nimbus-eth2/tree/unstable)
* http://unstable.prater.beacon-api.nimbus.team/ - `prater` testnet data, the [latest](http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/node/version) `unstable` [branch](https://github.com/status-im/nimbus-eth2/tree/unstable)

Note that right now these are very much unstable testing instances. They may be unresponsive at times - so **please do not rely on them for validation**. We may also disable them at any time.

--------------

### Notable changes

* Support for the Altair hard fork and the [latest Ethereum consensus spec](https://github.com/ethereum/consensus-specs/releases/tag/v1.1.1) (`v1.1.1`)

* Our [REST API](https://nimbus.guide/rest-api.html) is now feature complete, supporting the full [Beacon API](https://ethereum.github.io/beacon-APIs/) specification. This API should not be exposed to the public Internet as it includes multiple endpoints which could open your node to denial-of-service (DoS) attacks.
    * Known limitations: To use the REST API with a validator client, you need to enable the `--subscribe-all-subnets` option. This requirement will be removed in future versions.

* A new experimental `--num-threads=X` option allows Nimbus to take advantage of multiple CPU cores when verifying attestations. Set it to `1` to use one worker thread, `2` for two worker threads, etc. The default value  is set to `1` in this release, but future versions will set it to `0` (this tells the client to use as many worker threads as there are CPU cores available). N.B .**enabling anything other than `1` is considered experimental** at this stage.

* Improved peer discovery logic that ensures good connectivity to all gossip subnets.

* A new `version` metric that makes it easy to keep track of client upgrades within Grafana dashboards.

* New metrics `libp2p_peers_identity`, `libp2p_peers_traffic_read_total`, `libp2p_peers_traffic_write_total`, subdivided through Prometheus labels by the client type of the peer (i.e. nimbus, prysm, teku, lodestar or lighthouse).

* BLST has been upgraded to the latest version (`v0.3.5`).

* The `--network` option now accepts a directory with custom network metadata in the format of the [eth2-testnets](https://github.com/eth2-clients/eth2-networks) repository. The `SECONDS_PER_SLOT` configuration value remains the only setting that must be supplied at compile-time through the `-d:SECONDS_PER_SLOT=X` nim compilation flag.


2021-07-10 v1.4.2
=================

Nimbus `v1.4.2` - "Upgrade procedure: Hotfix release"

This release is marked as `low-urgency` for all Nimbus users other than those who have recently updated to `v1.4.1` from a version earlier than `v1.1.0` - for these users this is a `high-urgency` release.

## Notable changes
This release fixes an issue in the upgrade procedure when upgrading from a version earlier than `1.1.0` to `1.4.x`.

**How can I tell if I've been affected?**

If you've already upgraded to `1.4.1`, you can tell that you've been affected if you're seeing the following` WRN log`:

```
 Received invalid sequence of blocks
```

To re-iterate, this issue only affects users who are upgrading from `1.0.12` or earlier (released on `2021-03-10`), **and have not run any release in between**. Everyone else can ignore this release.


2021-07-10 v1.4.1
=================

Nimbus v1.4.1 - "Every attestation counts"

This release is marked as `low-urgency`

## Notable changes

Nimbus `v1.4.0` users might have noticed that they are missing a small number of (seemingly random) attestations since the update. Our investigation into the matter has showed that, due to `v1.4.0`'s significant performance improvements, Nimbus validators occasionally send their first attestation for a new epoch before some peers are ready. These "slow" peers end up dropping early attestations because they're busy with the epoch transition.

It's a rare occurrence, since it requires a validator to be scheduled to attest in the first slot of an epoch *and* for the beacon node to only be connected to "slow" peers for the respective libp2p topic. If both these conditions are true, a premature attestation may be lost in time, like tears in the rain.

As a fix, we are using a larger send delay: [#2705](https://github.com/status-im/nimbus-eth2/pull/2705).

Fo those Nimbus `v1.4.0` users who are concerned about reaching optimal attestation effectiveness, we encourage you to upgrade as soon as possible.

Other changes include log flushing and metrics fixes.

Full list:
- increase attestation wait time ([#2705](https://github.com/status-im/nimbus-eth2/pull/2705))
- ensure logs are printed without delays ([#2669](https://github.com/status-im/nimbus-eth2/pull/2669))
- fix metrics on Windows ([#2707](https://github.com/status-im/nimbus-eth2/pull/2707))


2021-06-21 v1.4.0
=================

This release is marked as low-urgency - please update at your convenience.

It contains **improvements to attestation effectiveness and CPU usage**.

It also contains **improvements to the RPC APIs**, as suggested by DappNode and RocketPool, and in preparation for our refactored validator client.
### Outdated Nimbus instances

A reminder that if you're running Nimbus with a version prior to `1.0.10` (March 2021) you are exposed to a vulnerability in our core cryptography library (this library is used by all eth2 clients). See this [blst security advisory](https://github.com/supranational/blst/security/advisories/GHSA-x279-68rr-jp4p) for more information. If this concerns you, please update as soon as you can.

## Notable changes
### We've added:

* Nightly builds for the very adventurous. (https://github.com/status-im/nimbus-eth2/pull/2640)
    * We expect users of nightly builds to be comfortable providing debugging logs.

### We've fixed:

* RPC API endpoints (https://github.com/status-im/nimbus-eth2/pull/2585, https://github.com/status-im/nimbus-eth2/pull/2586)
    * `/eth/v1/beacon/pool/attestations`
    * `/api/eth/v1/validator/aggregate_and_proofs`
* Doppelganger detection: fixed false positive on fast restart (https://github.com/status-im/nimbus-eth2/pull/2656/)


### We've improved

* Database read performance improvements during epoch transitions and startup (https://github.com/status-im/nimbus-eth2/pull/2639, https://github.com/status-im/nimbus-eth2/pull/2617)
* Better usage of caches, specially when validating attestations (https://github.com/status-im/nimbus-eth2/pull/2631)


2021-05-17 v1.3.0
=================

This release offers safer and easier options to migrate to Nimbus from other clients.
It also brings further performance optimizations.

**We've added:**

* A new `slashingdb` sub-command with `import` and `export` options. This allows for
  safely migrating to Nimbus from another client (as per the [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076)
  slashing protection interchange format).
  Please see the the newly prepared [migration guides](https://nimbus.guide/migration.html) for the details.

* A new `ncli_db validatorPerf` command. This can be used to perform a textual
  report for the attestation performance of a particular validator
  (please note that `ncli_db` is available only when compiling from source).

* Official binaries for macOS (AMD64 and ARM64).

* Pruning of the slashing protection database and a transition to more optimal
  queries. This results in a significant reduction in both disk and CPU usage
  on nodes running a large number of validators.

* More consistent level of validation for the attestations received from
  third-party sources and the JSON-RPC and REST APIs. This prevents invalid
  attestations from being broadcasted to the network.

* Performance tuning of attestation subnet transition timings and state
  snapshotting intervals. This results in improved CPU and bandwidth usage.

**We've fixed:**

* Problems in the GossipSub subnet walking logic leading to unnecessary bandwidth
  and CPU costs.


2021-05-03 v1.2.2
=================

This is a bugfix release improving the stability of the REST API and addressing
issues discovered during the mainnet deposit processing accident of 24-25 April.

**New features:**

* More efficient attestation processing pipeline using less queuing.

**We've fixed:**

* Insufficient validation of third-party Eth1Data votes.

* Sporadic REST API connection interruptions resulting from large request or
  result payloads.

* Incorrectly sent empty GossipSub IWANT messages.


2021-04-20 v1.2.1
=================

This is a hotfix release that solves the database migration issue highlighted
in the previous release -- this problem affected new Nimbus users who used
v1.1.0 to sync with the network from genesis, essentially resetting their
state database and causing them to start re-syncing from genesis.

If you have used an older version of Nimbus prior to upgrading to v1.1.0,
you should not be affected.

If you were affected, you have a couple of options available to you:

1) If you have backed-up your database prior to upgrading to v1.2.0, you
   can restore the database from backup and execute the migration successfully
   after upgrading to this release.

2) If you haven't backed up your database, you can upgrade to this release at
   your convenience; rest assured it won't delete your sync history.

Please accept our sincerest apologies for any inconvenience we may have caused.
We are reviewing our release testing policies to ensure that we cover a greater
number of possible upgrade paths going forward.


2021-04-19 v1.2.0
=================

If [`v1.1.0`](https://github.com/status-im/nimbus-eth2/releases/tag/v1.1.0)
was the big I/O update, `v1.2.0` is all about the CPU - together, these
updates help secure Nimbus against future network growth, and provide us
with a higher security margin and substantial [profitability improvements]
(https://twitter.com/ethnimbus/status/1384071918723092486).

To highlight just one data point, CPU usage has been cut by up to 50% over
v1.1.0 ( 🙏  batched attestation processing). This makes it the first release
we can officially recommend for validating on a Raspberry Pi 4.

> **N.B.** this release contains a **critical stability fix** so please
  **make sure you upgrade!**

**New features:**

* Beta support for the official Beacon Node REST API:
  https://ethereum.github.io/eth2.0-APIs/. Enable it by launching
  the client with the `--rest:on` command-line flag

* Batched attestation verification and other reforms **->** massive
  reduction in overall CPU usage.

* Improved attestation aggregation logic **->** denser aggregations
  which in turn improve the overall health of the network and improve
  block production.

* More efficient LibP2P connection handling code **->** reduction in
  overall memory usage.

**We've fixed:**

* A critical stability issue in attestation processing.

* `scripts/run-*-node.sh` no longer prompts for a web3 provider URL
  when the `--web3-url` command-line option has already been specified.


2021-04-05 v1.1.0
=================

This release brings planned reforms to our database schema that provide
substantial performance improvements and pave the way for an an improved
doppelganger detection ready immediately to propose and attest to blocks
(in a future release).

Please be aware that we will remain committed to maintaining backwards
compatibility between releases, but **this release does not support
downgrading back to any previous 1.0.x release**.

As a safety precaution, we advise you to **please backup your Nimbus
database before upgrading** if possible.

**New features:**

* More efficient state storage format ==> reduced I/O load and lower
  storage requirements.

* More efficient in-memory cache for non-finalized states ==> significant
  reduction in memory usage.

* More efficient slashing database schema ==> scales better to a larger
  number of validators.

* The metrics support is now compiled by default thanks to a new and
  more secure HTTP back-end.

* Command-line tools for generating testnet keystores and JSON deposit
  files suitable for use with the official network launchpads.

* `setGraffiti` JSON-RPC call for modifying the graffiti bytes of the
  client at run-time.

* `next_action_wait` metric indicating the time until the next scheduled
  attestation or block proposal.

* More convenient command-line help messages providing information
  regarding the default values of all parameters.

* `--direct-peer` gives you the ability to specify gossip nodes
  to automatically connect to.

* Official docker images for ARM and ARM64.

* Support for fallback `--web3-url` providers.

**We've fixed:**

* Long processing delays induced by database pruning.

* File descriptor leaks (which manifested after failures of the selected
  web3 provider).

* The validator APIs now return precise actual balances instead of rounded
  effective balances.

* A connection tracking problem which produced failed outgoing connection
  attempts.

**Breaking changes:**

* Nimbus-specific JSON-RPCs intended for debug purposes now have
  the `debug_` prefix:

  - `getGossipSubPeers` is now `debug_getGossipSubPeers`
  - `getChronosFutures` is now `debug_getChronosFutures`


2021-03-10 v1.0.12
==================

This is bugfix release correcting an error in the Prater testnet config
leading to incorrect Eth1 voting.


2021-03-10 v1.0.11
==================

This is a minor release adding support for connecting to the Prater testnet.


2021-03-10 v1.0.10
==================

This release contains important security and performance improvements.

-----

**Upgraded:**

* We're now running version 0.3.3 of the BLST library:
  https://github.com/supranational/blst/releases/tag/v0.3.3

* We've switched to a more recent version of BearSSL
 (this version features a more up-to-date list of trusted root certificates)

* We're now consistent with the v1.0.1 Eth2 spec

**We've fixed:**

* A frequent crash occurring on certain hardware configurations after
  building Nimbus from source.

* Long processing delays triggered by the reception of attestations that
  reference already pruned states.

* LibP2P peer management issue which led to an accumulation of inactive
  connections.

* A false-positive in doppelganger detection triggered by rebroadcasted
  older attestations arriving with a significant delay.

**New features**:

* A new improved format of the slashing protection database:

  - Significantly reduces the disk load with a large number of validators (1000+).

  - Makes it possible to enhance our doppelganger detection in the future
    such that waiting for 2 epochs before attesting is not necessary.

  To ensure smooth upgrade and emergency rollback between older and future
  Nimbus versions, v1.0.10 will keep track of your attestation in both the
  old and the new format. The extra load should be negligible for home
  stakers.


2021-03-09 v1.0.9
=================

This version was an internal release candidate build for the 1.0.10 release.


2021-02-22 v1.0.8
=================

This release includes important JSON-RPC stability improvements
and compatibility fixes, which make it possible to use Nimbus
as a RocketPool operator.

-----

**New features:**

* RocketPool integration:
  see https://github.com/rocket-pool/smartnode/pull/89
  and https://github.com/rocket-pool/smartnode-install/pull/26/commits/da720acc8f4c1c31c05971748fbc144de1621830

* Next attestation time displayed on every "Slot end" log message
  (helps you select the best time for restarting the node)

* libp2p scoring: disconnect from badly performing peers and prioritise
  peers with better latency and throughput.

**We've fixed:**

* A rare crash triggered when connecting to a web3 provider using
  a secure web socket.

* JSON-RPC spec violations and potential DoS attack vectors.

* Two stale bootstrap node addresses.


2021-02-04 v1.0.7
=================

A release which provides additional protection against accidental slashings
and further performance improvements across the board.

-----

**New features:**

* New slashing protection mechanism (doppelganger detection) prevents your
  validator from contradicting itself if you have accidentally left it running
  on another machine (see the `--doppelganger-detection` option).

* Optimized batching of BLS signature verification leading to faster sync
  speeds and reduced CPU load.

* Further improvements to attestation subnet walking resulting in a reduction
  in both bandwidth and CPU usage.

* A new `--subscribe-all-subnets` option allowing the node to maintain peers
  from all attestation subnets (most suitable for bootstrap nodes).

* Official docker images published at https://hub.docker.com/r/statusim/nimbus-eth2

* Official Windows binaries created from a reproducible build recipe.

*  An option to enable the automatic updating of IP:Port in the ENR
  (off by default, specify `--enr-auto-update:true` to turn it on)

**We've fixed:**

* A bug that had the potential to completely halt all syncing activity.

* Inefficient processing of blocks with Eth1 deposits which occassionally
  led to increased latencies when delivering attestations.

* Outdated records in our bootstrap nodes list.

* An Eth1 syncing issue which manifested itself as a "Corrupted deposits
  history detected" error.

* Non-standard encoding of certain data types such as signatures and bit
  sequences within the results of JSON-RPC requests.

**We've deprecated:**

* `make beacon_node` will no longer compile the beacon node.
  You'll need to run `make nimbus_beacon_node` from now on

* On monday we'll phase out the old `master` branch. If you're still building
  Nimbus from `master`, please switch to `stable`.


2021-01-10 v1.0.6
=================

A release that brings reproducible precompiled binaries for ARM devices and
significant performance improvements.

-----

**New features:**

* Reproducible build recipe for creating Nimbus Linux binaries intended for
  ARM devices.

* Improved attestation subnet walking logic: this brings significant reductions
  in bandwidth usage and CPU load.

* Better usage of the Sqlite3 checkpointing API (minor performance improvement).

* Larger window for the candidate attestations included in blocks: this can lead
  to higher block rewards.

**We've fixed:**

* Incorrect `attnets` value announced in ENR records.


2021-01-09 v1.0.5
=================

The 1.0.5 release was retracted because it included a potential optimization
to the reproducible build scripts that turned out to create a buggy binary for
AMD64 systems. Manually built binaries through the Makefiles were not affected.
After fixing the problem, the release was re-published as 1.0.6 with the same
release notes.


2020-12-16 v1.0.4
=================

A release bringing further stability improvements and minor performance
optimisations.

-----

**New features:**

* Nimbus can now be safely shut down with the SIGTERM signal on POSIX systems.

* New discovery IP limits making theoretic eclipse attack much more costly.

* A new `make benchmarks` target for obtaining a performance score for your system.

* Upgrade of the BLST library bringing minor performance improvement.

**We've fixed:**

* Gossipsub resource leaks that may reduce the quality of the gossipsub mesh and
  reduce the attestation effectiveness of the client.

* Incomplete validation of the forwarded attestations that may affect negatively
  the peer score of Nimbus.

* An issue halting the activity of the Eth1 monitor.

* The incorrect zero validator balance displayed while the node is syncing.

* A regression preventing Nimbus to be used with custom testnet metadata files.


2020-12-09 v1.0.3
=================

A release fixing issues that have contributed to Nimbus's lower peer scores
on the network.

-----

**New features:**

* New metrics tracking the syncing progress of the Eth1 deposit contract
  monitor.

* A new `web3 test` command for testing the compatibility of a web3 provider
  before using it.

**We've fixed:**

* Incorrect timing when sending aggregated attestations.

* Stale ENR records not taking into account the dynamic attestation subnet
  hopping.

* An invalid error message produced by the `deposits exit` command (validator
  state unknown).


2020-12-03 v1.0.2
=================

A release that fixes an issue regarding the occasional missed block proposal.

Proposing a block is arguably the most important duty you have as a validator.
So it's important you update at your earliest convenience.

-----

**New features:**

* 8 new JSON-RPC calls that bring us to feature parity with the official
  beacon node API.

**We've fixed:**

* A deposit merkle proofs generation issue occasionally resulting in missed
  block proposals shortly after a new Eth1 head was selected.

* Slow status bar updates in the absense of logging messages.


2020-12-02 v1.0.1
=================

A release with a number of important fixes and optimisations.

**Please update** at your earliest convenience.

In order to minimise downtime, we recommend updating and rebuilding
the beacon node **before restarting.**

-----

**New features:**

* More conservative Eth1 syncing requests to reduce the likelihood of
  going over the maximum allowed burst rates under the Infura free plan
  (predominantly aimed at those running Nimbus on resource-restricted
   device like Raspberry Pi's) + more resiliency in case of errors.

**We've fixed:**

* A "Only one concurrent read allowed" crash reported by multiple users.

* An error in the default configuration preventing the node from discovering
  peers on mainnet unless the `--network=mainnet` flag was passed. Please note
  that this not affect users starting their node with the `./run-mainnet-beacon-node`
  command.

* The fractional part of the ETH balance in the Nimbus status bar
  (the value displayed should now be correct).

* An issue that occasionally caused the Eth1 syncing process to get stuck
  before reaching the head of the chain.

* Unnecessary network traffic related to GossipSub `IHAVE`.

* Incorrect gossipsub pruning which occasionally resulted in messages
  getting lost.

* An issue where an excessively long graffiti string could cause a crash on
  startup.

* A Linux-only issue that resulted in the `deposits import` command ignoring
  its supplied arguments.


2020-11-29 v1.0.0-stateofus
===========================

As promised, a slightly more polished release before Mainnet launch ✨

Please make sure you update to this release before Eth2 genesis this
Tuesday (December 1 12:00:23 UTC), as it contains some important improvements.

-----------------

**New features:**

* Updated list of bootstrap nodes for Mainnet.

* Prometheus metrics for validator balances. The beacon node will also
  display the total balance of all attached validators in the status
  footer by default.

* `deposits import` now automagically finds the `validator_keys` directory
  produced by the `eth2.0-deposit-cli` if it is located in the same working
  directory.

* A `deposits exit` command for submitting a voluntary validator exit.

* A `record` CLI command for inspecting and creating ENR records.

* An `--agent-string` option for specifying how Nimbus will present itself
  in LibP2P messages. The default value is now `nimbus`.

* New RPC calls to track node and config status. Specifically, a JSON-RCP
  call for inspecting the active config preset (`get_v1_config_spec`).

**We've fixed:**

* Inaccurate peer counts (an occasional mismatch between the number of
  syncing peers and GossipSub peers) -- the default peer limit has been
  increased to maintain a healthy gossip mesh.

* High bandwidth usage of GossipSub (due to sub-optimal caching and lack
  of limits in the IWANT/IHAVE exchange messages) -- we're now using the
  latest spec GossipSub parameters.

* High sync memory footprint -- we've reduced the number of sync workers
  from 20 to 10 (note, this should not affect sync speed).


2020-11-25 v1.0.0-rc1
=====================

We're happy to join the other client teams in announcing our `v1.0.0` release
candidate with support for Mainnet ✨

You can use this release/binary to set up your rig and monitoring for Eth2
genesis next Tuesday (*December 1 12:00:23 UTC*).

> **N.B.** There will be at least one more release, before December 1st.
> In particular, **we are planning a more polished release for Sunday** which
> will act as a drop-in replacement for this release candidate.

Don't worry if your peer count appears low at first -- It should increase as
more validators connect to Mainnet.

-----------------

**Highlights include:**

* The addition of a deposit contract "state snapshot"  to network metadata.
  This allows the client to skip syncing deposits made prior to the snapshot.

* A much faster startup time. We've removed the deposits table from the database,
  which means the client no longer needs to process all deposits on start-up.

* The Eth1 monitor no longer starts if the beacon node has zero validators attached to it.

* The genesis detection code is now optional and disabled by default.

* An RPC call to get Chronos futures at runtime.

* Eth2 spec gossip parameters.

**We've fixed:**

* A database corruption issue affecting Pyrmont nodes.

* Unnecessary copy/memory alloc when loading DbSeq entries.

* A block production issue affecting clients that hadn't finished downloading the latest deposits.


2020-11-20 v0.6.6
=================

**New features:**

* New RPC APIs for inspecting the internal state of the Eth1 monitor.

**We've fixed:**

* A fork-choice issue causing Nimbus to get stuck on a particular slot.

* A logic error causing Nimbus to vote for an incorrect Eth1 block.

* A crash during initialization when the web3 provider is refusing
  to serve data (e.g. due to exceeded request quota).


2020-11-17 v0.6.4
=================

**New features:**

* Support for the Pyrmont testnet.

* The PCRE library is no longer necessary for building Nimbus.

* Sensitive files such as keystores are now accessible only to the
  user of the beacon node on POSIX systems (the group rights have
  been dropped).

**We've fixed:**

* An issue preventing blocks to be downloaded when the client goes
  out of sync.

* Resource leaks that may lead to reduction of network activity due
  to a build-up of malfunctioning peer connections.


2020-11-12 v0.6.2
=================

A bugfix release addressing issues discovered in the Toledo network.

**New features:**

* GossipSub 1.1

* The beacon node status bar (footer) now contains a
  time-left-until-synced estimate.

* A JSON-RPC method `setLogLevel` for dynamically changing the
  log level of selected components at run-time.

* The ability to launch Nimbus with a partially-synced Geth node.

**We've fixed:**

* A bug preventing the node from proposing blocks when connected
  to a web3 provider

* An invalid "corrupted database" error message appearing on start-up

* Incorrectly set message-ids in gossip message causing other clients
  to penalise and potentially disconnect our nodes from the network.

* An issue occuring when Nimbus is paired with a Geth node
  that is not fully synced.


2020-11-09 Hope (v0.6.0)
========================

`Nimbus eth2` 0.6.0 was the first externally audited and stable release
of our beacon node software. When compared to the 0.5x series, it features
significant reductions in storage and memory requirements, a faster sync
speed, and a plethora of usability and security enhancements across the
board. Under normal network conditions, the delivery rate of attestations
and block proposals is expected to be above 99%. Going forward, our release
schedule will start to accelerate, with multiple new releases expected before
the Eth2 mainnet launch.

**Changelog highlights include:**

* Full support for the 1.0 Eth2 phase0 spec and the monitoring of the
  mainnet validator deposit contract.

* LibP2P and GossipSub fixes which drastically improve the delivery of
  attestations and blocks (nearly 100% expected rate of delivery).

* Fixes for all major resource leaks: you no longer need to restart your
  node to improve its performance.

* Efficient caching and storage mechanisms: ensures our memory consumption
  remains comparatively low both during smooth and turbulent network conditions.

* Several storage and networking optimisations leading to an order of magnitude
  improvement in beacon chain sync speed.

* Audits to our codebase by ConsenSys Diligence, NCC Group and Trail of Bits.
  More than 60 of the security findings have already been addressed.
  The remaining items will be resolved before mainnet launch.

* Support for pairing with a locally running Geth instance to allow for
  decentralised monitoring of the validator deposit contract.

* An extensive user guide for managing the beacon node.

* Slashing protection mechanisms + database.

* Support for storing the validator signing keys in a separate process, isolated
  from the network, with a minimal attack surface.
