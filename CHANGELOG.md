2022-02-15 v1.7.0
=================

Nimbus `v1.7.0` is a `low-urgency` feature-packed upgrade, which brings support for [trusted node sync](https://nimbus.guide/trusted-node-sync.html) (also known as checkpoint sync) and HTTPS web3 providers.

Of particular note: the [Keymanager API](https://nimbus.guide/keymanager-api.html) now supports remote keystores (a.k.a web3signer keystores).

### Breaking changes

- Nimbus will no longer rewrite HTTP(S) web3 URLs to their respective WebSocket alternatives. Please review your setup to ensure you are using the desired web3 end-point.

- The peer scoring has been further tuned. As such the `--max-peers` should not be set below 70. Note that Lowering `max-peers` does not significantly improve bandwidth usage, but does increase the risk of missed attestations.

### Improvements:

* [Trusted node sync](https://nimbus.guide/trusted-node-sync.html): https://github.com/status-im/nimbus-eth2/pull/3326
* Full support for HTTP and HTTPS web3 URLs: https://github.com/status-im/nimbus-eth2/pull/3354
  * Nimbus now treats the first `--web3-url` as a primary and preferred web3 provider. Any extra URLs are treated as fallback providers (to be used only when the primary is offline). As soon as the primary is usable again, Nimbus will switch back to it.
* The Keymanager API now supports management of remote keystores (also known as web3signer keystores): https://github.com/status-im/nimbus-eth2/pull/3360
* The typical memory usage of Nimbus on mainnet is now below 1GB: https://github.com/status-im/nimbus-eth2/pull/3293
  * 128MB of savings come from exploiting a provision in the official spec, which allows clients to respond with only non-finalized blocks to network queries which request blocks by their root hash.
* Faster beacon node startup-times: https://github.com/status-im/nimbus-eth2/pull/3320
* The REST API is now compatible with CORS-enabled clients (e.g. browsers): https://github.com/status-im/nimbus-eth2/pull/3378
  * Use the `--rest-allow-origin` and/or `--keymanager-allow-origin` parameters to specify the allowed origin.

* A new `--rest-url` parameter for the `deposits exit` command: https://github.com/status-im/nimbus-eth2/pull/3344, https://github.com/status-im/nimbus-eth2/pull/3318
  * You can now issue exits uing any beacon node which provides the [official REST API](https://nimbus.guide/rest-api.html). The Nimbus-specific [JSON-RPC API](https://nimbus.guide/api.html) will be deprecated in our next release, with a view to completely phasing it out over the next few months.
* The REST API will now returns JSON data by default which simplifies testing the API with `curl`.
  * The notable exception here is when the client requests SSZ data by supplying an `Accept: application/octet-stream` header. 
* Fairer request capping strategy for block sync requests and reduced CPU usage when serving them: https://github.com/status-im/nimbus-eth2/pull/3358
* More accurate Nim GC memory usage metrics.
* BLST upgrade (latest version): https://github.com/status-im/nimbus-eth2/pull/3364
* The `web3 test` command now provides more data about the selected provided: https://github.com/status-im/nimbus-eth2/pull/3354

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
