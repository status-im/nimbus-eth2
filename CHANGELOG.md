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

