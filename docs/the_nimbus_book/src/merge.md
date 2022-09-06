# The Merge

The Ethereum network is preparing for a major upgrade to merge the beacon chain with the existing proof-of-work execution network, thus transitioning to proof-of-stake.

Read more about it [here](https://ethereum.org/en/upgrades/merge/).

## Preparing for the merge

The merge happens in two phases, the first of which is the Bellatrix upgrade on the Beacon Chain 2022-09-06 11:34:47 UTC.

The second phase happens when total difficulty on the execution chain reaches `58750000000000000000000` - it is expected this happens around 2022-09-15, but may come days early or late.

### Bookmark this page!

As the merge draws near, we will continue to update this page with the latest information and instructions.

### Keep Nimbus up to date

Leading up to the merge, it is important to [keep Nimbus up to date](./keep-updated.md). Before the merge, the exact version of Nimbus required to participate will be announced, but stakers should be prepared to upgrade their nodes on short notice.

You must be running Nimbus **22.8.0** or later.

### Set up your Execution Client

As a node operator, you will need to run both an execution client and a consensus client after the merge. If you were previously using a third-party web3 provider (such as Infura or Pocket), you will need to [set up an execution client](./eth1.md).

If you were running an execution client before, make sure to update its configuration to include an option for [JWT secrets](./eth1.md#3-pass-the-jwt-secret-to-nimbus) and engine API.

Please note that once the Bellatrix fork epoch is reached on 6th of September 2022, Nimbus will refuse to start unless connected to a properly configured execution client. If you need more time to complete the transition, you can temporarily run the beacon node with the command-line option `--require-engine-api-in-bellatrix=no`, but please note that such a setup will stop working once the network TTD is reached (currently estimated to happen on 13th of September, see https://wenmerge.com/ for more up-to-date information).

### Prepare a suggested fee recipient

After the merge, validators that propose blocks are eligible to receive transaction fees - read more about fee recipients [here](https://launchpad.ethereum.org/en/merge-readiness#fee-recipient).

See the [suggested fee recipent page](./suggested-fee-recipient.md) for information about the changes needed to Nimbus.
