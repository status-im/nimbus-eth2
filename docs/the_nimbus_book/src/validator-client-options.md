# Validator client

In the most simple setup, a single beacon node paired with an execution client is all that is needed to run a successful validator setup.

Nimbus however also provides options for running advanded setups that provide additional security and redundancy.

See the [validator client page](./validator-client.md) to get started!

## Multiple beacon nodes

By default, the validator client will connect to a beacon node running on the same machine using the default port (`5052`).

You can select one or more beacon nodes to connect to using the `--beacon-node` option:

```sh
build/nimbus_validator_client \
  --beacon-node=http://127.0.0.1:5052 \
  --beacon-node=http://127.0.0.1:5053
```

### Beacon node roles

When configuring multiple beacon nodes, each beacon node can be assigned to perform specific tasks on behalf of the validator client.

| Role name           | Role calls                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:------------------- |:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| attestation-data    | [produceAttestationData()](https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| attestation-publish | [submitPoolAttestations()](https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttestations)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |     |
| aggregated-data     | [getAggregatedAttestation()](https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestation)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| aggregated-publish  | [publishAggregateAndProofs()](https://ethereum.github.io/beacon-APIs/#/Validator/publishAggregateAndProofs)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| block-data          | [produceBlockV2()](https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV2)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |     |
| block-publish       | [publishBlock()](https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| sync-data           | [getBlockRoot()](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot)</br>[produceSyncCommitteeContribution()](https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |     |
| sync-publish        | [publishContributionAndProofs()](https://ethereum.github.io/beacon-APIs/#/Validator/publishContributionAndProofs) <br/> [submitPoolSyncCommitteeSignatures()](https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolSyncCommitteeSignatures)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| duties              | [getGenesis()](https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis)<br/>[getSpec()](https://ethereum.github.io/beacon-APIs/#/Config/getSpec)<br/> [getSyncingStatus()](https://ethereum.github.io/beacon-APIs/#/Node/getSyncingStatus)<br/>getValidatorsActivity()<br/>[getForkSchedule()](https://ethereum.github.io/beacon-APIs/#/Config/getForkSchedule)<br/>[getAttesterDuties()](https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties)<br/>[getProposerDuties()](https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties)<br/>[getSyncCommitteeDuties()](https://ethereum.github.io/beacon-APIs/#/Validator/getSyncCommitteeDuties)<br/> [getStateValidators()](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators)<br/>[prepareSyncCommitteeSubnets()](https://ethereum.github.io/beacon-APIs/#/Validator/prepareSyncCommitteeSubnets)<br/>[prepareBeaconCommitteeSubnet()](https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet) |

Also, there could be combinations:

| Name        | Roles                                                                |
| ----------- |:-------------------------------------------------------------------- |
| attestation | attestation-data, attestation-publish                                |
| aggregated  | aggregated-data, aggregated-publish                                  |
| block       | block-data, block-publish                                            |
| sync        | sync-data, sync-publish                                              |
| publish     | attestation-publish, aggregated-publish, block-publish, sync-publish |
| data        | attestation-data, aggregated-data, block-data, sync-data             |
| all         | attestation, aggregated, block, sync, duty                           |

### Configuration

Roles are configured using the `#roles=` URL anchor.
The default is `all`:

Examples:

- `http://127.0.0.1:5052/#roles=attestation-data,attestation-publish`
- `http://127.0.0.1:5053/#roles=block-proposal-data,block-proposal-publish`
- `http://127.0.0.1:5054/#roles=all`
- `http://127.0.0.1:5055/` also means `all` roles.

Before usage all the roles are got stripped from BN URLs.

## Advanced topologies

### Fully redundant nodes

Using multiple beacon nodes with the same role allows fully redundant setups.

These setups are resilient against any single beacon node getting disconnected and provide additional "entry points" for the data that the validator client produces should any node experience poor connectivity.

### Sentry node setup

In the Ethereum network, the block proposer is known up to 12 minutes before they propose the block.
Because each validator sends attestations every 6 minutes, it is also possible to map the validator key to the beacon node IP address that serves it.

Sentry nodes setups allow separating block production traffic from attestations and sync committee messages, making sure that a separate public IP address is used when proposing blocks.
In this setup, there are two beacon nodes:

* One beacon node has all roles except `block`
* The other beacon node has the `block` role

Separating block production makes it harder for an attacker to target the specific IP address that the validator would otherwise use for block production.
