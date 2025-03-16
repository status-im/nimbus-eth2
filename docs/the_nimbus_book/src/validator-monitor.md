# Validator monitoring

The validator monitoring feature allows for tracking the life cycle and performance of one or more validators in detail.
Monitoring can be carried out for any validator, with slightly more detail for validators that are running in the same beacon node.

Every time the validator performs a duty, the duty is recorded and the monitor keeps track of the reward-related events for having performed it.
For example:

* When attesting, the attestation is added to an aggregate, then a block, before a reward is applied to the state
* When performing sync committee duties, likewise

Validator actions can be traced either through logging, or comprehensive metrics that allow for creating alerts in monitoring tools.

The metrics are broadly compatible with [Lighthouse](https://lighthouse-book.sigmaprime.io/validator-monitoring.html), thus dashboards and alerts can be used with either client with minor adjustments.

## Command line options

The monitor is by default enabled for all keys that are validating via the beacon node.
It can also be configured to monitor a specific list of validators, or be disabled entirely with `--validator-monitor-auto=false`.

The `--validator-monitor-details` flag can be used to enable the detailed monitor mode.
In this mode, the performance of each validator is monitored individually in metrics leading to a more detailed view of performance.

!!! tip
    The detailed mode significantly increases the total number of published metrics for each monitored validator.
    When used with more than 10 validators, it may adversely impact performance of metrics collection and display.

```sh
# Disable automatic monitoring of all validators used with this beacon node beacon node
./run-mainnet-beacon-node.sh --validator-monitor-auto=false ...

# Enable monitoring of one or more specific validators
./run-mainnet-beacon-node.sh \
  --validator-monitor-pubkey=0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c \
  --validator-monitor-pubkey=0xb2ff4716ed345b05dd1dfc6a5a9fa70856d8c75dcc9e881dd2f766d5f891326f0d10e96f3a444ce6c912b69c22c6754d ...

# Publish detailed metrics for each monitored validator individually instead of an aggregate totals value
./run-mainnet-beacon-node.sh --validator-monitor-details ...
```

## Understanding monitoring

When a validator performs a duty, such as signing an attestation or a sync committee message, this is broadcast to the network.
Other nodes pick it up and package the message into an aggregate and later a block.
The block is included in the canonical chain and a reward is given two epochs (~13 minutes) later.

The monitor tracks each of these actions and will in detailed mode log each step at the `INF` level.
If any step is missed (irrespective of detail mode), a `NTC` log is shown instead.

The typical life cycle of an attestation might look something like the following:

```
INF 2021-11-22 11:32:44.228+01:00 Attestation seen                           topics="val_mon" attestation="(aggregation_bits: 0b0000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, data: (slot: 2656363, index: 11, beacon_block_root: \"bbe7fc25\", source: \"83010:a8a1b125\", target: \"83011:6db281cd\"), signature: \"b88ef2f2\")" src=api epoch=83011 validator=b93c290b
INF 2021-11-22 11:32:51.293+01:00 Attestation included in aggregate          topics="val_mon" aggregate="(aggregation_bits: 0b1111111101011111001101111111101100111111110100111011111110110101110111111010111111011101111011101111111111101111100001111111100111, data: (slot: 2656363, index: 11, beacon_block_root: \"bbe7fc25\", source: \"83010:a8a1b125\", target: \"83011:6db281cd\"), signature: \"8576b3fc\")" src=gossip epoch=83011 validator=b93c290b
INF 2021-11-22 11:33:07.193+01:00 Attestation included in block              attestation_data="(slot: 2656364, index: 9, beacon_block_root: \"c7761767\", source: \"83010:a8a1b125\", target: \"83011:6db281cd\")" block_slot=2656365 inclusion_lag_slots=0 epoch=83011 validator=b65b6e1b
```

The life cycle of a particular message can be traced by following the `epoch=.... validator=...` fields in the message.

Failures at any point are recorded at a higher logging level, such as `NTC`:

```
NTC 2021-11-17 20:53:42.108+01:00 Attestation failed to match head           topics="chaindag" epoch=81972 validator=...
```

Failures are reported with a lag of two epochs (~13 minutes).
To examine the log for potential root causes, the logs from the epoch in the failure message should be looked at.

!!! warning
    It should be noted that metrics are tracked for the current history.
    In the case of a reorg on the chain — in particular a deep reorg — no attempt is made to revisit previously reported values.
    In the case that finality is delayed, the risk of stale metrics increases.

Likewise, many metrics, such as aggregation inclusion, reflect conditions on the network.
It may happen that the same message is counted more than once under certain conditions.

## Monitoring metrics

For instructions on how to use Prometheus and Grafana, see [these instructions](./metrics-pretty-pictures.md).

The full list of metrics supported by the validator monitoring feature can be seen in the [source code](https://github.com/status-im/nimbus-eth2/blob/unstable/beacon_chain/validators/validator_monitor.nim) or by examining the metrics output:

```sh
curl -s localhost:8008/metrics | grep HELP.*validator_
```
