# Optimise for profitability

Profitability depends heavily on the network and peer quality.

While block proposals are more lucrative than attestations, they are much rarer.


## Check for next action before restarting


To see when your validator is next due to make an attestation or proposal pay attention to the `Slot end` messages in your logs:
```
INF 2021-05-31 17:46:11.094+02:00 Slot end
topics="beacnde" tid=213670 file=nimbus_beacon_node.nim:932
slot=1304329
nextSlot=1304330
head=cffee454:38460
headEpoch=1201
finalizedHead=077da232:38368
finalizedEpoch=1199
nextAttestationSlot=338638
nextProposalSlot=-1
nextActionWait=4m35s874ms405us837ns
```

Specifically, have a look at `nextActionWait` time.


If you're concerned about missing an attestation or proposal, wait until `nextActionWait` is greater than 4 minutes or so before restarting Nimbus.


You can also use the `nimbus-eth2` [API](./api.md). For example, to check if your validator has a next Proposal slot assigned, run:

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_duties_proposer","params":[${EPOCH_NUMBER_OF_INTEREST}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq ".result[]" | grep ${PATTERN_WHICH_MATCHES_VALIDATOR_PUBLIC_KEYS}
```

### Bash script

Quick and dirty bash monitoring/Nimbus-restarting loop:

```bash
while true; do tail -n2000 nimbus_beacon_node.log | grep nextActionWait | tail -n1 | jq -r .nextActionWait | grep '^[4-9]m' && kill -s SIGINT ${PID} && break; sleep 13; done
```

## Subscribe to all subnets
Launching the beacon node with the `--subscribe-all-subnets` option increases bandwidth and cpu usage, but helps the network and makes the block production algorithm perform slightly better.

To elaborate a little, without this option enabled Nimbus only listens to a subset of the attestation traffic - in particular, Nimbus doesn't listen to all unaggregated traffic but instead relies on peers to aggregate attestations on the subnets it doesn't subscribe to. 

With this option enabled, Nimbus listens to all unaggregated channels (subscribes to all subnets). Practically speaking, this means that when producing a block, Nimbus can "top up" the aggregates that other peers have made with it's own unaggregated attestations. This can lead to better packing in some cases, which can lead to slightly greater rewards.




## Keep track of your attestation effectiveness
Attestation effectiveness is a metric that directly affects your validator rewards. In simple terms, an attestation is more valuable the sooner it is put into a block and included in the chain. This interval is called the "inclusion distance" of an attestation. The smaller it is, the more profitable your validator will be. For a deeper understanding we highly recommend reading [Attestant's wonderful blog post](https://www.attestant.io/posts/defining-attestation-effectiveness/#:~:text=Stakers%20looking%20to%20maximize%20their,provide%20clear%20metrics%20for%20performance.) on the matter and [bison trail's eth2 insights report](https://bisontrails.co/eth2-insights-validator-effectiveness/).

You can verify your validator's effectiveness on the [beaconcha.in](https://beaconcha.in/) website.

![](https://i.imgur.com/u80Ub2j.png)

Ideally you want to see a value above 80%.

While attestation effectiveness depends on a variety of factors - attestation network propagation, your network connectivity, and the peers you are connected to - your network connectivity is likely the most important factors you can control to improve this metric. See [here](./health.md) for some tips on how to do so.




