# Frequently Asked Questions

## General

### Can I run Nimbus on my machine?

Check our [system requirements](./hardware.md) and [how to prepare your machine](./install.md).
Note that it is also possible to [run Nimbus on Raspberry Pi](./pi-guide.md).


### I'm currently using Prysm / Lighthouse / Teku, how do I migrate to Nimbus?

See our [migration guide](./migration.md).

### Which version of Nimbus am I running?

You can check the version through a number of methods:

```sh
# Run the beacon node with the --version flag:
build/nimbus_beacon_node --version

# Query the metrics server - requires running with the '--metrics' option
curl -s http://localhost:8008/metrics | grep version

# Query the REST API - requires running with the '--rest' option
curl -s http://localhost:9100/eth/v1/node/version
```

### How to upgrade Nimbus to a newer version?

See our [upgrading guide](./keep-updated.md).

### Why are metrics not working?

The metrics server is disabled by default.
Enable it by passing `--metrics` to the run command:

```sh
build/nimbus_beacon_node --metrics ...
```

### Why is the REST server not working?

The REST server is disabled by default.
Enable it by passing `--rest` to the run command:

```sh
build/nimbus_beacon_node --rest ...
```

### Why does my validator miss two epochs of attestations after (re)starting?

When a validator is started (or restarted), it listens for 2 epochs for attestations from a validator with the same public key (a doppelganger), before sending an attestation itself.
This is a simple way of handling the case where one validator comes online with the same key as another validator that's already online, e.g. one device was started without switching the other off.

While this strategy requires the client to wait two whole epochs on restart before attesting, a couple of missed attestations is a very minor price to pay in exchange for significantly reducing the risk of an accidental slashing.
You can think of it as a small penalty that you pay only on first launch and restarts.
When you take into account the total runtime of your validator, the impact should be minimal.

While we strongly recommend against it, you can disable doppelganger detection with an explicit flag (`--doppelganger-detection=false`) if you don't plan on moving your setup.

### What is the best way to stress test my execution+consensus setup before committing with real ETH?

We recommend running [a Nimbus beacon node](./quick-start.md) on [Holesky](./holesky.md) and a mainnet [execution client](./eth1.md) on the same machine.
This will simulate the load of running a mainnet validator.

To stress test it, add `--subscribe-all-subnets` to the [beacon node options](./options.md).
This simulates the maximum load that the consensus layer will put on the machine should you run 64 validators or more on it.

### How do I add an additional validator?

See the information [here](./additional-validator.md).

### What does `synced/opt` mean, in the "Slot start" message?

When `/opt` is present in the "Slot start" message, it means the node is [optimistically synced](./optimistic-sync.md) and is waiting for the execution client to finish its syncing process.
Until that happens, validator duties are disabled.

### Syncing is very slow, can this be sped up?

A complete sync might take several hours or even days.
We recommend you to do a [trusted node sync](./trusted-node-sync.md), which takes only few minutes.

### How can I automate running my beacon node?

You can set up a systemd service.
See [our systemd guide](./beacon-node-systemd.md).

### Folder Permissions

To protect against key loss, Nimbus requires that files and directories be owned by the user running the application.
Furthermore, they should not be readable by others.

It may happen that the wrong permissions are applied, particularly when creating the directories manually.

The following errors are a sign of this:

- `Data folder has insecure ACL`
- `Data directory has insecure permissions`
- `File has insecure permissions`

See the [data directory page](./data-dir.md#permissions) for instructions on how to fix this.





## Networking

### How can I improve my peer count?

See [the networking guide](./networking.md).

### How do I fix the discovered new external address warning log?

```
WRN 2021-03-15 02:23:37.569+00:00 Discovered new external address but ENR auto update is off topics="discv5"...
```

It's possible that your ISP has changed your dynamic IP address without you knowing.

The first thing to do it to try relaunching the beacon node with `--enr-auto-update` (pass it as an option in the command line).

If this doesn't fix the problem, the next thing to do is to check your external (public) IP address and detect open ports on your connection: you can use [https://www.yougetsignal.com/tools/open-ports/](https://www.yougetsignal.com/tools/open-ports/).
Note that Nimbus `TCP` and `UDP` ports are both set to `9000` by default.

See [here](./networking.md#set-up-port-forwarding) for how to set up port forwarding.






## Validating

### What exactly is a validator?

A validator is an entity that participates in the consensus of the Ethereum protocol, and has staked 32 ETH to do so.

Or, in plain English, a human running a computer process.
This process proposes and vouches for new blocks to be added to the blockchain.

In other words, you can think of a validator as a voter for new blocks.
The more votes a block gets, the more likely it is to be added to the chain.

Importantly, a validator's vote is weighted by the amount it has at stake.


### Do I need a separate validator client?

No, Nimbus doesn't require setting up a separate validator client process — the beacon node can itself perform validator duties.


### What is a deposit contract?

You can think of it as a transfer of funds between Ethereum 1.0 accounts and Ethereum 2.0 validators.

It specifies who is staking, who is validating, how much is being staked, and who can withdraw the funds.

### Why do validators need to have funds at stake?

Validators need to have funds at stake so they can be penalized for behaving dishonestly.
In other words: to keep them honest, their actions need to have financial consequences.

### How much ETH does a validator need to stake?

Before a validator can start to secure the network, they need to stake **32 ETH**.
This forms the validator's initial balance.

### Is there any advantage to having more than 32 ETH at stake?

No, there is no advantage to having more than 32 ETH staked.

Limiting the maximum stake to 32 ETH encourages decentralization of power as it prevents any single validator from having an excessively large vote on the state of the chain.

!!! note ""
    Remember that a validator’s vote is weighted by the amount it has at stake.

### Can I stop my validator for a few days and then start it back up again?

You can, but, under normal conditions, you will lose an amount of ETH roughly equivalent to the amount of ETH you would have gained in that period.
In other words, if you stood to earn ≈0.01 ETH, you would instead be penalized ≈0.01 ETH.

### How can I keep track of my validator?

One way of keeping track is using an online service such as beaconcha.in: [Mainnet](https://beaconcha.in/) or [Holesky](https://holesky.beaconcha.in).

Another way is to set up [validator monitoring](./validator-monitor.md) together with a [dashboard](./metrics-pretty-pictures.md) to keep track of its performance.


### I want to switch my validator keys to another machine, how long do I need to wait to avoid getting slashed?

We recommend waiting 2 epochs (around 15 minutes), before restarting Nimbus on a different machine.

### When should I top up my validator's balance?

The answer to this question very much depends on how much ETH you have at your disposal.

You should certainly top up if your balance is close to 16 ETH: this is to ensure you don't get removed from the validator set (which automatically happens if your balance falls below 16 ETH).

At the other end of the spectrum, if your balance is closer to 31 ETH, it's probably not worth your while adding the extra ETH required to get back to 32.

### When can I withdraw my funds, and what's the difference between exiting and withdrawing?

After the Capella hard-fork, activated on 12th of April 2023, all exited validators that use `0x01` withdrawal credentials will have their funds automatically withdrawn.
Please see our dedicated [guide for withdrawals](./withdrawals.md) for further information.

### How are validators incentivized to stay active and honest?

In addition to being penalized for being offline, validators are penalized for behaving maliciously (for example, attesting to invalid or contradicting blocks).

On the other hand, they are rewarded for proposing / attesting to blocks that are included in the chain.

The key concept is the following:

- Rewards are given for actions that help the network reach consensus.
- Minor penalties are given for inadvertent actions (or inactions) that hinder consensus.
- And major penalties — or **slashings** — are given for malicious actions.

In other words, validators that maximize their rewards also provide the greatest benefit to the network as a whole.

### How are rewards/penalties issued?

Remember that each validator has its own balance, with the initial balance outlined in the deposit contract.
This balance is updated periodically by the Ethereum network rules as the validator carries (or fails to carry) out his or her responsibilities.

Put another way, rewards and penalties are reflected in the validator's balance over time.


### How often are rewards/penalties issued?

Approximately every six and a half minutes — a period of time known as an epoch.

Every epoch, the network measures the actions of each validator and issues rewards or penalties appropriately.


### How large are the rewards/penalties?

There is no easy answer to this question as there are many factors that go into this calculation.

Arguably the most impactful factor on rewards earned for validating transactions is the total amount of stake in the network.
In other words, the total amount of validators.
Depending on this figure the max annual return rate for a validator can be anywhere between 2 and 20%.

Given a fixed total number of validators, the rewards/penalties predominantly scale with the balance of the validator: attesting with a higher balance results in larger rewards/penalties whereas attesting with a lower balance results in lower rewards/penalties.

Note however that this scaling mechanism works in a non-obvious way.
To understand the precise details of how it works requires understanding a concept called *effective balance*.
If you're not yet familiar with this concept, we recommend you read through this [excellent post](https://www.attestant.io/posts/understanding-validator-effective-balance/).


### Why do rewards depend on the total number of validators in the network?

Block rewards are calculated using a sliding scale based on the total amount of ETH staked on the network.

In plain English: if the total amount of ETH staked is low, the reward (interest rate) is high, but as the total stake rises, the reward (interest) paid out to each validator starts to fall.

Why a sliding scale?
While we won't get into the gory details here, the basic intuition is that there needs to be a minimum number of validators (and hence a minimum amount of ETH staked) for the network to function properly.
So, to incentivize more validators to join, it's important that the interest rate remains high until this minimum number is reached.

Afterwards, validators are still encouraged to join (the more validators the more decentralized the network), but it's not absolutely essential that they do so (so the interest rate can fall).

### How badly will a validator be penalized for being offline?

It depends.
In addition to [the impact of effective balance](https://www.attestant.io/posts/understanding-validator-effective-balance/#the-impact-of-effective-balance-on-validating), there are two important scenarios to be aware of:

1. Being offline while a supermajority (2/3) of validators is still online leads to relatively small penalties as there are still enough validators online for the chain to finalize. **This is the expected scenario.**

2. Being offline at the same time as more than 1/3 of the total number of validators leads to harsher penalties, since blocks do not finalize anymore. **This scenario is very extreme and unlikely to happen.**

Note that in the second (unlikely) scenario, validators stand to progressively lose up to 50% (16 ETH) of their stake over 21 days.
After 21 days they are ejected out of the validator pool.
This ensures that blocks start finalizing again at some point.

### How great does an honest validator's uptime need to be for it to be net profitable?

Overall, validators are expected to be net profitable as long as their uptime is [greater than 50%](https://blog.ethereum.org/2020/01/13/validated-staking-on-eth2-1-incentives/).

This means that validators don't need to go to extreme lengths with backup clients or redundant internet connections as the repercussions of being offline are not so severe.

### How much will a validator be penalized for acting maliciously?

Again, it depends.
Behaving maliciously, e.g. attesting to invalid or contradicting blocks, will lead to a validator's stake being slashed.

If a malicious behavior is detected, 1/32 of validator's staked ether (up to a maximum of 1 ETH) is immediately slashed and a 36-day removal period begins.
During this period, the validator's stake is gradually slashed and at day 18 an additional penalty is applied: the amount depends on the number of other slashed validators — the more validators are slashed, the magnitude of the slash increases.

The idea behind this is to minimize the losses from honest mistakes, but strongly discouraging coordinated attacks.

### What exactly is slashing?

Slashing has two purposes:

1. to make it prohibitively expensive to attack eth2, and
2. to stop validators from being lazy by checking that they actually perform their duties.

Slashing a validator is to destroy (a portion of) the validator’s stake if they act in a provably destructive manner.

Validators that are slashed are prevented from participating in the protocol further and are forcibly exited.


### What happens I lose my signing key?

If the signing key is lost, the validator can no longer propose or attest.

However, all is not lost.
Assuming validators derive their keys using [EIP2334](https://eips.ethereum.org/EIPS/eip-2334) (as per the default onboarding flow) then **validators can always recalculate their signing key from their withdrawal key**.

### What happens if I lose my withdrawal key?

If the withdrawal key is lost, there is no way to obtain access to the funds held by the validator.
As such, it's a good idea to create your keys from mnemonics which act as another backup.
This will be the default for validators who join via this site's onboarding process.

If the validator can no longer propose or attest, their balance will decrease over time as they are punished for not participating in the consensus process.
When the validator's balance reaches 16 ETH, they will be automatically exited from the validator pool, and 16 ETH will be transfered to their withdrawal address (as long it's specified).

!!! note
    After the Capella hard-fork, activated on 12th of April 2023, all exited validators that use `0x01` withdrawal credentials will have their funds automatically withdrawn.
    Please see our dedicated [guide for withdrawals](./withdrawals.md) for further information.

### What happens if my withdrawal key is stolen?

If the withdrawal key is stolen, the thief can transfer the validator’s balance, but only once the validator has exited.

If the signing key is not under the thief’s control, the thief cannot exit the validator.

The user with the signing key could attempt to quickly exit the validator and then transfer the funds — with the withdrawal key — before the thief.

### Why two keys instead of one?

In a nutshell, security.
The signing key must be available at all times.
As such, it will need to be held online.
Since anything online is vulnerable to being hacked, it's not a good idea to use the same key for withdrawals.

