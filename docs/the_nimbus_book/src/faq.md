# Frequently Asked Questions

## Nimbus

### Why are metrics not working?

Metrics are currently implemented using a HTTP server that hasn't been hardened sufficiently (which means it can't be exposed as a public endpoint). It must therefore be enabled specifically during build:

```
make NIMFLAGS="-d:insecure" beacon_node --metrics ...
```

## Validating

### What exactly is a validator?

A validator is an entity that participates in the consensus of the Ethereum 2.0 protocol.

Or in plain english, a human running a computer process. This process proposes and vouches for new blocks to be added to the blockchain.

In other words, **you can think of a validator as a voter for new blocks.** The more votes a block gets, the more likely it is to be added to the chain.

Importantly, a validator's vote is weighted by the amount it has at stake.


### What is the deposit contract?

You can think of it as a transfer of funds between Ethereum 1.0 accounts and Ethereum 2.0 validators.

It specifies who is staking, who is validating, how much is being staked, and who can withdraw the funds.

### Why do validators need to have funds at stake?
Validators need to have funds at stake so they can be penalized for behaving dishonestly.

In other words, to keep them honest, their actions need to have financial consequences.

### How much ETH does a validator need to stake?

Before a validator can start to secure the network, he or she needs to stake **32 ETH**. This forms the validator's initial balance.

### Is there any advantage to having more than 32 ETH at stake?

No. There is no advantage to having more than 32 ETH staked. 

Limiting the maximum stake to 32 ETH encourages decentralization of power as it prevents any single validator from having an excessively large vote on the state of the chain.

> Remember that a validator’s vote is weighted by the amount it has at stake.

### How are validators incentivized to stay active and honest?

In addition to being penalized for being offline, validators are penalized for behaving maliciously – for example attesting to invalid or contradicting blocks.

On the other hand, they are rewarded for proposing / attesting to blocks that are included in the chain.

The key concept is the following:

- Rewards are given for actions that help the network reach consensus
- Minor penalties are given for inadvertant actions (or inactions) that hinder consensus
- And major penalities -- or **slashings** -- are given for malicious actions

In other words, validators that maximize their rewards also provide the greatest benefit to the network as a whole.

### How are rewards/penalties issued?

Remember that each validator has its own balance -- with the initial balance outlined in the deposit contract.

This balance is updated periodically by the Ethereum network rules as the validator carries (or fails to carry) out his or her responsibilities.

Put another way, rewards and penalties are reflected in the validator's balance over time.


### How often are rewards/penalties issued?

Approximately every six and a half minutes -- a period of time known as an epoch.

Every epoch, the network measures the actions of each validator and issues rewards or penalties appropriately.


### How large are the rewards/penalties?

There is no easy answer to this question as there are many factors that go into this calculation.

Arguably the most impactful factor on rewards earned for validating transactions is the total amount of stake in the network. In other words, the total amount of validators. Depending on this figure the max annual return rate for a validator can be anywhere between 2 and 20%.

Given a fixed total number of validators, the rewards/penalties predominantly scale with the balance of the validator -- attesting with a higher balance results in larger rewards/penalties whereas attesting with a lower balance results in lower rewards/penalties.

>Note however that this scaling mechanism works in a non-obvious way. To understand the precise details of how it works requires understanding a concept called **effective balance**. If you're not yet familiar with this concept, we recommend you read through this [excellent post](https://www.attestant.io/posts/understanding-validator-effective-balance/).


### Why do rewards depend on the total number of validators in the network?

Block rewards are calculated using a sliding scale based on the total amount of ETH staked on the network.

In plain english: if the total amount of ETH staked is low, the reward (interest rate) is high, but as the total stake rises, the reward (interest) paid out to each validator starts to fall.

Why a sliding scale? While we won't get into the gory details here, the basic intution is that there needs to be a minimum number of validators (and hence a minimum amount of ETH staked) for the network to function properly. So, to incentivize more validators to join, it's important that the interest rate remains high until this minimum number is reached.

Afterwards, validators are still encouraged to join (the more validators the more decentralized the network), but it's not absolutely essential that they do so (so the interest rate can fall).

### How badly will a validator be penalized for being offline?

It depends. In addition to [the impact of effective balance](https://www.attestant.io/posts/understanding-validator-effective-balance/#the-impact-of-effective-balance-on-validating) there are two important scenarios to be aware of:

1. Being offline while a supermajority (2/3) of validators is still online leads to relatively small penalties as there are still enough validators online for the chain to finalize. **This is the expected scenario.**

2. Being offline at the same time as more than 1/3 of the total number of validators leads to harsher penalties, since blocks do not finalize anymore. **This scenario is very extreme and unlikely to happen.**

> Note that in the second (unlikely) scenario, validators stand to progressively lose up to 50% (16 ETH) of their stake over 21 days. After 21 days they are ejected out of the validator pool. This ensures that blocks start finalizing again at some point.

### How great does an honest validator's uptime need to be for it to be net profitable?

Overall, validators are expected to be net profitable as long as their uptime is [greater than 50%](https://blog.ethereum.org/2020/01/13/validated-staking-on-eth2-1-incentives/). 

This means that validators need not go to extreme lengths with backup clients or redundant internet connections as the repercussions of being offline are not so severe.

### How much will a validator be penalized for acting maliciously?

Again, it depends. Behaving maliciously – for example attesting to invalid or contradicting blocks, will lead to a validator's stake being slashed.

The minimum amount that can be slashed is 1 ETH, but **this number increases if other validators are slashed at the same time.**

The idea behind this is to minimize the losses from honest mistakes, but strongly disincentivize coordinated attacks.

### What exactly is slashing?

Slashing has two purposes: (1) to make it prohibitively expensive to attack eth2, and (2) to stop validators from being lazy by checking that they actually perform their duties. Slashing a validator is to destroy (a portion of) the validator’s stake if they act in a provably destructive manner. 

Validators that are slashed are prevented from participating in the protocol further and are forcibly exited.


### What happens I lose my signing key?

If the signing key is lost, the validator can no longer propose or attest.

Over time, the validator's balance will decrease as he or she is punished for not participating in the consensus process. When the validator's balance reaches 16 Eth, he or she will be automatically exited from the validator pool.

> However, all is not lost. Assuming validators derive their keys using [EIP2334](https://eips.ethereum.org/EIPS/eip-2334) (as per the default onboarding flow)then **validators can always recalculate their signing key from their withdrawal key**.

The 16 Eth can then be withdrawn -- with the withdrawal key -- after a delay of around a day.

> Note that this delay can be longer if many others are exiting or being kicked out at the same time.

### What happens if I lose my withdrawal key?

If the withdrawal key is lost, there is no way to obtain access to the funds held by the validator.

As such, it's a good idea to create your keys from mnemonics which act as another backup. This will be the default for validators who join via this site's onboarding process.

### What happens if my withdrawal key is stolen?

If the withdrawal key is stolen, the thief can transfer the validator’s balance, but only once the validator has exited.

If the signing key is not under the thief’s control, the thief cannot exit the validator. 

The user with the signing key could attempt to quickly exit the validator and then transfer the funds -- with the withdrawal key -- before the thief.

### Why two keys instead of one?

In a nutshell, security. The signing key must be available at all times. As such, it will need to be held online. Since anything online is vulnerable to being hacked, it's not a good idea to use the same key for withdrawals.


