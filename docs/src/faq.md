# Frequently Asked Questions

## 1. What is Beacon Chain?

A complete introduction about the beacon chain can be found in the [Ethereum 2.0 blog series](https://our.status.im/two-point-oh-the-beacon-chain/).

In short, the beacon chain is a **new type of blockchain** to help the Ethereum blockchain to smoothly transfer its consensus algorithm from PoW (Proof of Work) to PoS (Proof of Stake), aka Ethereum 2.0. You can also see it as a hybrid PoS + PoW solution.

## 2. Differences Between Beacon Chain and Ethereum 1.0

In traditional PoW, those that propose new blocks are called **_miners_**, whereas in PoS, they are called **_validators_**. In essence, _miners_ rely on actual hardware (such as some specifically manufactured mining machines), while _validators_ rely on just software.

## 3. What it is Like to Be a Validator?

It is obvious that you must have enough computing power or dedicated hardware in order to be a miner, but how about being a validator? Here is a brief overview:

1. A special smart contract named **_deposit contract_** is deployed on the original Ethereum blockchain. Note that in this case, the new beacon chain and the original blockchain co-exists.
2. To "register" as a validator, you have to first deposit **_32 Ether_** from your account to this smart contract.
3. Run the beacon node and wait for the network to sync before your validator is activated.
4. That's all! Remember to stay connected to the network, or you may lose your deposit. :P

## 4. What is Nimbus?

In a sentence, Nimbus is an Ethereum 1.0 & 2.0 Client for Resource-Restricted Devices.

It is open sourced at [github.com/status-im/nimbus](github.com/status-im/nimbus). Development progress and updates can be viewed at the [Nimbus blog](https://our.status.im/tag/nimbus/).

## 5. Why should you choose Nimbus?
