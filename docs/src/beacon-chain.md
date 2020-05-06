# What is Beacon Chain?

A complete introduction about the beacon chain can be found in the [Ethereum 2.0 blog series](https://our.status.im/two-point-oh-the-beacon-chain/).

In short, the beacon chain is a **new type of blockchain** to help the Ethereum blockchain to smoothly transfer its consensus algorithm from PoW (Proof of Work) to PoS (Proof of Stake), aka Ethereum 2.0. You can also see it as a hybrid PoS + PoW solution.

## Differences Compared to Ethereum 1.0
In traditional PoW, those that propose new blocks are called **_miners_**, whereas in PoS, they are called **_validators_**. In essence, *miners* rely on actual hardware (such as some specifically manufactured mining machines), while *validators* rely on just software.  

## How to Become a Validator?
It is obvious that you must have enough computing power or a dedicated hardware in order to be a miner, but how about being a validator? To give you a simple overview, below is the actual steps according to the current implementation:
1. There is a special smart contract named "*registration contract*" deployed on the original Ethereum blockchain. Note that in this case, the new beacon chain and the original blockchain co-exists. 
2. To "register" as a validator, you have to deposit *32 Etheres* to the smart contract first.
3. Run a beacon node 

