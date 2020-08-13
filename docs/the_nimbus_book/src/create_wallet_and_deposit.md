# Create a walletstore and make a deposit

In this page we'll take you through how to create a walletstore and make a deposit (from now on we'll use the terms wallet and walletstore interchangeably)

First, we'll create a wallet.

> For our purposes, a wallet is the [EIP-2386](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md) JSON file which contains an encrypted seed, a name, and a counter (`nextaccount`) that allows for creating validators (generating keystores) incrementally as outlined in [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334) (Deterministic Account Hierarchy).

The wallet we'll create will be [hierarchical deterministic](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md).

An HD wallet can create keys from a *seed* and a *path*. The encrypted seed is stored in the wallet (it needs to be accessible to create new keys). Further, HD wallets also have a mechanism (a `nextaccount` index) for maintaining state about which keys have been generated (to ensure keys are not duplicated).

## When do I need to use a walletstore?

If you're asking yourself this question then you probably don't need to use one :)

To be clear, the purpose of a walletstore is to generate new validators. But you don't need a walletstore to do this.

You can use the Ethereum Foundation's [launchpad](https://medalla.launchpad.ethereum.org/) or [deposit-cli](https://github.com/ethereum/eth2.0-deposit-cli) to do this without a walletstore.

## Create  a wallet
```
build/beacon_node wallets create
```

*TO BE FILLED*

## Create a deposit
```
build/beacon_node deposits create
```

*TO BE FILLED*

*Creates a deposits_data file that should be compatible with the new Ethereum Launchpad.*

- creates wallet
- generates deposits
- writes to deposit_data file

> Note: when you create deposits with `deposits create`, you can reference an existing wallet or you can create a new one which will guide through the standard wallets create procedure.

## Which keys do i pass to my validator client?

Importantly, to run a validator you only need to pass the voting keystore which leaks nothing about the withdrawal key (except perhaps the path that it can be derived with).

