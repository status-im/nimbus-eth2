# Create a validator wallet and make a deposit

In this page we'll take you through how to create a wallet to help generate your validator keys (keystores) and make a deposit using Nimbus.

> **Note:** this page is primarily aimed at users who wish to run multiple validators on several machines. If you simply wish to get one validator up and running with Nimbus, or run several validators on a single machine, we recommend following [this guide](./medalla.md) instead.


For our purposes, a wallet is the [EIP-2386](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md) JSON file which contains an encrypted seed, a name, and a counter (`nextaccount`) that allows for generating validator keystores incrementally as outlined in [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334) (Deterministic Account Hierarchy). It's sometimes referred to as a wallestore.

Such a wallet can create (and restore) keys from a *seed* and a *path*. The encrypted seed is stored in the wallet (it needs to be accessible to create new keys). Further, the wallet also has a mechanism (a `nextaccount` index) for maintaining state about which keys have been generated (to help ensure you don't duplicate a key by accident).



## When do I need to use a validator wallet?

If you're asking yourself this question then you probably don't need to use one :)

To be clear, the purpose of such a wallet is to help you generate your keystores (and keep track of how many you've generated). But you don't need a wallet to do this.

> **Tip:** You can use tools like the Ethereum Foundation's [deposit-cli](https://github.com/ethereum/eth2.0-deposit-cli) to generate keystores without a wallet.

## Prerequisites

You need to have installed Nimbus' [external dependencies](./install.md#external-dependencies) and [built the beacon node](./beacon_node.md#building-the-node).

## Create  a wallet

Run the following command to launch the command line interface app:

```
build/beacon_node wallets create
```

Now follow the instructions presented to you in the terminal window to create your wallet.

```
Wallet name: <YOUR_WALLET_NAME>
Wallet id: <YOUR_WALLET_ID>
INF 2020-08-18 11:05:47.126+02:00 Wallet file written
tid=137382
file=keystore_management.nim:404
path=<WHERE_YOUR_WALLET_IS_SAVED>
```

At the end of the process, you should see the above message printed to the terminal. Make sure to keep track of your wallet name, id, and path!

## Create a deposit data file
*Creates a deposits_data file compatible with the Ethereum Foundation's Validator Launchpad.*

To generate a keystore and create a `deposit_data` JSON file using an existing wallet, run:
```
build/beacon_node deposits create --wallet=<YOUR_WALLET_ID>
```

*explain where to find your wallet id*




- creates wallet
- generates deposits
- writes to deposit_data file

> Note: when you create deposits with `deposits create`, you can reference an existing wallet or create a new one which will guide through the standard wallets create procedure (default).

The deposit data file you just created contains your validator public key(s). You can upload this file to the the Ethereum Foundation's [Validator Launchpad](https://medalla.launchpad.ethereum.org/) to register your validator(s).


## Make a deposit using the launchpad

## Pass your keys to the Nimbus validator client

Importantly, to run a validator you only need to pass the voting keystore which leaks nothing about the withdrawal key (except perhaps the path that it can be derived with).

