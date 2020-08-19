# Create a validator wallet and make a deposit

In this page we'll take you through how to create a wallet to help generate your validator keys (keystores) and make a deposit using Nimbus.

> **Note:** this page is primarily aimed at users who wish to run multiple validators on several machines. If you simply wish to get one validator up and running with Nimbus, or run several validators on a single machine, we recommend following [this guide](./medalla.md) instead.


For our purposes, a wallet is the [EIP-2386](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md) JSON file which contains an encrypted seed, a name, and a counter (`nextaccount`) that allows for generating validator keystores incrementally as outlined in [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334) (Deterministic Account Hierarchy). It's sometimes referred to as a wallestore.

Such a wallet can create (and restore) keys from a *seed* and a *path*. The encrypted seed is stored in the wallet (it needs to be accessible to create new keys). Further, the wallet also has a mechanism (a `nextaccount` index) for maintaining state about which keys have been generated (to help ensure you don't duplicate a key by accident).



## When do I need to use a validator wallet?

If you're asking yourself this question then you probably don't need to use one :)

To be clear, the purpose of such a wallet is to help you generate your keystores (and keep track of how many you've generated). But you don't need a wallet to do this.

> **Tip:** You can use tools like the Ethereum Foundation's [deposit-cli](https://github.com/ethereum/eth2.0-deposit-cli) to generate keystores without a wallet. In fact, we recommend this approach if you're not sure whether or not you need a wallet.

## Prerequisites

You need to have installed Nimbus' [external dependencies](./install.md#external-dependencies) and [built the beacon node](./beacon_node.md#building-the-node).


## Create  a wallet

Run the following command from the the home directory of the `nim-beacon-chain` repository to launch the command line interface app:

```
build/beacon_node wallets create
```

Now follow the instructions presented to you in the terminal window to create your wallet.

```bash
Wallet name: <YOUR_WALLET_NAME>
Wallet id: <YOUR_WALLET_ID>
INF 2020-08-18 11:05:47.126+02:00 Wallet file written
tid=137382
file=keystore_management.nim:404
path="<WHERE_YOUR_WALLET_IS_SAVED>"
```

At the end of the process, you should see the above message printed to the terminal. Make sure to keep track of your wallet name, id, and path.

## Create a deposit data file
*Create a deposits_data file compatible with the Ethereum Foundation's Validator Launchpad.*

To generate a keystore and create a `deposit_data` JSON file using an existing wallet, run:
```bash
build/beacon_node deposits create --wallet="<YOUR_WALLET_ID>"
```
> **Tip:** Your wallet id should have been printed to the terminal when you created your wallet. It's also saved in the `uuid` field of your wallet (remember your wallet is just a JSON file).

Enter your password to unlock your wallet, create your signing keystore, and generate a `deposit_data` file.

```bash
INF 2020-08-19 13:53:24.271+02:00 Generating deposits
tid=330637
file=keystore_management.nim:143 
totalValidators=1
validatorsDir=validators 
secretsDir=secrets

INF 2020-08-19 13:53:24.286+02:00 Deposit data written
topics="beacnde" tid=330637 
file=beacon_node.nim:1406 
filename=validators/deposit_data-1597838004.284995.json
```

The deposit data file you just created contains your validator public key(s). You can find it in the newly created `validators` directory.

> **Note:** when you create deposits with `deposits create`, you can either reference an existing wallet (by passing the `--wallet` flag as we do above) or create a new wallet from which to make a deposit (just run `deposits create` with no flags).

*explain how to make multiple deposits in one go*

## Make a deposit using the launchpad

 You can upload your `deposit_data` file along with your signing keystore(s) to the the Ethereum Foundation's [Validator Launchpad](https://medalla.launchpad.ethereum.org/) to register your validator(s).
 
 *explain where to find your keystore(s)*

*TO BE FILLED*

## Pass your keys to the Nimbus validator client

*TO BE FILLED*

> Importantly, to run a validator you only need to pass the signing keystore which leaks nothing about the withdrawal key (except perhaps the path that it can be derived with).

