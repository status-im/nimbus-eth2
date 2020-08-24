# Generate your keys with NBC

In this chapter, we'll take you through how to create an [EIP-2386](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md) wallet to help you generate your validator keys (keystores), create a `deposits_data` file compatible with the Ethereum Foundation's [Validator Launchpad](https://medalla.launchpad.ethereum.org/), and use the launchpad to send this data to the eth1 network so that your validator can be registered.


> **Note:** this page is primarily aimed at users who wish to run multiple validators on several machines. If you simply wish to get one validator up and running with Nimbus, or run several validators on a single machine, we recommend following our [become a Medalla validator](./medalla.md) guide instead.


For our purposes, a wallet is the [EIP-2386](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md) JSON file which contains an encrypted seed, a name, and a counter (`nextaccount`) that allows for generating validator keystores incrementally as outlined in [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334) (Deterministic Account Hierarchy). It's sometimes referred to as a wallestore.

Such a wallet can create (and restore) keys from a *seed* and a *path*. The encrypted seed is stored in the wallet (it needs to be accessible to create new keys). Further, the wallet also has a mechanism (a `nextaccount` index) for maintaining state about which keys have been generated (to help ensure you don't duplicate a key by accident).



## When do I need to use a  wallet?

If you're asking yourself this question then you probably don't need to use one :)

To be clear, the purpose of such a wallet is to help you generate your keystores (and keep track of how many you've generated). But you don't need a wallet to do this.

> **Tip:** You can use tools like the Ethereum Foundation's [deposit-cli](https://github.com/ethereum/eth2.0-deposit-cli) to generate keystores without a wallet. In fact, we recommend this approach if you're not sure whether or not you need a wallet.

## Prerequisites

You need to have installed Nimbus' [external dependencies](./install.md#external-dependencies) and [built the beacon node](./beacon_node.md#building-the-node).


## 1. Create  a wallet

Run the following command from the the home directory of the `nim-beacon-chain` repository to launch the command line interface app:

```
build/beacon_node wallets create
```

Now follow the instructions presented to you in the terminal window to create your wallet.

```bash
Wallet id: <YOUR_WALLET_ID>
INF 2020-08-18 11:05:47.126+02:00 Wallet file written
tid=137382
file=keystore_management.nim:404
path="<WHERE_YOUR_WALLET_IS_SAVED>"
```

At the end of the process, you should see the above message printed to the terminal. Make sure to keep track of your wallet id, and path.

### Available options

To see a list of the options/flags available, run:
```bash
build/beacon_node wallets create --help
```

You should see the following:

```
The following options are available:

 --next-account      Initial value for the 'nextaccount' property of the wallet.
 --name              An easy-to-remember name for the wallet of your choice.
 --out               Output wallet file.
```

## 2. Create a keystore and signed deposit

To generate 1 keystore and create a `deposit_data` JSON file using an existing wallet, run:
```bash
build/beacon_node deposits create --wallet="<YOUR_WALLET_ID>" --count=1
```
> **Tip:** To find your wallet id, look at your terminal history. You should see it printed right after you created your wallet. It's also saved in the `uuid` field of your wallet (remember your wallet is simply a JSON file).

Enter your password to unlock your wallet, create your signing keystore, and generate a `deposit_data` file.

```bash
INF 2020-08-19 13:53:24.271+02:00 Generating deposits
tid=330637
file=keystore_management.nim:143 
totalValidators=2
validatorsDir=validators 
secretsDir=secrets

INF 2020-08-19 13:53:24.286+02:00 Deposit data written
topics="beacnde" tid=330637 
file=beacon_node.nim:1406 
filename=validators/deposit_data-1597838004.284995.json
```

The deposit data file you just created contains a signed deposit (signed by the key you just created). You can find it in the newly created `validators` directory.

In the `validators` directory you should also see a folder with a name that looks something like `0x8c...3ed3a5052e2d`. The name of this folder is your validator's public key. Inside it you'll find your validator's signing keystore -- `keystore.json`.

> **Note:** If you wish to create a new wallet from which to make a deposit (simply run `deposits create` with no extra flags).

### Available options

To see a list of the options/flags available, run:
```bash
build/beacon_node deposits create --help
```

You should see the following:
```
The following options are available:

 --count                   Number of deposits to generate.
 --wallet                  An existing wallet ID. If not specified, a new wallet will be created.
 --out-validators-dir      Output folder for validator keystores.
 --out-secrets-dir         Output folder for randomly generated keystore passphrases.
 --out-deposits-file       The name of generated deposits file.
 --new-wallet-name         An easy-to-remember name for the wallet of your choice.
 --new-wallet-file         Output wallet file.
```

</details>

## 3. Send your deposit transaction(s)

 You're now ready to upload your `deposit_data` JSON file along with your signing keystore(s) to the EF's [Validator Launchpad](https://medalla.launchpad.ethereum.org/): it will take you through how to create the necessary transaction(s) to make your deposit(s) and register your validator(s).
 
>**Note:** Your `deposit_data` file contains a list of all your signed deposits. So even if you have many keystores, you should only have one `deposit_data` file.

0. Make sure you have enough [Goerli ETH](https://faucet.goerli.mudit.blog/)  (32 ETH for each validator you wish to run). See [here](create_wallet_and_deposit.md#a-note-on-acquiring-goerli-eth) for how to request Goerli ETH.

1. Go to [https://medalla.launchpad.ethereum.org](https://medalla.launchpad.ethereum.org/)

<img src="https://storage.googleapis.com/ethereum-hackmd/upload_431e6a8ec269404e3f89fec7133482b9.png" width="700">

2. Click on **Get Started**

<img src="https://storage.googleapis.com/ethereum-hackmd/upload_cbe2983e3795cfa57b621ae21b6ba165.png" width="700">

3. Read through the *Overview section* -- making sure you understand the risks and responsibilities involved

<p>
<img width="350" src="https://storage.googleapis.com/ethereum-hackmd/upload_86a7b1e968fe5830cac4a06d4597f221.png">
<img width="350" src="https://storage.googleapis.com/ethereum-hackmd/upload_a630e2ad0e9c5e6c3111dd1fba3c9767.png">
</p>

4. Move on to the *Generate Keys* section to choose how many validators you'd like to run (1 per 32 ETH deposited)

<img src="https://storage.googleapis.com/ethereum-hackmd/upload_0fd4e55870b4b6ce57c80644323b45bd.png" width="700">


5. Scroll to the end of the Key Generation page, tick the box, and click continue

<img src="https://storage.googleapis.com/ethereum-hackmd/upload_10fcb69be02662e10bc4b62c29d8a074.png" width="700">



6. Upload the Deposit data file you generated using Nimbus in the previous step

<img src="https://storage.googleapis.com/ethereum-hackmd/upload_6db4e4c3715a0a80db53bd5f26eb1ffc.png" width="500">

*Remember you can find your `deposit_data` JSON file in the `nim-beacon-chain/validators` directory*

</br>

The launchpad will then double check you understand the most important things. And help you send the required transaction(s).

<p>
<img width="350" src="https://storage.googleapis.com/ethereum-hackmd/upload_e2c60ad1c9840d0f2fcf5c4ae8ec284a.png">
<img width="350" src="https://storage.googleapis.com/ethereum-hackmd/upload_0d3c0a5c8cb421041b6847f0c2d24328.png">
</p>

### A note on acquiring Goerli ETH
The easiest way to acquire testnet ETH is to join [Prysmatic Labs' discord](https://discord.com/invite/YMVYzv6) and send a request for ETH in the **#-request-goerli-eth channel**.

```
!send <your metamask goerli network ETH address>
```

You can also use the [Goerli Authenticated Faucet](https://faucet.goerli.mudit.blog/).

## 4. Connect to Medalla

Now that you've generated your keys and registered your validator, the final step is to [connect to Medalla](medalla.md#connect-to-medalla).


### A note on expected waiting time (the queue)

Once you send off your transaction(s), your validator will be put in a queue based on deposit time, and will getting through the queue may take a few hours or days (assuming the chain is finalising).

More technically: approximately every 3.5 hours the eth2 beacon chain receives an "include until X" eth1 block to vote on: this block must be at least 1024 blocks behind the eth1 head. However, can be made anywhere between the start and the end of a voting period, the time you'll need to wait can fluctuate (within a range of 1 or 2 voting periods).


