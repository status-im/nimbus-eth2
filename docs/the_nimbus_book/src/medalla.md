# Become a Medalla validator

This page will take you through how to become a validator on the eth2 testnet [Medalla](https://github.com/goerli/medalla).

If you generated your signing key using the [eth2 launchpad](https://medalla.launchpad.ethereum.org/), and wish to import it into the Nimbus client, this page is for you.

> If you haven't created your validator key yet, we recommend you go through the [launchpad first](https://medalla.launchpad.ethereum.org/). If you're not sure what the eth2 launchpad is, we recommend reading this [introductory post](https://blog.ethereum.org/2020/07/27/eth2-validator-launchpad/).

## Prerequisites

If this is your first time playing with Nimbus, make sure you [install our external dependencies](./install.md) first.

This tutorial assumes basic knowledge of the [command line](https://www.learnenough.com/command-line-tutorial/basics#:~:text=Learn%20Enough%20Command%20Line%20to%20Be%20Dangerous%20is%20an%20introduction,broad%20an%20audience%20as%20possible.).

## Validating

To start validating on the `medalla` network:


#### 1. Clone the nim beacon chain repository

```
git clone https://github.com/status-im/nim-beacon-chain
cd nim-beacon-chain
git checkout devel
```

#### 2. Build the beacon node
```
make beacon_node
```

*Patience... this may take a few minutes.*

#### 3. Import keystore(s)

```
build/beacon_node deposits import  --data-dir=build/data/shared_medalla_0 <YOUR VALIDATOR KEYS DIRECTORY>
```

Replacing `<YOUR VALIDATOR KEYS DIRECTORY>` with the full pathname of your `validator_keys` directory.

> Tip: run `pwd` in your `validator_keys` directory to print the full pathname to the console.

You'll be asked to enter the password you created to encrypt your keystore(s) in the *Generate Keys* section of the Launchpad process. Don't worry, this is entirely normal. Your validator client needs both your keystore(s) and the password encrypting it to import your [keys](https://blog.ethereum.org/2020/05/21/keys/) (since it needs to decrypt the keystore in order to be able to use it to sign on your behalf).


#### 4. Connect to Medalla

```
make medalla
```

This will build Nimbus and its dependencies, and connect you to Medalla.
You should see that the beacon node has launched with your validator attached and is waiting for [genesis](https://hackmd.io/@benjaminion/genesis) to start:

```
WRN 2020-08-03 16:24:17.950+02:00 Validator not in registry (yet?)           topics="beacval" tid=11677993 file=validator_duties.nim:53 pubKey=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validator attached                   tid=11677993 file=validator_pool.nim:21 pubKey=a9c4df36 validator=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validators attached                  topics="beacval" tid=11677993 file=validator_duties.nim:61 count=1
INF 2020-08-03 16:24:17.958+02:00 Starting beacon node                       topics="beacnde" tid=11677993 file=beacon_node.nim:875 version="0.5.0 (31b33907)" nim="Nim Compiler Version 1.2.6 [MacOSX: amd64] (bf320ed1)" timeSinceFinalization=81350 head=ebe49843:0 finalizedHead=ebe49843:0 SLOTS_PER_EPOCH=32 SECONDS_PER_SLOT=12 SPEC_VERSION=0.12.2 dataDir=build/data/shared_medalla_0 pcs=start_beacon_node
NOT 2020-08-03 16:24:17.958+02:00 Waiting for genesis                        topics="beacnde" tid=11677993 file=beacon_node.nim:890 genesisIn=22h35m50s0ns
```
<details>

<summary>Tips on how to graffiti and run multiple clients</summary>

> To draw on the [graffitwall](https://medalla.beaconcha.in/graffitiwall), pass the graffiti parameter like this:
>```
>make NODE_PARAMS="--graffiti='<YOUR_GRAFFITI>'" medalla
>```

> If you are running another client, you may need to use a different port. To change port, run:
>```
>make BASE_PORT=<YOUR_PORT_NUMBER> medalla
>```

</details>

#### 5. Keep an eye on your validator

If you deposited after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided (August 2nd 1300 UTC), your validators will have been put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or days.

The best way to keep track of your validator's status is [medalla.beaconcha.in](https://medalla.beaconcha.in) (click on the orange magnifying glass at the very top and paste in its public key). 

You can even [create an account](https://medalla.beaconcha.in/register) to add alerts and keep track it its [performance](https://medalla.beaconcha.in/dashboard).

#### 6. Keep your validator updated

Finally, makes sure you stay on the lookout for any critical updates to Nimbus. This best way to do so is through the **medalla-announcements** channel on our [discord](https://discord.com/invite/XRxWahP).

To update to the latest version, disconnect from medalla and run:

```
git pull && make update
```

Once the update is complete, run `make medalla` to reconnect to the network.

Looking forward to seeing you on Medalla! 💛

### A note on keys

The Nimbus client will only ever import your signing key -- in any case, if you used the deposit launchpad, this is the only key you should have (you can generate the withdrawal key from your mnemonic when you wish to withdraw). The keys your Nimbus client has access to are stored in the `build/data/shared_medalla_0/` folder, under `secrets` and `validators`.

The `secrets` folder contains the common secret that gives you access to all your validator keys. And the `validators` folder contains your keystores.

For more on keys in eth2, see [here](https://blog.ethereum.org/2020/05/21/keys/).
