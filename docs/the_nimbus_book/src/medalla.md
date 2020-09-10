# Become a Medalla validator

This chapter will take you through how to become a validator on the eth2 testnet [Medalla](https://github.com/goerli/medalla).

If you generated your signing key using the [eth2 launchpad](https://medalla.launchpad.ethereum.org/), and wish to import it into the Nimbus client, this page is for you.

> If you haven't created your validator key yet, we recommend you do so using the [launchpad](https://medalla.launchpad.ethereum.org/). If you're not sure what the eth2 launchpad is, we recommend reading this [introductory post](https://blog.ethereum.org/2020/07/27/eth2-validator-launchpad/) first.


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
You should see that the beacon node has launched with your validator attached:

```
WRN 2020-08-03 16:24:17.950+02:00 Validator not in registry (yet?)           topics="beacval" tid=11677993 file=validator_duties.nim:53 pubKey=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validator attached                   tid=11677993 file=validator_pool.nim:21 pubKey=a9c4df36 validator=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validators attached                  topics="beacval" tid=11677993 file=validator_duties.nim:61 count=1
INF 2020-08-03 16:24:17.958+02:00 Starting beacon node                       topics="beacnde" tid=11677993 file=beacon_node.nim:875 version="0.5.0 (31b33907)" nim="Nim Compiler Version 1.2.6 [MacOSX: amd64] (bf320ed1)" timeSinceFinalization=81350 head=ebe49843:0 finalizedHead=ebe49843:0 SLOTS_PER_EPOCH=32 SECONDS_PER_SLOT=12 SPEC_VERSION=0.12.2 dataDir=build/data/shared_medalla_0 pcs=start_beacon_node
```



> Tip: to 🎨 on the [graffitwall](https://medalla.beaconcha.in/graffitiwall), pass the graffiti parameter like this:
>```
>make NODE_PARAMS="--graffiti='<YOUR_GRAFFITI>'" medalla


#### 5. Keep an eye on your validator

If you deposited after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided (August 2nd 1300 UTC), your validators will have been put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or days.

The best way to keep track of your validator's status is [medalla.beaconcha.in](https://medalla.beaconcha.in) (click on the orange magnifying glass at the very top and paste in its public key). 

You can even [create an account](https://medalla.beaconcha.in/register) to add alerts and keep track of your validator's [performance](https://medalla.beaconcha.in/dashboard).

#### 6. Keep your validator updated

Finally, makes sure you stay on the lookout for any critical updates to Nimbus. This best way to do so is through the **medalla-announcements** channel on our [discord](https://discord.com/invite/XRxWahP).

To update to the latest version, disconnect from medalla and run:

```
git pull && make update
```

Once the update is complete, run `make medalla` to reconnect to the network.

Looking forward to seeing you on Medalla! 💛

## Key management

Keys are stored in the `build/data/shared_medalla_0/` folder, under `secrets` and `validators` - make sure you keep these folders backed up.

The `secrets` folder contains the common secret that gives you access to all your validator keys.

The `validators` folder contains your keystores (encrypted keys). Keystores are used by validators as a method for exchanging keys. For more on keys and keystores, see [here](https://blog.ethereum.org/2020/05/21/keys/).

>**Note:** The Nimbus client will only ever import your signing key -- in any case, if you used the deposit launchpad, this is the only key you should have (you can generate the withdrawal key from your mnemonic when you wish to withdraw).

## Metrics

Metrics are not included in the binary by default - to enable them, use the following options when starting the client:

```
make NIMFLAGS="-d:insecure" medalla
```

You can then browse the metrics by connecting to:

http://localhost:8008/metrics

Make sure this port is protected as the http server used is not considered secure (it should not be used by untrusted peers).

## Advanced options

### Start multiple nodes

You can start multiple local nodes, in different terminal windows/tabs, by specifying numeric IDs:

```
make medalla NODE_ID=0 # the default
make medalla NODE_ID=1
make medalla NODE_ID=2
```

### Attach multiple validators to the same beacon node

Simply [import as many keystores as you wish](./medalla.md#3-import-keystores) before running `make medalla`. Nimbus will automagically find your keys and attach your validators. See [key management](./medalla.md#key-management) for more information on where we store your keys.

To give you some context, we (the Nimbus team) are currently running 170 validators per beacon node on our AWS instances.

### Change the TCP and UDP ports

To change the TCP and UDP ports from their default value of 9000 to 9100, say, run:

```
make BASE_PORT=9100 medalla
```

You may need to do this if you are running another client.


### Make a deposit directly using Nimbus

```
make medalla-deposit VALIDATORS=2 # default is just 1
```

### Node parameters

You can customise your beacon node's parameters using the `NODE_PARAMS` option:

```
make NODE_PARAMS="--tcp-port=9100 --udp-port=9100" medalla
```

>**Note:** the above command has exactly the same effect as `make BASE_PORT=9100 medalla`

A complete list of the available parameters can be found [here](https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/conf.nim#L92-L210) (use a parameter's `name` field to set it).

### Logs

Log files are saved in `build/data/shared_medalla_0/`.


### Makefile

If you are comfortable reading [Makefiles](https://en.wikipedia.org/wiki/Makefile#:~:text=A%20makefile%20is%20a%20file,to%20generate%20a%20target%2Fgoal), you can see the commands that `make medalla`  executes under the hood, [here](https://github.com/status-im/nim-beacon-chain/blob/devel/Makefile#L184-L197).

Some of the provided options (such as `--network=medalla`) are essential while others (such as the ones controlling logging, metrics, ports, and the RPC service) are there for convenience.

The Goerli testnet parameters (`$(GOERLI_TESTNETS_PARAMS`), are defined higher up in the Makefile, [here](https://github.com/status-im/nim-beacon-chain/blob/devel/Makefile#L158-L165).

