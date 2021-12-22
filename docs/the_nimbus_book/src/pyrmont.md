# Become a Pyrmont validator

This chapter will take you through how to become a validator on the eth2 testnet [Pyrmont](https://github.com/protolambda/pyrmont).

If you generated your signing key using the [eth2 launchpad](https://pyrmont.launchpad.ethereum.org/), and wish to import it into the Nimbus client, this page is for you.

> If you haven't created your validator key yet, we recommend you do so using the [launchpad](https://pyrmont.launchpad.ethereum.org/). If you're not sure what the eth2 launchpad is, we recommend reading this [introductory post](https://blog.ethereum.org/2020/07/27/eth2-validator-launchpad/) first.

## Prerequisites

This tutorial assumes basic knowledge of the [command line](https://www.learnenough.com/command-line-tutorial/basics#:~:text=Learn%20Enough%20Command%20Line%20to%20Be%20Dangerous%20is%20an%20introduction,broad%20an%20audience%20as%20possible.).

## Validating

To start validating on the `pyrmont` network:

### 1. Install the beacon node

You can either download a pre-compiled release or build the beacon node yourself:

#### 1a. Download the beacon node

Open the [Nimbus eth2 releases page](https://github.com/status-im/nimbus-eth2/releases/latest) and copy the link for the file that works on your system. 
If you're not sure which Linux release to use, `amd64` will work on home PCs while the `arm` builds work on low-power devices.

Run this in your home directory to download nimbus-eth2:

```
mkdir nimbus-eth2
wget <insert download link here>
tar -xzf nimbus-eth2_*.tar.gz -C nimbus-eth2
rm nimbus-eth2_*.tar.gz
```

Please continue to step 2.

#### 1b. Build the beacon node

> ⚠️ If this is your first time playing with Nimbus, please make sure you [install our external dependencies](./install.md) first.

```
git clone https://github.com/status-im/nimbus-eth2
cd nimbus-eth2
make nimbus_beacon_node
```

*Patience... this may take a few minutes.*

### 3. Import keystore(s)

```
build/nimbus_beacon_node deposits import  --data-dir=build/data/shared_pyrmont_0 <YOUR VALIDATOR KEYS DIRECTORY>
```

Replacing `<YOUR VALIDATOR KEYS DIRECTORY>` with the full pathname of your `validator_keys` directory.

> Tip: run `pwd` in your `validator_keys` directory to print the full pathname to the console.

You'll be asked to enter the password you created to encrypt your keystore(s) in the *Generate Keys* section of the Launchpad process. Don't worry, this is entirely normal. Your validator client needs both your keystore(s) and the password encrypting it to import your [keys](https://blog.ethereum.org/2020/05/21/keys/) (since it needs to decrypt the keystore in order to be able to use it to sign on your behalf).


### 4. Connect to Pyrmont

```
./run-pyrmont-beacon-node.sh
```

You should see that the beacon node has launched with your validator attached:

```
WRN 2020-08-03 16:24:17.950+02:00 Validator not in registry (yet?)           topics="beacval" tid=11677993 file=validator_duties.nim:53 pubkey=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validator attached                   tid=11677993 file=validator_pool.nim:21 pubkey=a9c4df36 validator=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validators attached                  topics="beacval" tid=11677993 file=validator_duties.nim:61 count=1
INF 2020-08-03 16:24:17.958+02:00 Starting beacon node                       topics="beacnde" tid=11677993 file=nimbus_beacon_node.nim:875 version="0.5.0 (31b33907)" nim="Nim Compiler Version 1.2.6 [MacOSX: amd64] (bf320ed1)" timeSinceFinalization=81350 head=ebe49843:0 finalizedHead=ebe49843:0 SLOTS_PER_EPOCH=32 SECONDS_PER_SLOT=12 SPEC_VERSION=0.12.2 dataDir=build/data/shared_pyrmont_0 pcs=start_beacon_node
```

 > **Note:** when you run `./run-pyrmont-beacon-node.sh`, the beacon node launches with an Infura endpoint supplied by us. This endpoint is passed through the `web3-url` option (which takes as input the url of the web3 server from which you'd like to observe the eth1 chain).
>
> Because Infura caps the requests per endpoint per day to 100k, and all Nimbus nodes use the same Infura endpoint by default, it can happen that our Infura endpoint is overloaded (i.e the requests on a given day reach the 100k limit). If this happens, all requests to Infura using the default endpoint will fail, which means your node will stop processing new deposits.
>
> To pass in your own Infura endpoint, you'll need to run:
>```
> make NODE_PARAMS="--web3-url=<YOUR_WEBSOCKET_ENDPOINT>" pyrmont
>```
> Importantly, the endpoint must be a websocket (`wss`) endpoint, not `https`. If you're not familiar with Infura, we recommend reading through our [Infura guide](./infura-guide), first.
>
> P.S. We are well aware that Infura is less than ideal from a decentralisation perspective. As such we are in the process of changing our default to [Geth](https://geth.ethereum.org/docs/install-and-build/installing-geth) (with Infura as a fallback). For some rough notes on how to use Geth with Nimbus, see [here](https://gist.github.com/onqtam/aaf883d46f4dab1311ca9c160df12fe4) (we will be adding more complete instructions very soon).


> **Tip:** to 🎨 on the [graffitwall](https://pyrmont.beaconcha.in/graffitiwall), pass the graffiti parameter like this:
>```
> ./run-pyrmont-beacon-node.sh --graffiti='<YOUR_GRAFFITI>'


### 5. Keep an eye on your validator

If you deposited after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided (August 2nd 1300 UTC), your validators will have been put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or days.

The best way to keep track of your validator's status is [pyrmont.beaconcha.in](https://pyrmont.beaconcha.in) (click on the orange magnifying glass at the very top and paste in its public key).

You can even [create an account](https://pyrmont.beaconcha.in/register) to add alerts and keep track of your validator's [performance](https://pyrmont.beaconcha.in/dashboard).

To keep track of your syncing progress, have a look at the output at the very bottom of the terminal window in which your validator is running. You should see something like:

```
peers: 35 ❯ finalized: ada7228a:8765 ❯ head: b2fe11cd:8767:2 ❯ time: 9900:7 (316807) ❯ sync: wPwwwwwDwwDPwPPPwwww:7:4.0627 (280512)
```

Where:
- `peers` tells you how many peers you're currently connected to (in the above case, 35 peers)
- `finalized` tells you the most recent finalized epoch you've synced to so far (the 8765th epoch)
- `head` tells you the most recent slot you've synced to so far (the 2nd slot of the 8767th epoch)
- `time` tells you the current time since Genesis (the 7th slot of the 9900th epoch -- or equivalently, the 316,807th slot)
- `sync` tells you how fast you're syncing (4.0627 blocks per second), how many blocks you've synced so far (280,512), along with information about 20 sync workers linked to the 20 most performant peers you are currently connected to (represented by a string of letters and a number).

To dig into `sync` a little:
```
sync: <sync worker map>:<number of active workers>:<current syncing speed in blocks/second>
```

The string of letters -- what we call the `sync worker map` (in the above case represented by `wPwwwwwDwwDPwPPPwwww`) represents the status of the sync workers mentioned above, where:

```
    s - sleeping (idle),
    w - waiting for a peer from PeerPool,
    R - requesting blocks from peer
    D - downloading blocks from peer
    P - processing/verifying blocks
    U - updating peer's status information
```

The number following it (in the above case represented by `7`) represents the number of workers that are currently active (i.e not sleeping or waiting for a peer).


### 6. Keep your validator updated

Finally, makes sure you stay on the lookout for any critical updates to Nimbus. This best way to do so is through the **announcements** channel on our [discord](https://discord.com/invite/XRxWahP).

Check [Keep Nimbus updated](./keep-updated.md) for instructions on how to update your node to a new version.

Looking forward to seeing you on Pyrmont! 💛

## Key management

Keys are stored in the `build/data/shared_pyrmont_0/` folder, under `secrets` and `validators` - make sure you keep these folders backed up.

The `secrets` folder contains the common secret that gives you access to all your validator keys.

The `validators` folder contains your keystores (encrypted keys). Keystores are used by validators as a method for exchanging keys. For more on keys and keystores, see [here](https://blog.ethereum.org/2020/05/21/keys/).

>**Note:** The Nimbus client will only ever import your signing key -- in any case, if you used the deposit launchpad, this is the only key you should have (you can generate the withdrawal key from your mnemonic when you wish to withdraw).

## Metrics

Metrics are not enabled by default - to enable, run with the `--metrics` flag

```
./run-pyrmont-beacon-node.sh --metrics
```

You can then browse the metrics by connecting to:

[http://localhost:8008/metrics](http://localhost:8008/metrics)

Make sure this port is protected as the http server used is not considered secure (it should not be used by untrusted peers).

For instructions on how to spin up a beautiful and useful monitoring dashboard for your validator and beacon node, see [this page](./metrics-pretty-pictures.md).

## Advanced options

### Start multiple nodes

You can start multiple local nodes, in different terminal windows/tabs, by specifying numeric IDs:

```
NODE_ID=0 ./run-pyrmont-beacon-node.sh # the default
NODE_ID=1 ./run-pyrmont-beacon-node.sh
NODE_ID=2 ./run-pyrmont-beacon-node.sh
```

### Attach multiple validators to the same beacon node

Simply [import as many keystores as you wish](./pyrmont.md#3-import-keystores) before running `./run-pyrmont-beacon-node.sh`. Nimbus will automagically find your keys and attach your validators. See [key management](./pyrmont.md#key-management) for more information on where we store your keys.

To give you some context, we (the Nimbus team) are currently running 170 validators per beacon node on our AWS instances.

### Node parameters

You can customise your beacon node's parameters using the `NODE_PARAMS` option:

```
make NODE_PARAMS="--tcp-port=9100 --udp-port=9100" pyrmont
```

>**Note:** the above command has exactly the same effect as `make BASE_PORT=9100 pyrmont`

A complete list of the available parameters can be found [here](https://github.com/status-im/nimbus-eth2/blob/devel/beacon_chain/conf.nim#L92-L210) (use a parameter's `name` field to set it).

### Logs

Log files are saved in `build/data/shared_pyrmont_0/`.


### Makefile

If you are comfortable reading [Makefiles](https://en.wikipedia.org/wiki/Makefile#:~:text=A%20makefile%20is%20a%20file,to%20generate%20a%20target%2Fgoal), you can see the commands that `make pyrmont`  executes under the hood, [here](https://github.com/status-im/nimbus-eth2/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L184-L197).

Some of the provided options (such as `--network=pyrmont`) are essential while others (such as the ones controlling logging, metrics, ports, and the RPC service) are there for convenience.

The Goerli testnet parameters (`$(GOERLI_TESTNETS_PARAMS`), are defined higher up in the Makefile, [here](https://github.com/status-im/nimbus-eth2/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L164-L171).
