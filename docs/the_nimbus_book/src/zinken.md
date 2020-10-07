 # Become a Zinken validator


This page will take you through how to import your key(s) and get your validator(s) ready for [Zinken genesis](https://blog.ethereum.org/2020/09/22/eth2-quick-update-no-17/).

For those of you who are unfamiliar, [Zinken](https://github.com/goerli/medalla/blob/master/zinken/README.md) is a short-lived eth2 testnet that will begin on tuesday and last for three days or so. Its main objective is to allow us to test the deposit/[genesis](https://hackmd.io/@benjaminion/genesis) flow one more time before mainnet launch.

Although it will mainly be client teams taking part, it's also a chance for you to practice sending a deposit and launching a node under mainnet launch conditions (in order to avoid clogging up the validator queue, we recommend practicing with one, or at most a handful of validators).

## Prerequisites

> ⚠️ If this is your first time playing with Nimbus, please make sure you [install our external dependencies](./install.md) first.

This tutorial assumes basic knowledge of the [command line](https://www.learnenough.com/command-line-tutorial/basics#:~:text=Learn%20Enough%20Command%20Line%20to%20Be%20Dangerous%20is%20an%20introduction,broad%20an%20audience%20as%20possible.).
 
 ## 1. Make a deposit
 
 The easiest way to get your deposit in is to follow the Launchpad instructions here:
 
[https://zinken.launchpad.ethereum.org/](https://zinken.launchpad.ethereum.org/)
 
 You should notice that there have been considerable improvements to the launchpad process since Medalla.
 
 In particular, the Key Generation section is now much clearer, and you no longer have to install dependencies to get the command line app working. As such, it should now be much easier for non-technical folks to generate their key(s).
 
 ![](https://i.imgur.com/SYHgtK2.png)
 
 
 Once you've sent off your transaction, you should see the following screen.
 
 ![](https://i.imgur.com/A4IMlhK.png)
 
 
 Click on `Beaconchain` to open up a window that will allow you to track of your validator's status.
 
 ![](https://i.imgur.com/JHQblna.png)
  
 ## 2. Import your key(s)
 
 To import your `zinken` key(s) into Nimbus:
 
 > **Note:** You can skip steps 1 and 2 if you've already cloned `nim-beacon-chain` and built the beacon node for `medalla`: just make sure you run `git pull && make update` from the `master` branch before continuing with step 3.
 
 
 #### 1. Clone the nim beacon chain repository
 
 ```
 git clone https://github.com/status-im/nim-beacon-chain
 cd nim-beacon-chain
 ```
 
 #### 2. Build the beacon node
 ```
 make beacon_node
 ```
 
 *Patience... this may take a few minutes.*
 
 #### 3. Import keystore(s)
 
 ```
 build/beacon_node deposits import  --data-dir=build/data/shared_zinken_0 <YOUR VALIDATOR KEYS DIRECTORY>
 ```
 
 Replacing `<YOUR VALIDATOR KEYS DIRECTORY>` with the full pathname of the `validator_keys` directory that was created when you generated your keys using the [Zinken Launchpad](https://zinken.launchpad.ethereum.org/) [command line app](https://github.com/ethereum/eth2.0-deposit-cli/releases/).
 
 > **Tip:** run `pwd` in your `validator_keys` directory to print the full pathname to the console.
 
 You'll be asked to enter the password you created to encrypt your keystore(s).
 
 Don't worry, this is entirely normal. Your validator client needs both your signing keystore(s) and the password encrypting it to import your [key](https://blog.ethereum.org/2020/05/21/keys/) (since it needs to decrypt the keystore in order to be able to use it to sign on your behalf).
 
 ## 3. Connect to Zinken
 
 To build Nimbus and its dependencies, and connect to Zinken, run:
 
 ```
 make zinken
 ```
 
 You should see that your beacon node has launched, and that you are processing eth1 blocks (using [infura](https://infura.io/)) and obtaining information about other depositers (`deposit log events`) in the run-up to genesis:
 
 ```
 DBG 2020-09-27 17:33:28.500+02:00 Launching beacon node                      topics="beacnde" tid=8490483 file=beacon_node.nim:1190 version="0.5.0 (6cf7e837)" bls_backend=BLST cmdParams="@[\"--network=zinken\", \"--log-level=DEBUG\", \"--log-file=build/data/shared_zinken_0/nbc_bn_20200927173328.log\", \"--data-dir=build/data/shared_zinken_0\", \"--web3-url=wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a\", \"--tcp-port=9000\", \"--udp-port=9000\", \"--metrics\", \"--metrics-port=8008\", \"--rpc\", \"--rpc-port=9190\"]" config="(logLevel: \"DEBUG\", logFile: Some(build/data/shared_zinken_0/nbc_bn_20200927173328.log), eth2Network: Some(\"zinken\"), dataDir: build/data/shared_zinken_0, validatorsDirFlag: None[InputDir], secretsDirFlag: None[InputDir], walletsDirFlag: None[InputDir], web3Url: \"wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a\", depositContractAddress: Some(0x48b597f4b53c21b48ad95c7256b49d1779bd5890), depositContractDeployedAt: Some(\"3384340\"), nonInteractive: false, cmd: noCommand, bootstrapNodes: @[\"# teku (@rolfyone)\", \"enr:-KG4QA-EcFfXQsL2dcneG8vp8HTWLrpwHQ5HhfyIytfpeKOISzROy2kYSsf_v-BZKnIx5XHDjqJ-ttz0hoz6qJA7tasEhGV0aDKQxKgkDQAAAAL__________4JpZIJ2NIJpcIQDFt-UiXNlY3AyNTZrMaECkR4C5DVO_9rB48eHTY4kdyOHsguTEDlvb7Ce0_mvghSDdGNwgiMog3VkcIIjKA\", \"\"], bootstrapNodesFile: , libp2pAddress: 0.0.0.0, tcpPort: 9000, udpPort: 9000, maxPeers: 79, nat: \"any\", validators: ..., stateSnapshot: None[InputFile], stateSnapshotContents: ..., runtimePreset: (GENESIS_FORK_VERSION: 00000002, GENESIS_DELAY: 172800, MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 1024, MIN_GENESIS_TIME: 1601380800, ETH1_FOLLOW_DISTANCE: 1024), nodeName: \"\", graffiti: None[GraffitiBytes], verifyFinalization: false, stopAtEpoch: 0, metricsEnabled: true, metricsAddress: 127.0.0.1, metricsPort: 8008, statusBarEnabled: true, statusBarContents: \"peers: $connected_peers;finalized: $finalized_root:$finalized_epoch;head: $head_root:$head_epoch:$head_epoch_slot;time: $epoch:$epoch_slot ($slot);sync: $sync_status|\", rpcEnabled: true, rpcPort: 9190, rpcAddress: 127.0.0.1, inProcessValidators: true, discv5Enabled: true, dumpEnabled: false)"
 INF 2020-09-27 17:33:31.018+02:00 Starting Eth1 deposit contract monitoring  tid=8490483 file=mainchain_monitor.nim:758 contract=0x48b597f4b53c21b48ad95c7256b49d1779bd5890 url=web3(wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a)
 INF 2020-09-27 17:33:31.018+02:00 Waiting for new Eth1 block headers         tid=8490483 file=mainchain_monitor.nim:415
 INF 2020-09-27 17:33:46.213+02:00 Obtaining deposit log events               tid=8490483 file=mainchain_monitor.nim:376 fromBlock=3384341 toBlock=3476604
 INF 2020-09-27 17:33:56.912+02:00 Eth1 block processed                       tid=8490483 file=mainchain_monitor.nim:717 block=3423176:0ac7969b totalDeposits=1
 ```
 
 > **Note:** when you run `make zinken`, the beacon node launches with an Infura endpoint supplied by us. This endpoint is passed through the `web3-url` option (which takes as input the url of the web3 server from which you'd like to observe the eth1 chain). 
> 
> Because Infura caps the requests per endpoint per day to 100k, and all Nimbus nodes use the same Infura endpoint by default, it can happen that our Infura endpoint is overloaded (i.e the requests on a given day reach the 100k limit). If this happens, all requests to Infura using the default endpoint will fail, which means your node will stop processing new deposits.
>
> To pass in your own Infura endpoint, you'll need to run:
>```
> make NODE_PARAMS="--web3-url=<YOUR_WEBSOCKET_ENDPOINT>" medalla
>```
> Importantly, the endpoint must be a websocket (`wss`) endpoint, not `https`. If you're not familiar with Infura, we recommend reading through our [Infura guide](./infura-guide), first.
>
> P.S. We are well aware that Infura is less than ideal from a decentralisation perspective. As such we are in the process of changing our default to [Geth](https://geth.ethereum.org/docs/install-and-build/installing-geth) (with Infura as a fallback). For some rough notes on how to use Geth with Nimbus, see [here](https://gist.github.com/onqtam/aaf883d46f4dab1311ca9c160df12fe4) (we will be adding more complete instructions very soon).
 
 
 ## 4. Keep an eye on your validator
 
 If you deposited after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided (September 27th 1400 UTC), your validators will have been put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or a day or so.
 
 The best way to keep track of your validator's status is [zinken.beaconcha.in](https://medalla.beaconcha.in) (click on the orange magnifying glass at the very top and paste in your validator's public key).
 
 You can even [create an account](https://zinken.beaconcha.in/register) to add alerts and keep track of your validator's [performance](https://zinken.beaconcha.in/dashboard).
 
 
 Finally, makes sure you stay on the lookout for any critical updates to Nimbus. This best way to do so is through the **announcements** channel on our [discord](https://discord.com/invite/XRxWahP).
 
 To update to the latest version, disconnect from `zinken` and run:
 
 ```
 git pull && make update
 ```
 
 Once the update is complete, run `make zinken` again to reconnect to the network.
 
 Looking forward to seeing you on Zinken! 💛
 

 ----------
 
##  Key management
 
 Keys are stored in the `build/data/shared_zinken_0/` folder, under `secrets` and `validators` - make sure you keep these folders backed up.
 
 The `secrets` folder contains the common secret that gives you access to all your validator keys.
 
 The `validators` folder contains your signing keystore(s) (encrypted keys). Keystores are used by validators as a method for exchanging keys. For more on keys and keystores, see [here](https://blog.ethereum.org/2020/05/21/keys/).
 
 >**Note:** The Nimbus client will only ever import your signing key -- in any case, if you used the deposit launchpad, this is the only key you should have (thanks to the way these keys are derived, you can generate the withdrawal key from your mnemonic whenever you wish to withdraw).
 
 ## Metrics
 
 Metrics are not included in the binary by default - to enable them, use the following options when starting the client:
 
 ```
 make NIMFLAGS="-d:insecure" zinken
 ```
 
 You can then browse the metrics by connecting to:
 
 [http://localhost:8008/metrics](http://localhost:8008/metrics)
 
 Make sure this port is protected as the http server used is not considered secure (it should not be used by untrusted peers).
 
 For instructions on how to spin up a beautiful and useful monitoring dashboard for your validator and beacon node, see [this page](./metrics-pretty-pictures.md) (note you'll need to replace all mention of `medalla` with `zinken`).
 
 ## Advanced options
 
 N.B. All the options you're used to running with `medalla` should work as expected with `zinken`.
 
 
 ### Change the TCP and UDP ports
 
 To change the TCP and UDP ports from their default value of 9000 to 9100, say, run:
 
 ```
 make BASE_PORT=9100 zinken
 ```
 
 You may need to do this if you are running another client.
 
 
 
 ### Node parameters
 
 You can customise your beacon node's parameters using the `NODE_PARAMS` option:
 
 ```
 make NODE_PARAMS="--tcp-port=9100 --udp-port=9100" zinken
 ```
 
 >**Note:** the above command has exactly the same effect as `make BASE_PORT=9100 zinken`
 
 A complete list of the available parameters can be found [here](https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/conf.nim#L92-L210) (use a parameter's `name` field to set it).
 
 ### Logs
 
 Log files are saved in `build/data/shared_zinken_0/`.
 
 
 ### Makefile
 
 If you are comfortable reading [Makefiles](https://en.wikipedia.org/wiki/Makefile#:~:text=A%20makefile%20is%20a%20file,to%20generate%20a%20target%2Fgoal), you can see the commands that `make zinken`  executes under the hood, [here](https://github.com/status-im/nim-beacon-chain/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L184-L197).
 
 Some of the provided options (such as `--network`) are essential while others (such as the ones controlling logging, metrics, ports, and the RPC service) are optional and included for the sake convenience.
 
 The Goerli testnet parameters (`$(GOERLI_TESTNETS_PARAMS`), are defined higher up in the Makefile, [here](https://github.com/status-im/nim-beacon-chain/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L164-L171).
 
 ## Useful Resources
 
 - [ethstaker discord](https://discord.com/invite/e84CFep): great place for tips and discussions
 
 - [Validator launchpad](https://zinken.launchpad.ethereum.org): to send Zinken deposits 
 
 - [Beacon chain explorer](https://zinken.beaconcha.in/) : to monitor testnet health 
 
 - [Nimbus discord](https://discord.com/invite/XRxWahP) : best place to ask questions and to stay up-to-date with critical updates
