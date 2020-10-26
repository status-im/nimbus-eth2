 # Become a Zinken validator

This page will take you through how to import your key(s) and get your validator(s) ready for [Zinken genesis](https://blog.ethereum.org/2020/09/22/eth2-quick-update-no-17/).

For those of you who are unfamiliar, [Zinken](https://github.com/goerli/medalla/blob/master/zinken/README.md) is a short-lived eth2 testnet that will begin on **Monday, October 12th at 12 UTC** and last for three days or so. Its main objective is to allow us to test the deposit/[genesis](https://hackmd.io/@benjaminion/genesis) flow one more time before mainnet launch.

Although it will mainly be client teams taking part, it's also a chance for you to practice sending a deposit and launching a node under mainnet launch conditions (in order to avoid clogging up the validator queue, we recommend practicing with one, or at most a handful of validators).

## Prerequisites

> ⚠️ If this is your first time playing with Nimbus, please make sure you [install our external dependencies](./install.md) first.

This tutorial assumes basic knowledge of the [command line](https://www.learnenough.com/command-line-tutorial/basics#:~:text=Learn%20Enough%20Command%20Line%20to%20Be%20Dangerous%20is%20an%20introduction,broad%20an%20audience%20as%20possible.).
 
## 1. Make a deposit
 
 The easiest way to get your deposit in is to follow the Launchpad instructions here:
 
[https://zinken.launchpad.ethereum.org/](https://zinken.launchpad.ethereum.org/)
 
 You should notice that there have been considerable improvements to the launchpad process since Medalla.
 
 In particular, the Key Generation section is now much clearer, and you no longer have to install dependencies to get the command line app working. As such, it should now be much easier for non-technical folks to generate their key(s).
 
 ![](https://i.imgur.com/slELPmk.png)
  
 Once you've sent off your transaction, you should see the following screen.
 
 ![](https://i.imgur.com/A4IMlhK.png)
 
 
 Click on `Beaconchain` to open up a window that will allow you to track of your validator's status.
 
 ![](https://i.imgur.com/JHQblna.png)
  
 ## 2. Import your key(s)
 
 To import your `zinken` key(s) into Nimbus:
 
 > **Note:** You can skip steps 1 and 2 below if you've already cloned `nimbus-eth2` and built the beacon node for `medalla`: just make sure you run `git pull && make update` from the `master` branch before continuing with step 3.
 
 
 #### 1. Clone the nim beacon chain repository
 
 ```
 git clone https://github.com/status-im/nimbus-eth2
 cd nimbus-eth2
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
 
 If you look near the top of the logs printed to your console, you should see that your beacon node has started, with your local validator attached:
 
 ```
 INF 2020-10-07 17:04:09.213+02:00 Initializing networking                    topics="networking" tid=11688398 file=eth2_network.nim:1335 hostAddress=/ip4/0.0.0.0/tcp/9000 network_public_key=0802122102defb020c8e47dd8f5da89f51ed6c3998aaa0dd59eeb2784e29d47fdbdab69235 announcedAddresses=@[/ip4/195.177.101.93/tcp/9000]
WRN 2020-10-07 17:04:09.215+02:00 Ignoring invalid bootstrap address         tid=11688398 file=eth2_discovery.nim:45 bootstrapAddr= reason="an empty string is not a valid bootstrap node"
NOT 2020-10-07 17:04:09.231+02:00 Local validators attached                  topics="beacval" tid=11688398 file=validator_duties.nim:65 count=0
NOT 2020-10-07 17:04:09.231+02:00 Starting beacon node                       topics="beacnde" tid=11688398 file=beacon_node.nim:923 version="0.5.0 (1dec860b)" nim="Nim Compiler Version 1.2.6 [MacOSX: amd64] (bf320ed1)" timeSinceFinalization=0ns head=0814b036:0 finalizedHead=0814b036:0 SLOTS_PER_EPOCH=32 SECONDS_PER_SLOT=12 SPEC_VERSION=0.12.3 dataDir=build/data/shared_zinken_0
 peers: 0 ❯ finalized: 0814b036:0 ❯ head: 0814b036:0:0 ❯ time: 387:2 (12386) INF 2020-10-07 17:04:09.232+02:00 Starting discovery node                    topics="discv5" tid=11688398 file=protocol.nim:799 node=Node[195.177.101.93:9000] uri=enr:-LK4QCje1Tb8tPIjuIWcAjVRprALNr-fGSmX0ijk2nt4-BgTRSG_q2oekHW9IxbdRi-bcT9RsppI7JtjIxjkm-dG9ZwBh2F0dG5ldHOI__________-EZXRoMpCEe0P1AAAAA___________gmlkgnY0gmlwhMCoC1OJc2VjcDI1NmsxoQLe-wIMjkfdj12on1HtbDmYqqDdWe6yeE4p1H_b2raSNYN0Y3CCIyiDdWRwgiMo bindAddress=0.0.0.0:9000 
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
 
 If you deposit after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided (October 8th, 12pm UTC), your validators will be put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or a day or so.
 
 The best way to keep track of your validator's status is [zinken.beaconcha.in](https:/zinken.beaconcha.in) (click on the orange magnifying glass at the very top and paste in your validator's public key).
 
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
 
 A complete list of the available parameters can be found [here](https://github.com/status-im/nimbus-eth2/blob/devel/beacon_chain/conf.nim#L92-L210) (use a parameter's `name` field to set it).
 
 ### Logs
 
 Log files are saved in `build/data/shared_zinken_0/`.
 
 
 ### Makefile
 
 If you are comfortable reading [Makefiles](https://en.wikipedia.org/wiki/Makefile#:~:text=A%20makefile%20is%20a%20file,to%20generate%20a%20target%2Fgoal), you can see the commands that `make zinken`  executes under the hood, [here](https://github.com/status-im/nimbus-eth2/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L184-L197).
 
 Some of the provided options (such as `--network`) are essential while others (such as the ones controlling logging, metrics, ports, and the RPC service) are optional and included for the sake convenience.
 
 The Goerli testnet parameters (`$(GOERLI_TESTNETS_PARAMS`), are defined higher up in the Makefile, [here](https://github.com/status-im/nimbus-eth2/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L164-L171).
 
 ## Useful Resources
 
 - [ethstaker discord](https://discord.com/invite/e84CFep): great place for tips and discussions
 
 - [Validator launchpad](https://zinken.launchpad.ethereum.org): to send Zinken deposits 
 
 - [Beacon chain explorer](https://zinken.beaconcha.in/) : to monitor testnet health 
 
 - [Nimbus discord](https://discord.com/invite/XRxWahP) : best place to ask questions and to stay up-to-date with critical updates
