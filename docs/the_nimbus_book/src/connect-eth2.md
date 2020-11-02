# Connect to eth2

To connect to the Medalla testnet, from the `nimbus-eth2` repository run:

```
make medalla
```

> **Note:** If your beacon node is already running, you'll need to shut it down gracefully (`Ctrl+c`) and re-run the above command.

This will build Nimbus and its dependencies, and connect you to the eth2 network.
You should see that the beacon node has launched with your validator attached:

```
WRN 2020-08-03 16:24:17.950+02:00 Validator not in registry (yet?)           topics="beacval" tid=11677993 file=validator_duties.nim:53 pubKey=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validator attached                   tid=11677993 file=validator_pool.nim:21 pubKey=a9c4df36 validator=a9c4df36
INF 2020-08-03 16:24:17.951+02:00 Local validators attached                  topics="beacval" tid=11677993 file=validator_duties.nim:61 count=1
INF 2020-08-03 16:24:17.958+02:00 Starting beacon node                       topics="beacnde" tid=11677993 file=beacon_node.nim:875 version="0.5.0 (31b33907)" nim="Nim Compiler Version 1.2.6 [MacOSX: amd64] (bf320ed1)" timeSinceFinalization=81350 head=ebe49843:0 finalizedHead=ebe49843:0 SLOTS_PER_EPOCH=32 SECONDS_PER_SLOT=12 SPEC_VERSION=0.12.2 dataDir=build/data/shared_medalla_0 pcs=start_beacon_node
```

 > **Note:** when you run `make medalla`, the beacon node launches with an Infura endpoint supplied by us. This endpoint is passed through the `web3-url` option (which takes as input the url of the web3 server from which you'd like to observe the eth1 chain). 
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
 

> **Tip:** to 🎨 on the [graffitwall](https://medalla.beaconcha.in/graffitiwall), pass the graffiti parameter like this:
>```
>make NODE_PARAMS="--graffiti='<YOUR_GRAFFITI>'" medalla

For a more complete list of the options available, see [here](./advanced.md).
