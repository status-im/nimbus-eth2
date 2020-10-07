# Supplying your own Infura endpoint

In a nutshell, Infura is a hosted ethereum node cluster that lets you make requests to the eth1 blockchain without requiring you to set up your own eth1 node.

While we do support Infura to process incoming validator deposits, we recommend running your own eth1 node to avoid relying on a third-party-service.

> **Note:** Nimbus currently supports remote Infura nodes and [local Geth archive nodes](https://gist.github.com/onqtam/aaf883d46f4dab1311ca9c160df12fe4). However we are working on relaxing that assumption (an archive node certainly won't be required for mainnet). In the future, we plan on having our own eth1 client -- [Nimbus 1](https://github.com/status-im/nimbus) -- be the recommended default.

## How it works

When you join an eth2 testnet by running `make zinken` or `make medalla`, the beacon node actually launches with an Infura endpoint supplied by us. 

This endpoint is passed through the `web3-url` option (which takes as input the url of the web3 server from which you'd like to observe the eth1 chain).

If you look at the initial logs you should see something similar to the following:


```
DBG 2020-09-29 12:15:41.969+02:00 Launching beacon node
topics="beacnde" tid=8941404 file=beacon_node.nim:1190 version="0.5.0 (78ceeed8)" bls_backend=BLST 
cmdParams="@[
\"--network=zinken\",
\"--log-level=DEBUG\",
\"--log-file=build/data/shared_zinken_0/nbc_bn_20200929121541.log\",
\"--data-dir=build/data/shared_zinken_0\",
\"--web3-url=wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a\",
\"--tcp-port=9000\",
\"--udp-port=9000\",
\"--metrics\",
\"--metrics-port=8008\",
\"--rpc\",
\"--rpc-port=9190\"
]"
...
```

This allows us to deduce that the default endpoint is given by: 

```
--web3-url=wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a\"
```

## Potential problems

Because Infura caps the requests per endpoint per day to 100k, and all Nimbus nodes use the same Infura endpoint by default, it can happen that our Infura endpoint is overloaded (i.e the requests on a given day reach the 100k limit). If this happens, all requests to Infura using the default endpoint will fail, which means your node will stop processing new deposits.

To know if our endpoint has reached its limit for the day, keep your eye out for error messages that look like the following:

```
ERR 2020-09-29 14:04:33.313+02:00 Mainchain monitor failure, restarting      tid=8941404 
file=mainchain_monitor.nim:812 err="{\"code\":-32005,
\"data\":{\"rate\":{\"allowed_rps\":1,
\"backoff_seconds\":24,
\"current_rps\":22.5},
\"see\":\"https://infura.io/dashboard\"},
\"message\":\"daily request count exceeded, request rate limited\"}"
```

To get around this problem, we recommend launching the beacon node with your own endpoint.

## Supplying your own endpoint



> **Note:** In a previous version of the software it wasn't possible to manually override the web3 endpoint when running `make zinken` or `make medalla`. For the instructions below to work, make sure you've updated to the latest version of the software (run `git pull && make update` from the `master` branch of the `nim-beacon-chain` repository).

### 1. Visit Infura.io

Go to:

[https://infura.io/](https://infura.io/) 

and click on `Get Started For Free`
 
![](https://i.imgur.com/BtStgup.png)

### 2. Sign up

Enter your email address and create a password

![](https://i.imgur.com/al1OsdR.png)

### 3. Verify email address
You should have received an email from Infura in your inbox. Open up it up and click on `Confirm Email Address`

![](https://i.imgur.com/EAD8ZhV.png)

### 4. Go to dashboard
This will take you to your Infura dashboard (https://infura.io/dashboard/)

![](https://i.imgur.com/LuNcoYr.png)

### 5. Create your first project

Click on the first option (`create your first project`) under `Let's Get Started`

![](https://i.imgur.com/wBAGhcs.png)

Choose a name for your project

![](https://i.imgur.com/yr5vnSo.png)

You'll be directed to the settings page of your newly created project

![](https://i.imgur.com/kx3R8XS.png)

### 6. View Görli endpoints

In the `KEYS` section, click on the dropdown menu to the right of `ENDPOINTS`, and select `GÖRLI`

![](https://i.imgur.com/D9186kv.png)

### 7. Copy the websocket endpoint

Copy the address that starts with `wss://`

![](https://i.imgur.com/fZ6Bcjy.png)

> ⚠️ **Warning:** make sure you've copied the endpoint that starts with`wss` (websocket), and not the `https` endpoint.


### 8. Run the beacon node

Run the beacon node on your favourite testnet, pasting in your websocket endpoint as the input to the `web3-url` option.

```
make NODE_PARAMS="--web3-url=wss://goerli.infura.io/ws/v3/83b9d67f81ca401b8f9651441b43f29e"
<TESTNET_NAME>
```
> Remember to replace <TESTNET_NAME> with either `medalla` or `zinken`.

### 9. Check stats

Visit your project's stats page to see a summary of your eth1 related activity and method calls 

![](https://i.imgur.com/MZVTHHV.png)

That's all there is to it :)
