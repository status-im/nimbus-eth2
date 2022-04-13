# Run Kiln 

Kiln is the latest long-running  merge testnet (the previous one was known as Kintsugi).

Kiln is the perfect opportunity to verify your setup works as expected through the proof-of-stake transition and in a post-merge context. If you come across any issues, please [report them here](https://github.com/eth-clients/merge-testnets/).

> **N.B.** Post merge, Node runners will need to run both a consensus and execution layer client.

## 1. Preparation

#### 1.1 Download configs

To download the merge testnet configurations, run:

```
git clone https://github.com/eth-clients/merge-testnets.git
cd merge-testnets/kiln 
```

#### 1.2 Generate secret
To generate and write the JWT secret to a file, run:
```
openssl rand -hex 32 | tr -d "\n" > "/tmp/jwtsecret"
```

You will need to pass this file to both the Execution Client and the Consensus Client (the JWT secret is an authentication mechanism between CL/EL).


## 2. Execution client

> We recommend running either Nethermind or Geth with Nimbus

### Nethermind

#### 2.1N Clone and build
Clone and build the `kiln` branch of Nethermind:

```
git clone --recursive -b kiln https://github.com/NethermindEth/nethermind.git
cd nethermind/src/Nethermind
dotnet build Nethermind.sln -c Release
```

#### 2.2N Start the client
Start Nethermind:

```
cd kiln/nethermind/src/Nethermind/Nethermind.Runner
dotnet run -c Release -- --config kiln --JsonRpc.Host=0.0.0.0 --JsonRpc.JwtSecretFile=/tmp/jwtsecret
```

### Geth

#### 2.1G Clone and build

Clone and build the `merge-kiln-v2` branch from Marius' fork of Geth:

```
git clone -b merge-kiln-v2 https://github.com/MariusVanDerWijden/go-ethereum.git
cd go-ethereum 
make geth
cd ..
```

#### 2.2G Start the client

Start Geth:

```
cd kiln
./go-ethereum/build/bin/geth init genesis.json  --datadir "geth-datadir"
./go-ethereum/build/bin/geth --datadir "geth-datadir" --http --http.api="engine,eth,web3,net,debug" --ws --ws.api="engine,eth,web3,net,debug" --http.corsdomain "*" --networkid=1337802 --syncmode=full --authrpc.jwtsecret=/tmp/jwtsecret --bootnodes "enode://c354db99124f0faf677ff0e75c3cbbd568b2febc186af664e0c51ac435609badedc67a18a63adb64dacc1780a28dcefebfc29b83fd1a3f4aa3c0eb161364cf94@164.92.130.5:30303" console

```

## 3. Nimbus

#### 3.1 Clone and build Nimbus from source

Clone and build Nimbus from source from the `kiln-dev-auth` branch:

```
git clone --branch=kiln-dev-auth https://github.com/status-im/nimbus-eth2.git
cd nimbus-eth2
make update OVERRIDE=1
make nimbus_beacon_node
cd ..
```

#### 3.2 Start the client

Start Nimbus:

```
nimbus-eth2/build/nimbus_beacon_node \
    --network=merge-testnets/kiln \
    --web3-url=ws://127.0.0.1:8551 \
    --rest \
    --metrics \
    --log-level=DEBUG \
    --terminal-total-difficulty-override=20000000000000 \
    --jwt-secret="/tmp/jwtsecret"
```

## Useful resources

- Kiln [landing page](https://kiln.themerge.dev/): add the network to your browser wallet, view block explorers, request funds from the faucet, and connect to a JSON RPC endpoint.

- Kiln [validator launchpad](https://kiln.launchpad.ethereum.org/en/): make a deposit for your validator.

- [EF launchpad notes](https://notes.ethereum.org/@launchpad/kiln): how to run a node on Kiln

- [Ethereum On Arm Kiln RP4 image](https://ethereum-on-arm-documentation.readthedocs.io/en/latest/kiln/kiln-testnet.html): Run Nimbus on a raspberry pi or using an AWS AMI

<br/>





