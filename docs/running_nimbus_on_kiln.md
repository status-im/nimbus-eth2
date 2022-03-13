With reference to https://notes.ethereum.org/@launchpad/kiln

# Nimbus

Pre-requisites: `git`, `make`, `gcc`.

Clone the merge testnet configurations
```
git clone https://github.com/eth-clients/merge-testnets/
```

Clone and build from source (use branch `kiln-dev-auth`)
```
git clone --branch=kiln-dev-auth https://github.com/status-im/nimbus-eth2.git
cd nimbus-eth2
make update OVERRIDE=1
make nimbus_beacon_node
cd ..
```

Start the client
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

Because this uses WebSocket, it's necessary to adjust the execution layer client examples slightly, e.g., for Geth:
```
./go-ethereum/build/bin/geth --datadir "geth-datadir" --ws --ws.api="engine,eth,web3,net,debug" --networkid=1337802 --syncmode=full --authrpc.jwtsecret=/tmp/jwtsecret --bootnodes "enode://c354db99124f0faf677ff0e75c3cbbd568b2febc186af664e0c51ac435609badedc67a18a63adb64dacc1780a28dcefebfc29b83fd1a3f4aa3c0eb161364cf94@164.92.130.5:30303" console
```
Nethermind already is configured to listen on WebSockets on port 8551 using this guide, so no modification is necessary.
