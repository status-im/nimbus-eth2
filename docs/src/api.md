
NBC exposes API:s for querying the state of the application at runtime.

:note: Where applicable, this API mimics https://github.com/ethereum/eth2.0-APIs with the exception that JSON-RPC is used instead of http rest - method names, parameters and results are equivalent except for the encoding / access method.

## Introduction

The NBC API is implemented using JSON-RPC 2.0. To query it, you can use a JSON-RPC library in the language of your choice, or a tool like `curl` to access it from the command line. A tool like [jq](https://stedolan.github.io/jq/) is helpful to pretty-print the responses.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"peers","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Before you can access the API, make sure it's enabled using the RPC flag (`beacon_node --rpc`):

```
     --rpc                     Enable the JSON-RPC server.
     --rpc-port                HTTP port for the JSON-RPC service.
     --rpc-address             Listening address of the RPC server.
```

## Beacon Node API

### getBeaconHead

The latest head slot, as chosen by the latest fork choice.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getBeaconHead","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### getChainHead

Show chain head information, including head, justified and finalized checkpoints.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getChainHead","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### getSyncing

### getBeaconBlock

### getBeaconState

### getNetworkPeerId

### getNetworkPeers

### getNetworkEnr

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getNetworkEnr","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

## Valdiator API

## Administrative / Debug API

### getNodeVersion

Show version of the software

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getNodeVersion","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### getSpecPreset

Show spec constants in use.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getSpecPreset","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### peers

Show a list of peers that the beacon node is connected to.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"peers","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```
