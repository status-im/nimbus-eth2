# Keymanager API

The standardized [Keymanager API](https://ethereum.github.io/keymanager-APIs/) can be used to add, remove, or [migrate](./migration.md) validators on the fly while the beacon node is running.

## Configuration

By default, we disable the Keymanager API.
To enable it, start the beacon node with the `--keymanager` option enabled:

```
./run-prater-beacon-node.sh --keymanager
```

Once the node is running, you'll be able to access the API from [http://localhost:5052/](http://localhost:5052/).

### Authorization: Bearer scheme

All requests must be authorized through the `Authorization: Bearer` scheme with a token matching the contents of a file provided at the start of the node through the `--keymanager-token-file` parameter.

### Enabling connections from outside machines

By default, only connections from the same machine are entertained.
If you wish to change this you can configure the port and listening address with the `--keymanager-port` and `--keymanager-address` options respectively.

!!! warning
    The Keymanager API port should only be exposed through a secure channel (e.g. HTTPS, an SSH tunnel, a VPN, etc.)

## Specification

The specification is documented [here](https://ethereum.github.io/keymanager-APIs/).
The  README is also extremely useful and is documented [here](https://github.com/ethereum/keymanager-APIs/).
