# Keymanager API

The standardized [Keymanager API](https://ethereum.github.io/keymanager-APIs/) can be used to add, remove or migrate validators on the fly on a running beacon node.

## Configuration

By default, the Keymanager API is disabled. To enable it, start the beacon node with the `--keymanager` option, then access the API from http://localhost:5052/. All requests must be authorized through the `Authorization: Bearer` scheme with a token matching the contents of a file provided at the start of the node through the `--keymanager-token-file` parameter.

By default, only connections from the same machine are entertained. The port and listening address can be further configured through the options `--keymanager-port` and `--keymanager-address`.

> **Warning:** The Keymanager API port SHOULD be exposed through a secure channel, such as with HTTPs, an SSH tunnel, a VPN, etc.

## Specification

The specification is documented [here](https://ethereum.github.io/keymanager-APIs/).

See the Readme [here](https://github.com/ethereum/keymanager-APIs/).
