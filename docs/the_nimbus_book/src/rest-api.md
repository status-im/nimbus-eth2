# REST API

Nimbus supports the [common REST API](https://ethereum.github.io/beacon-APIs/) for runtime communication. To enable it, use the `--rest` option when starting the beacon node, then access the API from http://localhost:5052/. The port and listening address can be further configured through the options `--rest-port` and `--rest-address`.

The API is a REST interface, accessed via HTTP. The API should not, unless protected by additional security layers, be exposed to the public Internet as the API includes multiple endpoints which could open your node to denial-of-service (DoS) attacks through endpoints triggering heavy processing.

The beacon node (BN) maintains the state of the beacon chain by communicating with other beacon nodes in the Ethereum network. Conceptually, it does not maintain keypairs that participate with the beacon chain.

The validator client (VC) is a conceptually separate entity which utilizes private keys to perform validator related tasks, called "duties", on the beacon chain. These duties include the production of beacon blocks and signing of attestations.

> Please note that using a validator client with a Nimbus beacon node requires the node to be launched with the `--subscribe-all-subnets` option. This limitation will be removed in Nimbus 1.6.

The goal of this specification is to promote interoperability between various beacon node implementations.

## Specification
The specification is documented [here](https://ethereum.github.io/beacon-APIs/).

See the Readme [here](https://github.com/ethereum/beacon-apis).

