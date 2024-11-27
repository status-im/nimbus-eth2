# Networking

These folders hold a collection of modules to:
- configure the Eth2 P2P network
- discover, connect, and maintain quality Eth2 peers

Data received is handed over to the `../gossip_processing` modules for validation.

## Security concerns

- Collusion: part of the peer selection must be kept random. This avoids peers bringing all their friends and colluding against a beacon node.
- Denial-of-service: The beacon node must provide ways to handle burst of data that may come:
  - from malicious nodes trying to DOS us
  - from long periods of non-finality, creating lots of forks, attestations, forks
