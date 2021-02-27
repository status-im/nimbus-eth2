# NBC Audit 2020

This folder contains the description, tasks and scope of Nimbus audit pre-mainnet launch.

RFP:
- https://our.status.im/nimbus-eth2-0-security-audit-request-for-proposal

The audit was done in 3 phases, related branches are:
- https://github.com/status-im/nimbus-eth2/tree/nbc-audit-2020-0
- https://github.com/status-im/nimbus-eth2/tree/nbc-audit-2020-1
- https://github.com/status-im/nimbus-eth2/tree/nbc-audit-2020-2

The audit involved 3 vendors:
- Consensys Diligence: https://consensys.net/diligence/
- NCC: https://www.nccgroup.com/
- Trail of Bits: https://www.trailofbits.com/

Outline

|                 Module                 |                   Repository                    | Audit round |           Category            |
| -------------------------------------- | ----------------------------------------------- | ----------- | ----------------------------- |
| Wire encryption                        | nim-crypto, nim-libp2p, nim-bearssl             | Round 1     | Network Core Audit            |
| [Ethereum 2 Request/Response protocol](./eth2_spec_core/attestation_processing_and_production.md)   | nimbus-eth2, nim-faststreams, nim-serialization | Round 1     | Network Core Audit            |
| [Discover Protocol (discv5)](./network_core/discovery_protocol_discv5.md)             | nim-eth                                         | Round 1     | Network Core Audit            |
| [SSZ - (De)serialization & tree hashing](./network_core/ssz_serialization_and_tree_hashing.md) | nimbus-eth2                                     | Round 2     | Network Core Audit            |
| [Block/attestation signing](./validator_core/block_attestation_signing.md)              | nimbus-eth2, nim-blscurve                       | Round 2     | Validator Core Audit         |
| [Peer pool management](./eth2_spec_core/peer_pool_management.md)                   | nimbus-eth2                                     | Round 2     | ETH2 Specification Core Audit |
| [Block Synchronization](./eth2_spec_core/block_synchronization.md)                  | nimbus-eth2                                     | Round 2     | ETH2 Specification Core Audit |
| [Fork choice logic](./eth2_spec_core/fork_choice_logic.md)                      | nimbus-eth2                                     | Round 2     | ETH2 Specification Core Audit |
| [Reward processing](./eth2_spec_core/reward_processing.md)                      | nimbus-eth2                                     | Round 2     | ETH2 Specification Core Audit |
| [Eth1 data processing](./eth2_spec_core/eth1_data_processing.md)                  | nimbus-eth2, nim-web3                           | Round 2     | ETH2 Specification Core Audit |
| [Epoch finalisation and justification](./eth2_spec_core/epoch_finalization_and_justification.md)  | nimbus-eth2                                     | Round 2     | ETH2 Specification Core Audit |
| [Signature verification](./eth2_spec_core/signature_verification.md)                 | nimbus-eth2, nim-blscurve                       | Round 2     | ETH2 Specification Core Audit |
| [State transition logic](./eth2_spec_core/state_transition_logic.md)                 | nimbus-eth2                                     | Round 2     | ETH2 Specification Core Audit |
| [Publish/Subscribe protocol (gossipsub)](./network_core/publish_subscribe_gossipsub.md) | nim-libp2p                                      | Round 4     | Network Core Audit            |
| [Command Line Interface (CLI)](./validator_core/command_line_interface_CLI.md)           | nimbus-eth2, nim-confutils                      | Round 3     | Validator Core Audit         |
| [RPC API](./validator_core/rpc_api.md)                                | nimbus-eth2, nim-json-rpc                       | Round 3     | Validator Core Audit         |
| [Accounts management & key storage](./validator_core/account_management_and_key_storage.md)      | nimbus-eth2                                     | Round 3     | Validator Core Audit         |
| [Slash-prevention mechanisms](./validator_core/slash_prevention_mechanisms.md)            | nimbus-eth2                                     | Round 3     | Validator Core Audit         |
| [Attestation processing and production](./eth2_spec_core/attestation_processing_and_production.md) | nimbus-eth2                                     | Round 3     | ETH2 Specification Core Audit |
| [Block processing and production](./eth2_spec_core/block_processing_and_production.md)        | nimbus-eth2                                     | Round 3     | ETH2 Specification Core Audit |
