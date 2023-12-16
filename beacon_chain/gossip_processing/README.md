# Gossip Processing

This folder holds a collection of modules to:
- validate raw gossip data before
  - rebroadcasting it (potentially aggregated)
  - sending it to one of the consensus object pools

## Validation

Gossip validation is different from consensus verification in particular for blocks.

- Blocks: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#beacon_block
- Attestations (aggregated): https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
- Attestations (unaggregated): https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#attestation-subnets
- Voluntary exits: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/phase0/p2p-interface.md#voluntary_exit
- Proposer slashings: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#proposer_slashing
- Attester slashing: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#attester_slashing

There are multiple consumers of validated consensus objects:
- a `ValidationResult.Accept` output triggers rebroadcasting in libp2p
  - We jump into method `validate(PubSub, Message)` in libp2p/protocols/pubsub/pubsub.nim
  - which was called by `rpcHandler(GossipSub, PubSubPeer, RPCMsg)`
- a `blockValidator` message enqueues the validated object to the processing queue in `block_processor`
  - `blockQueue: AsyncQueue[BlockEntry]` (shared with request_manager and sync_manager)
  - This queue is then regularly processed to be made available to the consensus object pools.
- a `xyzValidator` message adds the validated object to a pool in eth2_processor
  - Attestations (unaggregated and aggregated) get collected into batches.
  - Once a threshold is exceeded or after a timeout, they get validated together using BatchCrypto.

## Security concerns

As the first line of defense in Nimbus, modules must be able to handle bursts of data that may come:
- from malicious nodes trying to DOS us
- from long periods of non-finality, creating lots of forks, attestations
