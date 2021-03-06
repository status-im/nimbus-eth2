# Gossip Processing

This folders hold a collection of modules to:
- validate raw gossip data before
  - rebroadcasting them (potentially aggregated)
  - sending it to one of the consensus object pool

## Validation

Gossip Validation is different from consensus verification in particular for blocks.

- Blocks: https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_block
- Attestations (aggregate): https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
- Attestations (single): https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#attestation-subnets
- Exits: https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#voluntary_exit
- Proposer slashings: https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#proposer_slashing
- Attester slashing: https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#attester_slashing

There are 2 consumers of validated consensus objects:
- a `ValidationResult.Accept` output triggers rebroadcasting in libp2p
  - method `validate(PubSub, message)` in libp2p/protocols/pubsub/pubsub.nim in the
  - which was called by `rpcHandler(GossipSub, PubSubPeer, RPCMsg)`
- a `xyzValidator` message enqueues the validated object in one of the processing queue in eth2_processor
  - `blocksQueue: AsyncQueue[BlockEntry]`, (shared with request_manager and sync_manager)
  - `attestationsQueue: AsyncQueue[AttestationEntry]`
  - `aggregatesQueue: AsyncQueue[AggregateEntry]`

Those queues are then regularly processed to be made available to the consensus object pools.

## Security concerns

As the first line of defense in Nimbus, modules must be able to handle burst of data that may come:
- from malicious nodes trying to DOS us
- from long periods of non-finality, creating lots of forks, attestations, forks
