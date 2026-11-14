# Gossip Processing

This folder holds a collection of modules to:
- validate raw gossip data before
  - rebroadcasting it (potentially aggregated)
  - sending it to one of the consensus object pools

## Validation

Gossip validation is different from consensus verification in particular for blocks.

- Blocks: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#beacon_block
- Attestations (aggregated): https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
- Attestations (unaggregated): https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#attestation-subnets
- Voluntary exits: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#voluntary_exit
- Proposer slashings: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#proposer_slashing
- Attester slashing: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#attester_slashing

There are multiple consumers of validated consensus objects:
- a `ValidationResult.Accept` output triggers rebroadcasting in libp2p
  - We jump into method `validate(PubSub, Message)` in libp2p/protocols/pubsub/pubsub.nim
  - which was called by `rpcHandler(GossipSub, PubSubPeer, RPCMsg)`
- a validated block is enqueued to the `BlockProcessor` (in `block_processor`)
  - via `blockProcessor.enqueueBlock` (fire-and-forget, gossip entry point)
  - blocks from sync and API sources call `blockProcessor.addBlock` directly
  - the `BlockProcessor` serializes all stores through a single `storeLock`
    and makes blocks available to the consensus object pools (clearance, DAG,
    fork choice, database)
- a validated attestation / aggregate / sync committee message / contribution /
  payload attestation is added to its pool in `eth2_processor`
  - Signature verification is batched: signature sets are collected into
    batches and once a threshold is exceeded or after a timeout, they get
    validated together using BatchCrypto
- a validated execution payload envelope (Gloas+) is added to the
  `EnvelopeQuarantine` and its block's payload processing is enqueued
- a validated data column sidecar (Fulu/Gloas) is added to the column
  quarantine (KZG proofs checked via BatchCrypto)

## Security concerns

As the first line of defense in Nimbus, modules must be able to handle bursts of data that may come:
- from malicious nodes trying to DOS us
- from long periods of non-finality, creating lots of forks, attestations
