# Consensus object pools

This folder holds the various consensus object pools needed for a blockchain client.

Object in those pools have passed the "gossip validation" filter according
to specs:
- blocks: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#beacon_block
- aggregate attestations: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
- unaggregated attestation: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
- voluntary exits: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#voluntary_exit
- Attester slashings: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#attester_slashing
- Proposer slashings: https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#proposer_slashing

After "gossip validation" the consensus objects can be rebroadcasted as they are optimistically good, however for internal processing further verification is needed.
For blocks, this means verifying state transition and all contained cryptographic signatures (instead of just the proposer signature).
For other consensus objects, it is possible that gossip validation is a superset of consensus verification (TODO).

The pools presenet in this folder are:
- block_pools:
  - block_quarantine: for seemingly valid blocks that are on a fork unknown to us.
  - block_clearance: to verify (state_transition + cryptography) candidate blocks.
  - blockchain_dag: an in-memory direct-acyclic graph of fully validated and verified blockchain candidates with the tail being the last finalized epoch. A block in the DAG MUST be in the fork choice and a block in the fork choice MUST be in the DAG (except for orphans following finalization). On finalization non-empty epoch blocks are stored in the beacon_chain_db.
- attestation_pool:
  Handles the attestation received from gossip and collect them for fork choice.
- exit_pool:
  Handle voluntary exits and forced exits (attester slashings and proposer slashings)
