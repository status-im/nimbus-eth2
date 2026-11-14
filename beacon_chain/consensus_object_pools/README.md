# Consensus object pools

This folder holds the various consensus object pools needed for a blockchain client.

Object in those pools have passed the "gossip validation" filter according
to specs:
- blocks: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#beacon_block
- aggregate attestations: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
- unaggregated attestation: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#attestation-subnets
- voluntary exits: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#voluntary_exit
- Attester slashings: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#attester_slashing
- Proposer slashings: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/phase0/p2p-interface.md#proposer_slashing

After "gossip validation" the consensus objects can be rebroadcasted as they are optimistically good, however for internal processing further verification is needed.
For blocks, this means verifying state transition and all contained cryptographic signatures (instead of just the proposer signature).
For other consensus objects, it is possible that gossip validation is a superset of consensus verification (TODO).

The pools present in this folder are:
- block_pools:
  - block_quarantine: for seemingly valid blocks that cannot be processed yet — orphans (missing parent), sidecarless Fulu blocks (missing data columns), unviable blocks (fork not containing the finalized checkpoint, or failed verification), and missing roots to be fetched by the sync protocol.
  - envelope_quarantine: for execution payload envelopes (Gloas+) whose block is not yet verified — orphans, missing, unviable.
  - column_quarantine: for PeerDAS data column sidecars (Fulu/Gloas) of custody columns, accumulated per block root until enough are available to import the block (Fulu) or the envelope (Gloas); memory-budgeted with disk offload.
  - block_clearance: to verify (state_transition + cryptography) candidate blocks using the DAG's `clearanceState` — `checkHeadBlock`, `addHeadBlockWithParent` (batch signature verification + state transition), `addHeadExecutionPayload`, `addBackfillBlock`.
  - blockchain_dag: an in-memory direct-acyclic graph of fully validated and verified blockchain candidates with the tail being the last finalized epoch. A block in the DAG MUST be in the fork choice and a block in the fork choice MUST be in the DAG (except for orphans following finalization). On finalization non-empty epoch blocks are stored in the beacon_chain_db.
- consensus_manager:
  Bundles the DAG, the attestation pool, the quarantine and the EL manager — the single object through which block processing and sync reach fork choice, head updates and the execution layer (`updateHead`, `updateExecutionHead`, `expectBlock`, `checkExpectedBlock`).
- attestation_pool:
  Handles the attestations received from gossip, aggregates them, and collects them for fork choice and block production.
- payload_attestation_pool:
  Gloas+ PTC payload attestations — deduplicated per (slot, validator), aggregated for block production, recorded in fork choice.
- sync_committee_msg_pool:
  Aggregates sync committee messages and contributions into sync aggregates for block production (not fed to fork choice).
- validator_change_pool:
  Handle voluntary exits and forced exits (attester slashings and proposer slashings) as well as BLS-to-execution changes, for block production; attester slashings also feed fork choice via equivocation processing.
- execution_payload_pool:
  Execution payload bids (Gloas+) with their payload availability status, used for fork choice and proposer preferences.
- inclusion_list_pool:
  Inclusion lists (Heze) and whether they arrived timely.
- light_client_pool:
  Light client finality / optimistic updates for serving light clients.
- column_reconstruction_backfiller:
  Background PeerDAS data-column reconstruction (KZG cell + proof recovery) to extend the contiguous servable slot range, driven by new columns arriving via the block processor.
