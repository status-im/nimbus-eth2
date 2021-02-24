# Attestation Flow

This is a WIP document to explain the attestation flows.

## Validation & Verification flow

Important distinction:
- We distinguish attestation `validation` which is defined in the P2P specs:
  - single: https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
  - aggregated: https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
  A validated attestation or aggregate can be forwarded on gossipsub.
- and we distinguish `verification` which is defined in consensus specs:
  https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#attestations
  An attestation needs to be verified to enter fork choice, or be included in a block.

To be clarified: from the specs it seems like gossip attestation validation is a superset of consensus attestation verification.

### Inputs

Attestations can be received from the following sources:
- Gossipsub
  - Aggregate: `/eth2/{$forkDigest}/beacon_aggregate_and_proof/ssz` stored `topicAggregateAndProofs` field of the beacon node
  - Unaggregated `/eth2/{$forkDigest}/beacon_attestation_{subnetIndex}/ssz`
- Included in blocks received
- the NBC database (within a block)
- a local validator vote
- Devtools: test suite, ncli, fuzzing

The related base types are
- Attestation
- IndexedAttestation

The base types are defined in the Eth2 specs.
On top, Nimbus builds new types to represent the level of trust and validation we have with regards to each BeaconBlock.
Those types allow the Nim compiler to help us ensure proper usage at compile-time and zero runtime cost.

#### TrustedAttestation & TrustedIndexedAttestation

An attestation or indexed_attestation that was verified as per the consensus spec or that was retrieved from the database or any source of trusted blocks is considered trusted. In practice we assume that its signature was already verified.

_TODO Note: it seems like P2P validation is a superset of consensus verification in terms of check and that we might use TrustedAttestation earlier in the attestation flow._

## Attestation processing architecture

How the various modules interact with block is described in a diagram:

![./attestation_flow.png](./attestation_flow.png)

Note: The Eth2Processor as 2 queues for attestations (before and after P2P validation) and 2 queues for aggregates. The diagram highlights that with separated `AsyncQueue[AttestationEntry]` and `AsyncQueue[AggregateEntry]`

### Gossip flow in

### Gossip flow out

### Eth2 RPC in

### Comments

### Sync vs Steady State

#### Bottlenecks during sync

##### Backpressure

##### Latency & Throughput sensitiveness

#### Bottlenecks when synced

##### Backpressure

##### Latency & Throughput sensitiveness
