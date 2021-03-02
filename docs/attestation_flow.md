# Attestation Flow

This is a WIP document to explain the attestation flows.

## Validation & Verification flow

Important distinction:
- We distinguish attestation `validation` which is defined in the P2P specs:
  - single: https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_attestation_subnet_id
  - aggregated: https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
  A validated attestation or aggregate can be forwarded on gossipsub.
- and we distinguish `verification` which is defined in consensus specs:
  https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#attestations
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

Attestatios are listened to via the gossipsub topics
- Aggregate: `/eth2/{$forkDigest}/beacon_aggregate_and_proof/ssz` stored `topicAggregateAndProofs` field of the beacon node
- Unaggregated `/eth2/{$forkDigest}/beacon_attestation_{subnetIndex}/ssz`

They are then
- validated by `validateAttestation()` or `validateAggregate()` in either `attestationValidator()` or `aggregateValidator()`
  according to spec
  - https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#beacon_aggregate_and_proof
  - https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/p2p-interface.md#attestation-subnets
- It seems like P2P validation is a superset of consensus verification as in `process_attestation()`:
  - https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#attestations
- Enqueued in
  - `attestationsQueue: AsyncQueue[AttestationEntry]`
  - `aggregatesQueue: AsyncQueue[AggregateEntry]`
- dropped in case of error

### Gossip flow out

- After validation in `attestationValidator()` or `aggregateValidator()` in the Eth2Processor
- Important: P2P validation is different from verification at the consensus level.
- We jump into libp2p/protocols/pubsub/pubsub.nim in the method `validate(PubSub, message)`
- which was called by `rpcHandler(GossipSub, PubSubPeer, RPCMsg)`

### Eth2 RPC in

There is no RPC for attestations but attestations might be included in synced blocks.
### Comments

### Sync vs Steady State

During sync the only attestation we receive are within synced blocks.
Afterwards attestations come from GossipSub

#### Bottlenecks during sync

During sync, attestations are not a bottleneck, they are a small part of the large block processing.

##### Backpressure

The `attestationsQueue` to store P2P validated attestations has a max size of `TARGET_COMMITTEE_SIZE * MAX_COMMITTEES_PER_SLOT` (128 * 64 = 8192)

The `aggregatesQueue` has a max size of `TARGET_AGGREGATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT` (16 * 64 = 1024)

##### Latency & Throughput sensitiveness

We distinguish an aggregated attestation:
- aggregation is done according to eth2-spec rules, usually implies diffusion of aggregate signature and the aggregate public key is computed on-the-fly.
- and a batched validation (batching done client side), implies aggregation of signatures and public keys are done on-the-fly

During sync attestations are included in blocks and so do not require gossip validation,
they are also aggregated per validators and can be batched with other signatures within a block.

After sync, attestations need to be rebroadcasted fast to:
- maintain the quality of the GossipSub mesh
- not be booted by peers

Attestations need to be validated or aggregated fast to avoid delaying other networking operations, in particular they are bottleneck by cryptography.

The number of attestation to process grows with the number of peers. An aggregated attestation is as cheap to process as a non-aggregated one. Batching is worth it even with only 2 attestations to batch.
