# Block Validation Flow

This is a WIP document to explain the block validation flow.
This should be transformed into diagram that explain
the implicit block validation state machine.

## Inputs

Blocks can be received from the following sources:
- Gossipsub
- the NBC database
- a local validator block proposal
- Devtools: test suite, ncli, fuzzing

The related base types are:
- BeaconBlockBody
- BeaconBlock
  - BeaconBlockBody
  - + metadata (slot, blockchain state before/after, proposer)
- BeaconBlockHeader
  - metadata (slot, blockchain state before/after, proposer)
  - merkle hash of the BeaconBlockBody
- SignedBeaconBlock
  - BeaconBlock
  - + BLS signature

The base types are defined in the Eth2 specs.
On top, Nimbus builds new types to represent the level of trust and validation we have with regards to each BeaconBlock.
Those types allow the Nim compiler to help us ensure proper usage at compile-time and zero runtime cost.

### BeaconBlocks

Those are spec-defined types.

On deserialization the SSZ code guarantees that BeaconBlock are correctly max-sized
according to:
- MAX_PROPOSER_SLASHINGS
- MAX_ATTESTER_SLASHINGS
- MAX_ATTESTATIONS
- MAX_DEPOSITS
- MAX_VOLUNTARY_EXITS

### TrustedBeaconBlocks

A block that has been fully checked to be sound
both in regards to the blockchain protocol and its cryptographic signatures is known as a `TrustedBeaconBlock` or `TrustedSignedBeaconBlock`.
This allows skipping expensive signature checks.
Blocks are considered trusted if they come from:
- the NBC database
- produced by a local validator

### SigVerifiedBeaconBlocks

A block with a valid cryptographic signature is considered SigVerified.
This is a weaker guarantee than Trusted as the block might still be invalid according to the state transition function.
Such a block are produced if incoming gossip blocks' signatures are batched together for batch verification **before** being passed to state transition.

### TransitionVerifiedBeaconBlocks

A block that passes the state transition checks and can be successfully applied to the beacon chain is considered `TransitionVerified`.
Such a block can be produced if incoming blocks' signatures are batched together for batch verification **after** successfully passing state transition.
