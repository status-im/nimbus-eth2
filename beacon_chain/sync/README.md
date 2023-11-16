# Block syncing

This folder holds all modules related to block syncing

Block syncing uses ETH2 RPC protocol.

Reference diagram

![Block flow](../../docs/block_flow.png)

## Eth2 RPC in

Blocks are requested during sync by the SyncManager.

Blocks are received by batch:
- `syncStep(SyncManager, index, peer)`
- in case of success:
  - `push(SyncQueue, SyncRequest, seq[SignedBeaconBlock]) is called to handle a successful sync step.
    It calls `validate(SyncQueue, SignedBeaconBlock)` on each block retrieved one-by-one
  - `validate` only enqueues the block in the SharedBlockQueue `AsyncQueue[BlockEntry]` but does no extra validation only the GossipSub case
- in case of failure:
  - `push(SyncQueue, SyncRequest)` is called to reschedule the sync request.

Every second when sync is not in progress, the beacon node will ask the RequestManager to download all missing blocks currently in quarantine.
- via `handleMissingBlocks`
- which calls `fetchAncestorBlocks`
- which asynchronously enqueue the request in the SharedBlockQueue `AsyncQueue[BlockEntry]`.

The RequestManager runs an event loop:
- that calls `fetchAncestorBlocksFromNetwork`
- which RPC calls peers with `beaconBlocksByRoot`
- and calls `validate(RequestManager, SignedBeaconBlock)` on each block retrieved one-by-one
- `validate` only enqueues the block in the `AsyncQueue[BlockEntry]` but does no extra validation only the GossipSub case

## Weak subjectivity sync

Not implemented!

## Comments

The `validate` procedure name for `SyncManager` and `RequestManager`
as no P2P validation actually occurs.

## Sync vs Steady State

During sync:
- The RequestManager is deactivated
- The syncManager is working full speed ahead
- Gossip is deactivated

## Bottlenecks during sync

During sync:
- The bottleneck is clearing the SharedBlockQueue `AsyncQueue[BlockEntry]` via `storeBlock`
  which requires full verification (state transition + cryptography)

## Backpressure

The SyncManager handles backpressure by ensuring that
`current_queue_slot <= request.slot <= current_queue_slot + sq.queueSize * sq.chunkSize`.
- queueSize is -1, unbounded, by default according to comment but all init paths uses 1 (?)
- chunkSize is SLOTS_PER_EPOCH = 32

However the shared `AsyncQueue[BlockEntry]` itself is unbounded.
Concretely:
- The shared `AsyncQueue[BlockEntry]` is bounded for sync
- The shared `AsyncQueue[BlockEntry]` is unbounded for validated gossip blocks

RequestManager and Gossip are deactivated during sync and so do not contribute to pressure.
