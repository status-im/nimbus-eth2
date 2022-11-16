# Optimistic sync

Optimistic sync is the process of syncing an execution and consensus client concurrently, without having the consensus client wait for the execution client. During optimistic sync, the consensus client quickly syncs up to the latest conesensus but delays verifying block execution payloads - it continuously informs the execution client of the latest consensus head, allowing the execution client to perform a snapshot sync directly to the latest state.

Once the execution client has caught up, the consensus and execution clients work in lock-step each validating the block.

Both execution and consensus clients must be fully synced to perform validation duties - while optimistically synced, validator duties (attestation, sync committee and block production work) are skipped.

## Identifying optimistic sync

An optimistically synced node can be identified by examining the "Slot start" log message - when optimistically synced, the `sync` key will have a `/opt` suffix, indicating that it's waiting for the execution client to catch up:

```
INF 2022-10-26 18:57:35.000+02:00 Slot start                                 topics="beacnde" slot=4998286 epoch=156196 sync=synced/opt peers=29 head=f21d399e:4998285 finalized=156194:91e2ebaf delay=467us953ns
```

## Optimistic mode

In "optimistic" mode, Nimbus will start syncing optimistically without an execution client present, as normally required:

```sh
# Start in optimistic mode which allows syncing the beacon chain without an execution client, albeit with reduced security and functionality
./run-mainnet-beacon-node.sh --optimistic
```

!!! warning
    An optimistically synced node is less secure than a fully synced node: it has not validated that the transactions in blocks received from the network are valid - as such, it is not suitable for validation duties (where block contents have not yet been validated by a supermajority of validators) and may be unsuitable for other uses.
