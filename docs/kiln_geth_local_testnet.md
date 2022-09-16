# How to run Geth

- Clone Geth: `git clone https://github.com/ethereum/go-ethereum.git ~/go-ethereum`
- Build Geth with `make geth`
- Run `scripts/run-catalyst.sh` to run Geth. It listens on port 8551.

# Verify Geth and Nimbus interoperate

- Clone Nimbus
- Run `scripts/run-catalyst.sh`. This depends on the paths set up in the first section. If those are changed, adjust accordingly.
- Run `./env.sh nim c -r scripts/test_merge_vectors.nim`. It should show output akin to:

```
[Suite] Merge test vectors
  [OK] getPayload, newPayload, and forkchoiceUpdated
```

# How to run Nimbus local testnet with Geth

- Check out branch `kiln`
- Run (and keep running) `./scripts/run-catalyst.sh`.
- Run `./scripts/launch_local_testnet.sh --preset minimal --nodes 4 --disable-htop --stop-at-epoch 7 -- --verify-finalization --discv5:no`

This creates a 4-node local testnet with 128 validators.

The Nimbus console output will be similar to
![./nimbus_localhost_run.png](./nimbus_localhost_run.png)
The broken pipe on `tail` is normal, and unrelated to merge aspects of Nimbus.

Meanwhile, Nimbus is interacting with Geth in preparing, getting, and executing payloads:
![./kiln_geth_logs.png](./kiln_geth_logs.png)
