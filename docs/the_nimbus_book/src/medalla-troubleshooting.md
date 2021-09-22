# Troubleshooting Medalla

As it stands, we are continuously making improvements to both stability and memory usage. So please make sure you keep your client up to date! This means restarting your node and updating your software regularly from the `master` branch. If you can't find a solution to your problem here, feel free to hit us up on our [discord](https://discord.com/invite/XRxWahP)!

> **Note:** While the `master` branch of the `nim-beacon-chain` repository is more stable, the latest updates happen in the `devel` branch which is (usually) merged into master every week on Tuesday. If you choose to run Nimbus directly from the `devel` branch, be prepared for instabilities!

To update and restart, run `git pull`, `make update`, followed by `make medalla`:

```
cd nim-beacon-chain
git pull
make update # Update dependencies
make medalla # Restart using same keys as last run
```

If you find that `make update` causes the console to hang for too long, try running `make update V=1` or `make update V=2` instead (these will print a more verbose output to the console which may make it easier to diagnose the problem).

>**Note:** rest assured that when you restart the beacon node, the software will resume from where it left off, using the validator keys you have already imported.

### Starting over
The directory that stores the blockchain data of the testnet is `build/data/shared_medalla_0` (if you're connecting to another testnet, replace `medalla` with that testnet's name). Delete this folder to start over (for example, if you started building medalla with the wrong private keys).

### Syncing
If you’re experiencing sync problems,  we recommend running `make clean-medalla` to delete the database and restart your sync (make sure you’ve updated to the latest `master` first though).

> **Warning**: `make clean-medalla` will erase all of your syncing progress so far, so it should only be used as a last resort -- if your client gets stuck for a long time (because it's unable to find the right chain and/or stay with the same head value) and a normal restart doesn't improve things.

### Pruning the database
If you're running out of storage, you can [prune](https://blog.ethereum.org/2015/06/26/state-tree-pruning/) the database of unnecessary blocks and states by running:

```
make ncli_db
build/ncli_db pruneDatabase --db=build/data/shared_medalla_0/db --verbose=true
```

This will create `nbc_pruned.sqlite3` files in `build/data/shared_medalla_0/db`, which you can use in place of the orginal `nbc.sqlite3` files. We recommend you hold onto the originals until you've verified that your validator is behaving as expected with the pruned files.

Options:
- `--keepOldStates` (boolean):  Keep pre-finalisation states; defaults to `true`.
- `--verbose` (boolean): Print a more verbose output to the console; defaults to `false`.


### Keeping up with the head of the chain

As it stands, logging seems to be slowing down the client,  and quite a few users are experiencing trouble either catching up or keeping up with the head of the chain. You can use either the `LOG_LEVEL=INFO` or `LOG_LEVEL=NOTICE` options to reduce verbosity and speed up the client (`NOTICE` is even less verbose than `INFO`).

```
make LOG_LEVEL=INFO medalla
```

### Low peer counts

If you're experiencing a low peer count, you may be behind a firewall. Try restarting your client and passing `NODE_PARAMS="--nat:\"extip:$EXT_IP_ADDRESS\""` as an option to `make medalla`, where `$EXT_IP_ADDRESS` is your real IP. For example, if your real IP address is `35.124.65.104`, you'd run:

```
make NODE_PARAMS="--nat:\"extip:35.124.65.104\"" medalla
```

### Resource leaks

If you're experiencing RAM related resource leaks, try restarting your client (**we recommend restarting every 6 hours** until we get to the bottom of this issue). If you have a [local Grafana setup](https://github.com/status-im/nim-beacon-chain#getting-metrics-from-a-local-testnet-client), you can try monitoring the severity of these leaks and playing around with the restart interval.

### Address already in use error

If you're seeing an error that looks like:

```
Error: unhandled exception: (98) Address already in use [TransportOsError]
```

It's probably because you're running multiple validators -- and the default base port `9000` is already in use.

To change the base port, run:

```
make BASE_PORT=9100 medalla
```

(You can replace `9100` with a port of your choosing)

### Mainchain monitor failure

If you're seeing one or more error messages that look like the following:

```
ERR 2020-09-29 14:04:33.313+02:00 Mainchain monitor failure, restarting      tid=8941404 
file=mainchain_monitor.nim:812 err="{\"code\":-32005,
\"data\":{\"rate\":{\"allowed_rps\":1,
\"backoff_seconds\":24,
\"current_rps\":22.5},
\"see\":\"https://infura.io/dashboard\"},
\"message\":\"daily request count exceeded, request rate limited\"}"
```

This means that our Infura endpoint is overloaded (in other words, the requests on a given day have reached the 100k free tier limit). 

You can fix this by passing in your own Infura endpoint.

To do so, run: 

```
make NODE_PARAMS="--web3-url=<YOUR_WEBSOCKET_ENDPOINT>" medalla
```

Importantly, make sure you pass in a websocket (`wss`) endpoint, not `https`. If you're not familiar with Infura, we recommend reading through our [Infura guide](./infura-guide) first.

