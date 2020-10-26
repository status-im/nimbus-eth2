# Advanced options

### Start multiple nodes

You can start multiple local nodes, in different terminal windows/tabs, by specifying numeric IDs:

```
make medalla NODE_ID=0 # the default
make medalla NODE_ID=1
make medalla NODE_ID=2
```

### Attach multiple validators to the same beacon node

Simply [import as many keystores as you wish](./medalla.md#3-import-keystores) before running `make medalla`. Nimbus will automagically find your keys and attach your validators. See [key management](./medalla.md#key-management) for more information on where we store your keys.

To give you some context, we (the Nimbus team) are currently running 170 validators per beacon node on our AWS instances.

### Change the TCP and UDP ports

To change the TCP and UDP ports from their default value of 9000 to 9100, say, run:

```
make BASE_PORT=9100 medalla
```

You may need to do this if you are running another client.

### Node parameters

You can customise your beacon node's parameters using the `NODE_PARAMS` option:

```
make NODE_PARAMS="--tcp-port=9100 --udp-port=9100" medalla
```

>**Note:** the above command has exactly the same effect as `make BASE_PORT=9100 medalla`

A complete list of the available parameters can be found [here](https://github.com/status-im/nimbus-eth2/blob/devel/beacon_chain/conf.nim#L92-L210) (use a parameter's `name` field to set it).

### Logs

Log files are saved in `build/data/shared_medalla_0/`.


### Makefile

If you are comfortable reading [Makefiles](https://en.wikipedia.org/wiki/Makefile#:~:text=A%20makefile%20is%20a%20file,to%20generate%20a%20target%2Fgoal), you can see the commands that `make medalla`  executes under the hood, [here](https://github.com/status-im/nimbus-eth2/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L184-L197).

Some of the provided options (such as `--network=medalla`) are essential while others (such as the ones controlling logging, metrics, ports, and the RPC service) are there for convenience.

The Goerli testnet parameters (`$(GOERLI_TESTNETS_PARAMS`), are defined higher up in the Makefile, [here](https://github.com/status-im/nimbus-eth2/blob/23bec993414df904e9d7ea9d26e65005b981aee0/Makefile#L164-L171).

### Make a deposit directly using Nimbus

```
make medalla-deposit VALIDATORS=2 # default is just 1
```
