# Perform a voluntary exit

> ⚠️  Voluntary exits are **irreversible**. You won't be able to validate again with the same key. And you won't be able to withdraw your stake until the Eth1 and Eth2 merge. *Note that voluntary exits won't be processed if the chain isn't finalising.*

To perform a voluntary exit, make sure your beacon node is running with the `--rpc`option enabled (e.g. `./run-mainnet-beacon-node.sh --rpc`), then run:


**Prater**

```
build/nimbus_beacon_node deposits exit \ 
 --validator=<VALIDATOR_PUBLIC_KEY> \ 
 --data-dir=build/data/shared_prater_0
```


**Mainnet**

```
build/nimbus_beacon_node deposits exit \ 
 --validator=<VALIDATOR_PUBLIC_KEY> \
 --data-dir=build/data/shared_mainnet_0
```

> **Note:** Make sure your `<VALIDATOR_PUBLIC_KEY>` is prefixed with `0x`. In other words the public key should look like `0x95e3...`



