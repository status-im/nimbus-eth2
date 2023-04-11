# Backup web3 provider

TODO: This is no longer correct (See the support for using multiple ELs)
      Find all links that point to here and fix them.

Nimbus supports using multiple web3 providers, in case one breaks or goes down.
These web3 providers must share JWT secret and will be used in a fallback manner, meaning that when the first one fails, the second one will be used instead until the first one is back up.

Each beacon node requires at least one dedicated web3 provider.

!!! note
    The backup web3 provider must use the same JWT secret as the main provider, and will not be used until the main provider has failed.
    This may result in a gap in duties as the backup provider syncs.
    This gap will be addressed in future releases.

```sh
./run-mainnet-beacon-node.sh \
  --web3-url="http://127.0.0.1:8551" \
  --web3-url="ws://backup:4444"
```
