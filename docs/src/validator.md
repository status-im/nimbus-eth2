# Become a Validator

To become a validator, you have to first connect to a testnet.

### Connecting to testnets

Nimbus connects to any of the testnets published in the [eth2-clients/eth2-testnets repo](https://github.com/eth2-clients/eth2-testnets/tree/master/nimbus).

Once the [prerequisites](#prerequisites) are installed you can connect to testnet0 with the following commands:

```bash
git clone https://github.com/status-im/nim-beacon-chain
cd nim-beacon-chain
make                 # This invocation will bootstrap the build system with additional Makefiles
make testnet0        # This will build Nimbus and all other dependencies
                     # and connect you to testnet0
```

The testnets are restarted once per week, usually on Monday evenings (UTC)) and integrate the changes for the past week.
