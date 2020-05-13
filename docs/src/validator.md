# Become a Validator

To become a validator, you have to first connect to a testnet and sync with the network.

### Connecting to testnets

Nimbus connects to any of the testnets published in the [eth2-clients/eth2-testnets repo](https://github.com/eth2-clients/eth2-testnets/tree/master/nimbus).

Once the [prerequisites](#prerequisites) are installed, you can connect to testnet0 with the following commands. Remember to replace `make` with `mingw32-make` if using Windows:

```bash
git clone https://github.com/status-im/nim-beacon-chain
cd nim-beacon-chain
git checkout devel
make                 # This invocation will bootstrap the build system with additional Makefiles
make testnet0        # This will build Nimbus and all other dependencies
                     # and connect you to testnet0
```

The testnets are restarted once per week, usually on Monday evenings (UTC)) and integrate the changes for the past week.

## Trouble Shooting

The directory that stores the blockchain data of the testnet is `build/data/testnet0`. Delete this folder if you want to start over.
For example, you can start over with a fresh storgae if you entered a wrong private key.
Sample private key: `2042c4306c27f21a85bb1d7b16a8a4270aa674dd3aec4483420ef4ee401957a6`. Feel free to copy this value directly from MetaMask.

You have to switch to the devel branch

Visit the [Goerli faucet](https://faucet.goerli.mudit.blog/) and request for more than 32 Ethers. (should choose the 37.5 Ethers option in the website)

> > > > > how to become a validator with AWS cloud
