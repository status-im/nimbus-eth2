# Become a Validator

To become a validator, you need to install the beacon chain software, acquire 32 ETH, set up your validator account and register with the deposit contract on Ethereum.

There is currently no Eth2 mainnet - all networks are testnets.

## Recommended Testnets

Though Nimbus can connect to any of the testnets published in the [eth2-clients/eth2-testnets repo](https://github.com/eth2-clients/eth2-testnets/tree/master/nimbus), below are the recommended ones:

- Multi-client Testnet: [altona](https://github.com/goerli/altona) ([explorer](https://altona.beaconcha.in))
- Nimbus Testnet: testnet0 (experimental, not always active)

## Altona

### Initial setup

Before we start, we have to obtain 32 ETH on the Goerli testnet. Then, we can deposit 32 Ethers to the registration smart contract to become a validator.

1. Open your [MetaMask](https://metamask.io/) wallet, switch to the `Goerli Test Network` option from the top right corner.
2. Copy your account address by clicking on one of your accounts.
3. Post your account address on a social media platform (Twitter or Facebook). Copy the url to the post.
4. Paste your post url on the [Goerli faucet](https://faucet.goerli.mudit.blog/) and select `Give me Ether > 37.5 Ethers` from the top right cornor of the page.
5. Wait for a few seconds and return to your MetaMask wallet to check if you have successfully received.
6. Once the [prerequisites](./install.md) are installed, you can connect to the altona testnet with the following commands: <br>

- **_Remember to replace `make` with `mingw32-make` if using Windows._**

```bash
git clone https://github.com/status-im/nim-beacon-chain
cd nim-beacon-chain
git checkout devel
git pull
make update
make altona        # This will build Nimbus and all other dependencies
                   # and connect you to altona
```

<img src="./img/connect_testnet.PNG" alt="" style="margin: 0 40 0 40"/>

7. You will be prompted to enter your private key of the account you want to deposit the 32 Ether from. Find your private key from MetaMask as below:

<img src="./img/export_pkey.PNG" alt="" width="200" style="margin: 0 40 0 40"/>

<img src="./img/enter_private_key.PNG" alt="" style="margin: 0 40 0 40"/>

8. Wait for a few seconds until you see that your deposit has been sent:

<img src="./img/deposit_sent.PNG" alt="" style="margin: 0 40 0 40"/>

9. The beacon chain client will start syncing the network while your deposit is being processed. As soon as the deposit has been added, the client will start performing validation duties.

<img src="./img/success.PNG" alt="" style="margin: 0 40 0 40"/>

You can also get a brief estimate of the time remaining until your network gets synced by comparing the output `epoch` value and the one in the blockchain explorer (the [altona explorer](https://altona.beaconcha.in) for example).

### Upgrading

When restarting the beacon node, the software will resume from where it left off, using your previous deposits.

```
cd nim-beacon-chain
git pull
make update # Update dependencies
make altona # Restart using same keys as last run
```

## Key management

Keys are stored in the `build/data/testnet_name/` folder, under `secrets` and `validators` - make sure to keep these folders backed up.

## Metrics

Metrics are not included in the binary by default - to enable them, use the following options when starting the client:

```
make NIMFLAGS="-d:insecure" altona
```

You can now browse the metrics using a browser and connecting to:

http://localhost:8008/metrics

Make sure to protect this port as the http server used is not considered secure and should not be used by untrusted peers.

## Troubleshooting

1. The directory that stores the blockchain data of the testnet is `build/data/shared_altona_0` (replace `altona` with other testnet names). Delete this folder if you want to start over. For example, you can start over with a fresh storage if you entered a wrong private key.

2. Currently, you have to switch to the devel branch in order to run the validator node successfully.

3. Everytime you want to update your node to the latest version, run `git pull`, `make update`, and then `make altona`.

4. If `make update` has been running for too long, you can use `make update V=1` or `make update V=2` for verbose output.
