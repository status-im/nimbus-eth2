# Prater testnet: what you should know

</br>
</br>


- The Prater launchpad is live here (use it to make a deposit): [https://prater.launchpad.ethereum.org/en/](https://prater.launchpad.ethereum.org/en/)

- To run a Prater node after making a deposit, [update Nimbus](./keep-updated.md)  and then execute `./run-prater-beacon-node.sh`

</br>
</br>

----------------------------------------------------------

</br>
</br>

The latest Eth2 testnet, [Prater](https://twitter.com/Butta_eth/status/1374383003011452937), is now open to the public.

Prater's objective is to ensure that the network remains stable under a higher load than we've seen so far on mainnet -- the genesis count for Prater was 210k (almost double the size of the Beacon Chain Mainnet).

To elaborate a little, we want to make sure that the network is able to function properly with considerably more validators: increasing the number of validators increases the state size, increases the amount of work done to process that state, and increases the number of messages being gossipped on the network; blocks also become fuller, which explores a new kind of constraint as clients need to optimise better for attestation inclusion.

Both Pyrmont and Prater will co-exist for the foreseeable future (we will be testing the [Altair](https://github.com/ethereum/eth2.0-specs/releases/tag/v1.1.0-alpha.1) fork on Pyrmont, for example). However, in the medium term we expect Prater to replace Pyrmont.

If you're already validating with Nimbus, you should start thinking about transitioning from Pyrmont to Prater at some point over the next few weeks. However, there is no immediate rush, so please do so at your own convenience. If you're new to Nimbus then you could try starting directly with Prater.







