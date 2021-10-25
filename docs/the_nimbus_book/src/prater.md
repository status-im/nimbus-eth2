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

The latest Eth2 testnet, [Prater](https://twitter.com/Butta_eth/status/1374383003011452937), is open to the public.

Prater's objective is to ensure that the network remains stable under a higher load than we've seen so far on mainnet -- the genesis count for Prater was 210k (almost double the size of the Beacon Chain Mainnet).

To elaborate a little, we want to make sure that the network is able to function properly with considerably more validators: increasing the number of validators increases the state size, increases the amount of work done to process that state, and increases the number of messages being gossipped on the network; blocks also become fuller, which explores a new kind of constraint as clients need to optimise better for attestation inclusion.






