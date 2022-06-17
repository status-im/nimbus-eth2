# Make a deposit for your validator
The easiest way to get your deposit in is to follow the Ethereum Foundation's launchpad instructions here:

**Prater testnet**:
[https://prater.launchpad.ethereum.org/](https://prater.launchpad.ethereum.org/)

> Use Prater to stress test / future proof  your set up against peak mainnet load. See [here](./prater.md) for all you need to know

**Mainnet**: [https://launchpad.ethereum.org/](https://launchpad.ethereum.org/)

> ⚠️  If you are making a mainnet deposit make sure you verify that the deposit contract you are interacting with is the correct one.
>
> You should verify that the address is indeed: [0x00000000219ab540356cBB839Cbe05303d7705Fa](https://etherscan.io/address/0x00000000219ab540356cBB839Cbe05303d7705Fa)

We won't elaborate on each individual step here, since they are well explained on the site itself. However, there are two points of note:

## 1. Execution client / web3 connection
![](https://i.imgur.com/81BgR14.png)

In the `Select Client` section you'll first be asked to choose an execution client. You need to run an execution client in order to perform your validator duties.

![](https://i.imgur.com/l5WSGqZ.png)

*If you've followed the book up to this point, you should already have an execution client up and running.*

## 2. Block explorer
Once you've sent off your transaction, you should see the following screen.

![](https://i.imgur.com/A4IMlhK.png)



We recommend you click on `Beaconchain`. This will open up a window that allows you to keep track of your validator's status.

![](https://i.imgur.com/JHQblna.png)

It's a good idea to bookmark this page.

## Expected waiting time (the queue)
Once you send off your transaction(s), your validator will be put in a queue based on deposit time. Getting through the queue may take a few hours or days (assuming the chain is finalising). No validators are accepted into the validator set while the chain isn't finalising. The `Pending Validators` metric on the [beaconcha.in](https://beaconcha.in/) will give you the size of the queue.
