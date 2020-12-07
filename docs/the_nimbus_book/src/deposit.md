# Make a deposit for your validator
The easiest way to get your deposit in is to follow the Ethereum Foundation's launchpad instructions here:

**Testnet**:
[https://pyrmont.launchpad.ethereum.org/](https://pyrmont.launchpad.ethereum.org/)

**Mainnet**: [https://launchpad.ethereum.org/](https://launchpad.ethereum.org/)

> ⚠️  If you are making a mainnet deposit make sure you verify that the deposit contract you are interacting with is the correct one. 
>
> You should verify that the address is indeed: [0x00000000219ab540356cBB839Cbe05303d7705Fa](https://etherscan.io/address/0x00000000219ab540356cBB839Cbe05303d7705Fa)

You may notice that there have been considerable improvements to the launchpad process since the summer.
 
In particular, the Key Generation section is now much clearer, and you no longer have to install dependencies to get the command line app working.

We won't elaborate on each individual step here, since they are well explained on the site itself. However, there are two points of note:

## 1. Eth1 connection
![](https://i.imgur.com/81BgR14.png)

In the `Select Client` section you'll first be asked to choose an eth1 client. You need to run an eth1 client in order to process incoming validator deposits from the eth1 chain.

![](https://i.imgur.com/l5WSGqZ.png)

We recommend you choose `Go Ethereum` (or `Geth`). 

*If you've followed the book up to this point, you should already have geth up and running.*

## 2. Block explorer
Once you've sent off your transaction, you should see the following screen.
 
![](https://i.imgur.com/A4IMlhK.png)
 
 

We recommend you click on `Beaconchain`. This will open up a window that allows you to keep track of your validator's status.
 
![](https://i.imgur.com/JHQblna.png)

It's a good idea to bookmark this page.

## Expected waiting time (the queue)
Once you send off your transaction(s), your validator will be put in a queue based on deposit time. Getting through the queue may take a few hours or days (assuming the chain is finalising). No validators are accepted into the validator set while the chain isn't finalising.

