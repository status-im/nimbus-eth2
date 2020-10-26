# Make a deposit
 
The easiest way to get your deposit in is to follow the Ethereum Foundation's launchpad instructions here:
 
[https://medalla.launchpad.ethereum.org/](https://zinken.launchpad.ethereum.org/)
 
You may notice that there have been considerable improvements to the launchpad process since the summer.
 
In particular, the Key Generation section is now much clearer, and you no longer have to install dependencies to get the command line app working.
 
![](https://i.imgur.com/UjQ7uRt.png)

We won't elaborate on each individual step here, since they are well explained on the site itself. However, there are two points of note:

## 1. Eth1 connection
![](https://i.imgur.com/81BgR14.png)

In the `Select Client` section you'll first be asked to choose an eth1 client. You need to run an eth1 client in order to process incoming validator deposits from the eth1 chain.

![](https://i.imgur.com/l5WSGqZ.png)

We recommend you choose `Go Ethereum` (or `Geth`).

## 2. Block explorer
Once you've sent off your transaction, you should see the following screen.
 
![](https://i.imgur.com/A4IMlhK.png)
 
 

We recommend you click on `Beaconchain`. This will open up a window that allows you to keep track of your validator's status.
 
![](https://i.imgur.com/JHQblna.png)

It's a good idea to bookmark this page.

## A note on expected waiting time (the queue)
Once you send off your transaction(s), your validator will be put in a queue based on deposit time, and will getting through the queue may take a few hours or days (assuming the chain is finalising).

