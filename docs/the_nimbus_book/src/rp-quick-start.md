# Rocket Pool: Introductory guide

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">We believe decentralised staking pools like <a href="https://twitter.com/Rocket_Pool?ref_src=twsrc%5Etfw">@Rocket_Pool</a> and <a href="https://twitter.com/DAppNode?ref_src=twsrc%5Etfw">@DAppNode</a> DAO are essential to ensuring <a href="https://twitter.com/ethereum?ref_src=twsrc%5Etfw">@ethereum</a>&#39;s future as an unbreakable and censorship-resistant system.<a href="https://t.co/FXQQICZsfL">https://t.co/FXQQICZsfL</a></p>&mdash; Nimbus (@ethnimbus) <a href="https://twitter.com/ethnimbus/status/1367841160081907717?ref_src=twsrc%5Etfw">March 5, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


This guide offers a bare-bones introduction to getting up and running with Nimbus and [Rocket Pool](https://www.rocketpool.net/) -- a trustless staking pool which matches those who wish to stake some ETH with those who wish to operate a node.

> **Nota Bene:** Rocket Pool is not only for node operators. Staking in Rocket Pool as a regular user is as easy as navigating to the [Rocket Pool website](https://beta.rocketpool.net/), entering an amount of ETH to stake, and clicking Start! When you stake, you will immediately receive an amount of rETH with equivalent value to the ETH you deposit. This allows anyone, no matter how technical or wealthy, to help contribute to the decentralisation of the network.

It assumes you are familiar with the basics of how Rocket Pool works. If that's not the case, we recommend reading through the following resources first:
- Our [introductory post](https://our.status.im/rocket-pool-integration/)
- Rocket Pool explainer series: [part 1](https://medium.com/rocket-pool/rocket-pool-staking-protocol-part-1-8be4859e5fbd)
- Rocket Pool explainer series: [part 2](https://medium.com/rocket-pool/rocket-pool-staking-protocol-part-2-e0d346911fe1)
- [Beta Finale](https://medium.com/rocket-pool/rocket-pool-3-0-beta-finale-fb35c4f8e003) announcement

If you're a Raspberry Pi user, we highly recommend [this wonderful and complementary resouce](https://github.com/jclapis/rp-pi-guide/blob/main/Overview.md) by community member Joe Clapis.

> **Note:** Rocket Pool is currently running their [Beta Finale](https://medium.com/rocket-pool/rocket-pool-3-0-beta-finale-fb35c4f8e003) on Pyrmont testnet, so this is the perfect time to get up to speed and play around with their stack.

## 1. Install Docker + Compose

> If you're using  Ubuntu, Debian, CentOS or Fedora, please skip this step.

To install Docker and Compose follow the instructions [here](https://docs.docker.com/get-docker/) and [here](https://docs.docker.com/compose/install/).

> Note that Docker Desktop for Mac and Windows already include Compose, which means that if you're using a Mac or Windows device you can ignore the second link.

## 2. Install smart node client
> **Background:** The Rocket Pool smart node software stack provides all of the necessary infrastructure for running a node in the Rocket Pool network: it contains a smart node client, which provides a command-line interface for managing a smart node either locally or remotely (over SSH) and a smart node service; which provides an API for client communication and performs background node tasks (such as validator duties).


You can install the smart node client with either `curl` or `wget`.

To see which tool you have available, run:

```
curl --version
wget --version
```

Once you know whether you have `curl` or `wget` available, you can find the relevant command for your operating system [here](https://rocket-pool.readthedocs.io/en/latest/smart-node/getting-started.html#installation).

> For example, if you're running MacOS with `curl` installed, you should run:
>
> ```
>curl -L https://github.com/rocket-pool/smartnode-install/releases/latest/download/rocketpool-cli-darwin-amd64 -o /usr/local/bin/rocketpool && chmod +x /usr/local/bin/rocketpool
>```


## 3. Install smart node service

To install the smart node service, run:
```
rocketpool service install
```

> **Note:** If you’re using Ubuntu, Debian, CentOS or Fedora, the above will automatically install docker engine and docker-compose on your system. If automatic dependency installation is not supported on your platform (this is the case for MacOS for example), run `rocketpool service install -d` instead.

## 4. Configure smart node client

Now you're ready to configure the smart node client:
```
rocketpool service config
```

You’ll be prompted to select an eth1 and eth2 client to run. If you like, you can use Infura instead of running an eth1 client.

*The default is to select a random client for you, so make sure you select Nimbus!*

## 5. Start Rocket Pool

To start Rocket Pool, open a new shell session and run:

```
rocketpool service start
```

You should see the following:

```
Starting rocketpool_eth1 ... done
Starting rocketpool_api  ... done
Starting rocketpool_eth2 ... done
Starting rocketpool_watchtower ... done
Starting rocketpool_node       ... done
Starting rocketpool_validator  ... done
```

> **Note:** Docker will make sure that Rocket Pool keeps running, even if Nimbus crashes or you restart your computer.

## 6. Check Nimbus is running correctly

To ensure Nimbus is running correctly, run:

```
rocketpool service logs eth2
```

Nimbus will print lines that look like this:

```
eth2_1        | INF 2021-02-21 06:35:43.302+00:00 Slot start                                 topics="beacnde" tid=1 file=nimbus_beacon_node.nim:940 lastSlot=682377 scheduledSlot=682378 delay=302ms641us581ns peers=47 head=f752f69a:745 headEpoch=23 finalized=2717f624:672 finalizedEpoch=21 sync="PPUPPPDDDD:10:2.0208:1.5333:01d20h29m (736)"
eth2_1        | INF 2021-02-21 06:35:43.568+00:00 Slot end
```

The time towards the end (`01d20h29m`) tells you how long Nimbus thinks it will be until you're fully synced.

## 7. Create a Rocket Pool wallet

Now that Nimbus is syncing, you're ready to create a Rocket Pool wallet to create and hold your validator keys:
```
rocketpool wallet init
```

## 8. Find your node address

You'll need to find your node address in order to be able to request Goerli ETH:
```
rocketpool node status
```

## 9. Request Goerli ETH

Request **35** Goerli ETH from [the faucet](https://faucet.goerli.mudit.blog/) to the address you found in the previous step.

> **Note:** you'll need slightly more than 32 ETH since you'll also need to interact with the Rocket Pool smart contracts to request RPL.



## 10. Request Goerli RPL

You'll also need some RPL. To request RPL directly from the Rocket Pool faucet, run: 

```
rocketpool faucet withdraw-rpl
```

## 11. Register your node

Now you're finally ready to register your node with Rocket Pool:

```
rocketpool node register
```

## 12. Make a deposit

The final step is to deposit 32 ETH to initialise your validator (don't worry you'll get half of it back):

```
rocketpool node deposit
```

> **Note:** You’ll see a prompt that will ask you to select the amount of ETH you wish to deposit. Select 32 ETH to ensure you can start staking ASAP. At some point (shouldn't take more than 24 hours) you'll be assigned an additional 16 ETH to manage from Rocket Pool stakers: at this stage you'll be able to ask for a 16 ETH refund using `rocketpool minipool refund`.


That’s it! You’re officially part of the Rocket Pool network!

> **Tip:** Once Nimbus is synced, you'll be able to check on the status of your minipool by running:
> ```
> rocketpool minipool status
> ```


## Key resources / further reading
- Node Operator’s Guide: [https://medium.com/rocket-pool/rocket-pool-v2-5-beta-node-operators-guide-77859891766b](https://medium.com/rocket-pool/rocket-pool-v2-5-beta-node-operators-guide-77859891766b)

- Smart node docs (for all things documentation related): [https://rocket-pool.readthedocs.io/en/latest/smart-node/introduction.html](https://rocket-pool.readthedocs.io/en/latest/smart-node/introduction.html)

- Joe Clapis' guide (Excellent resource for Pi users): [https://github.com/jclapis/rp-pi-guide/blob/main/Overview.md](https://github.com/jclapis/rp-pi-guide/blob/main/Overview.md)

- Rocket Pool's [discord](https://discord.gg/a5zVQd66gr)
