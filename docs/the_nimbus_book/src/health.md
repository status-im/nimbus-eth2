# Monitor the health of your node

The most important thing for the the health, performance and stablity of your node and the overall network is the strength of your node's network connectivity / peer count.

See [here](./networking.md) for our networking related tips and tricks.

## Keep track of your attestation effectiveness

Attestation effectiveness is a metric that directly affects your validator rewards. In simple terms, an attestation is more valuable the sooner it is put into a block and included in the chain. 

This interval is called the *inclusion distance* of an attestation. The smaller it is, the more profitable your validator will be. For a deeper understanding we highly recommend reading [Attestant's wonderful blog post](https://www.attestant.io/posts/defining-attestation-effectiveness/#:~:text=Stakers%20looking%20to%20maximize%20their,provide%20clear%20metrics%20for%20performance.) on the matter.

You can verify your validator's effectiveness on the [beaconcha.in](https://beaconcha.in/) website.

![](https://i.imgur.com/u80Ub2j.png)

Ideally you want to see a value above 80%.

While attestation effectiveness depends on a variety of factors - attestation network propagation, your network connectivity, and the peers you are connected to - your network connectivity is likely the most important factors you can control to improve this metric. Apart from the tips outlined on this guide, you could also experiment with [subscribing to all subnets](./profits.md#subscribe-to-all-subnets).

## Monitor your system's network I/O usage

If you're a Linux user and want to track how much network I/O your system uses over time, you can install a nice utility called [`vnstat`](https://humdi.net/vnstat/).

To install, run:

```
sudo apt install vnstat
```

To run it:

*TBC -See [here](https://github.com/jclapis/rp-pi-guide/blob/main/Native.md#monitoring-your-pis-performance) for more*

