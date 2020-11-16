# Hardware

In order to process incoming validator deposits from the eth1 chain, you will need to run an eth1 client in parallel to your eth2 client. While it is possible to use a third-party service like Infura, we recommend running your own client in order to ensure the network stays as decentralised as possible.
For example, you need at least 140 GB SSD to run geth fast sync on mainnet...

Is there a recommend AWS machine to run Nimbus on? Struggling to find the right balance between expense and ease of running. Have crashed due to memory a few times, and now due to a full / Any direction would be appreciated for a genuine newbie...

> Stefan: I'm comfortable with 4 GiB of RAM, on another VPS provider. 2 GiB would be a theoretical minimum for building the software, but if you're trying to build a new version while running a beacon node, you're pushing the limits.
So look at "t3.medium".

What about storage requirements?

> Stefan: I'm starting with 160 GiB of block storage for the beacon node alone. If you're also running Geth on that server, you'll want more.

> Tersec: there's a tool to prune the database, which keeps it smaller, but for the moment that's active maintenance which requires a bit of downtime. So it's a tradeoff.
