# Contribute without a validator (WIP: UNPUBLISHED)

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">&quot;How could running a node be more of a compelling experience? How do I signal to my friends that I&#39;m running a node? Can running a node feel like a game?&quot;<a href="https://t.co/4WrhjGK4Kh">https://t.co/4WrhjGK4Kh</a></p>&mdash; Nimbus (@ethnimbus) <a href="https://twitter.com/ethnimbus/status/1385530083486670848?ref_src=twsrc%5Etfw">April 23, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## Run a slasher
https://medium.com/prysmatic-labs/eth2-slashing-prevention-tips-f6faa5025f50
```
Slasher
The slasher refers to a separate piece of software with its main purpose of detecting slashable events. You can think of a slasher as the “police” of the network. Due to the extra data and processes required to detect malicious messages, usually it is run separate from the beacon node. In order to detect slashable messages, the slasher records the attesting and proposing history for every validator on the network, and cross references this history with what is broadcasted to find slashable messages such as double blocks or surrounding votes.
All the network needs is 1 honest slasher client to monitor the network because any slashings found are propagated to the entire network for it to be put into a block as soon as possible.
Whistleblower Rewards
In order to incentivize slashing detection, validators are given a “whistleblower reward” which is a reward on the beacon chain for submitting a block with any valid slashing. These rewards are given for each validator in the slashing, and are usually ~0.1 ETH each validator.
While incentivizing detection is valuable, simply running a slasher client will not have you earn whistleblower rewards if you find a slashing in Prysm. By default, any slashings found are propagated to the network to be included in the block ASAP so usually the reward goes to the proposer immediately after the slashing is detected, not to the validator running the slasher.
Running a slasher is not meant to be profitable. Slashing is meant to be rare and whistleblower rewards are low on purpose. Running a slasher is meant to be an altruistic action, and once again, only a single honest, properly functioning slasher needs to be active in the network to catch slashable offenses. Thankfully, this is a low bar to entry, and we envision quite a lot of users and entities will run slashers to ensure network security.
```

## Run a light-client server

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">In this case, the bottleneck is the number of light clients on the network - you need enough such that the network can recover the block. I believe this is the &quot;minimum user count&quot; section in his blog post.</p>&mdash; Mustafa Al-Bassam (@musalbas) <a href="https://twitter.com/musalbas/status/1396834702795972621?ref_src=twsrc%5Etfw">May 24, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
