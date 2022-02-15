# Mainnet checklist


## Latest software

Please check that you are running the latest stable [Nimbus software release](https://github.com/status-im/nimbus-eth2/releases).

> At the minimum you should check the [release page](https://github.com/status-im/nimbus-eth2/releases) every other week.

## More than 15 peers

Please check that your node has at least 15 peers. To monitor your peer count, pay attention to the [`Slot start` messages in your logs](keep-an-eye.md#keep-track-of-your-syncing-progress). You should follow the [networking page](networking.md) to get good peers.

## Validator attached

Please check that your [validator is attached](keep-an-eye.md#make-sure-your-validator-is-attached) to your node.

## Systemd

Now that you have Nimbus up and running, we recommend [setting up a systemd service](beacon-node-systemd.md) with an autorestart on boot (should you experience an unexpected power outage, this will ensure your validator restarts correctly). 

Systemd will also ensure your validator keeps running when you exit your ssh session (`Ctrl-C`) and/or switch off your laptop.


## Ethereum Foundation's Checklist

Ad a final check, we recommend you also go through the EF'S [staker checklist](https://launchpad.ethereum.org/checklist).
