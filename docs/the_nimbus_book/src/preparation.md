# Mainnet preparations

## Genesis

eth2 will have a `MIN_GENESIS_TIME` of `1606824000` (or for those of you who don’t think in unix time – **December 1, 2020, 12pm UTC**).

To trigger genesis at this time, there must be at least `16,384` validator deposits 7 days prior to December 1. If not, genesis will be triggered 7 days after this threshold has been met (whenever that may be). For a more detailed discussion of how genesis is kicked off, see Ben Edgington’s genesis [excellent writeup](https://hackmd.io/@benjaminion/genesis).

To summarize the above, although Genesis may occur after December 1st, you should be prepared for it to occur on the first. Which means, you should make your deposit no later than **November 24, 2020, 12pm UTC** if you wish to be included in the Genesis block.

> **Tip:** You can keep track of how many deposits are still needed in order for Genesis to be triggered on the [Launchpad homepage](https://launchpad.ethereum.org/).

## Latest software

Please check that you are running the latest stable [Nimbus software release](https://github.com/status-im/nimbus-eth2/releases).

> **Note:** If you are setting up your client before launch, it is your responsibility  to check for any new software releases in the run up to launch. At the minimum you should check the [release page](https://github.com/status-im/nimbus-eth2/releases) weekly.

## More than 20 peers

Please check that your node has at least 15 peers. See [the footer](keep-an-eye.md#keep-track-of-your-syncing-progress) at the bottom of the terminal window for your peer count.

## Validator attached

Please check that your [validator is attached](keep-an-eye.md#make-sure-your-validator-is-attached) to your node.

## VPN

To avoid exposing your validator identity to the network, we recommend you use a trustworthy VPN such as [protonmail](https://protonmail.com/).. This help reduce the risk of revealing your IP address to the network.

## Ethereum Foundation's Checklist

Ad a final check, we recommend you also go through the EF'S [staker checklist](https://launchpad.ethereum.org/checklist).

