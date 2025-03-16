# Withdraw your staked funds

Withdrawals are enabled for each validator once it's configured to use [0x01 withdrawal credentials](https://notes.ethereum.org/@launchpad/withdrawals-faq#Q-What-are-0x00-and-0x01-withdrawal-credentials-prefixes) which specify an execution layer address that will be the beneficiary of all withdrawn funds.

If your validator was created with `0x01` withdrawal credentials, it's already fully prepared for withdrawals and you can safely skip the next step.

## Updating your withdrawal credentials

To migrate your validator from BLS to `0x01` withdrawal credentials, you have to use the same third-party tool that was used to generate the BLS key.
You have to create a signed `BLS-to-Execution-Change` message that must be broadcast to the network (and eventually published in a beacon chain block) in order to execute the desired withdrawal credentials update.

If you have used the [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) tool (formerly known as `eth2.0-deposit-cli`), please follow the steps provided [here](https://launchpad.ethereum.org/en/btec/).
Alternatively, if you have used [ethdo](https://github.com/wealdtech/ethdo), follow the steps provided [here](https://github.com/wealdtech/ethdo/blob/master/docs/changingwithdrawalcredentials.md).

If you have used other software for generating your BLS withdrawal credentials, please refer to its documentation or development team for further assistance regarding creating a signed `BLS-to-Execution-Change` message.

!!! warning
    Your choice of withdrawal address is permanent.
    If you ever wish to switch it later, the only option is to exit your validator and then create a new one.

!!! tip
    The specified withdrawal address doesn't need to match the [fee recipient address](./suggested-fee-recipient.md) used by your validator.

!!! tip
    It's recommended that you prepare your `BLS-to-Execution-Change` message on a secure device, disconnected from the internet.
    You can use an USB drive to transfer the produced JSON file to the machine where Nimbus is running and then use the following command to broadcast the message to the network:

        curl \
          -X POST \
          -H “Content-type: application/json” \
          -d @<Bls-to-Execution-Change-Filename> \
          http://localhost:5052/eth/v1/beacon/pool/bls_to_execution_changes

## Periodic withdrawals of staking rewards (partial withdrawals)

Once the validator is configured with `0x01` withdrawal credentials, all staking rewards will be periodically withdrawn as long as the validator balance is above 32 ETH.
No user action is required.

!!! info
    It is not possible to manually request specific amounts of ETH to be withdrawn

## Full withdrawals

To withdrawal the entire staked balance of your validator, you must perform a voluntary validator exit.

!!! warning
    Voluntary exits are **irreversible**.
    You won't be able to validate again with the same key.

!!! warning
    Make sure you've migrated your validator to `0x01` withdrawal credentials before exiting.

The time required for the withdrawal to complete depends on multiple factors such as the total number of validators in the network, the number of other validators attempting to exit at the moment and the current time in the periodic withdrawals cycle.
Under typical conditions, it's expected to take 2 to 7 days.

!!! warning
    Do not remove the validator keys or shut down your validator software until the withdrawal operation is complete.
    Otherwise, you may incur protocol inactivity penalties.

To perform the voluntary exit, make sure your beacon node is running with the `--rest` option enabled (e.g. `./run-mainnet-beacon-node.sh --rest`), then run:

    build/nimbus_beacon_node deposits exit --validator=<VALIDATOR_KEYSTORE_PATH>

!!! note
    In the command above, you must replace `<VALIDATOR_KEYSTORE_PATH>` with the file-system path of an Ethereum [ERC-2335 Keystore](https://eips.ethereum.org/EIPS/eip-2335) created by a tool such as [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) or [ethdo](https://github.com/wealdtech/ethdo).

## `rest-url` parameter

The `--rest-url` parameter can be used to point the exit command to a specific node for publishing the request, as long as it's compatible with the [REST API](./rest-api.md).
