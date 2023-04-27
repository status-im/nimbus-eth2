# Set up Graffiti

You can use your node's graffiti flag to include a short text in the blocks that your node creates.
You will be able to see it using the block explorer.

The graffiti can be either a string or, if you want to specify raw bytes, you can use 0x-prefixed hex value.

## Command line

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --graffiti="<YOUR_WORDS>"
    ```

=== "Prater"
    ```sh
    ./run-prater-beacon-node.sh --graffiti="<YOUR_WORDS>"
    ```

