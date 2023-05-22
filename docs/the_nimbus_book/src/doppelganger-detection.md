# Doppelganger detection

Doppelganger detection is a safety feature for preventing slashing in the event that two setups are using the same validator keys, for example after a migration of keys from one setup to another.

Doppelganger detection works by monitoring network activity for a short period for each validator while preventing duties from being performed.

If any activity is detected, the node shuts down with exit code 129.

Because detection depends on network detection, there are cases where it may fail to find duplicate validators even though they are live.
You should never use it as a mechanism for running redundant setups!

## Command line

Doppelganger detection is turned on by default - disable it with:

=== "Beacon node"

    ```sh
    # Disable doppelganger detection
    ./run-mainnet-beacon-node.sh --doppelganger-detection=off ...
    ```

=== "Validator client"

    ```sh
    # Disable doppelganger detection
    build/nimbus_validator_client --doppelganger-detection=off ...
    ```
