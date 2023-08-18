# Add an additional validator

<!-- TODO: We should work on a new recommended way to add validators based on the Keymanager API (this doesn't require a node restart) -->

To add an additional validator, [generate a new key](./more-keys.md) then follow [the same steps](./run-a-validator.md#2-import-your-validator-keys) as you did when adding your other keys.

You'll have to [restart](./run-a-validator.md#3-start-validating) the beacon node for the changes to take effect.

!!! tip
    A single Nimbus instance is able to handle multiple validators.
