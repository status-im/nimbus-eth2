# Move a Nimbus validator to another server
> You stop the node, remove the corresponding files from data-dir/secrets and data-dir/validators  (they're named by the public key) - then you start the node again and verify that the validator is not loaded per https://nimbus.guide/connect-eth2.html (no Local validator attached log line for the moved validator)
>
> in particular, you should ensure that the removed validator is not attesting (using for example https://beaconcha.in/ to verify) before starting it on the other node
>
> You will also want to copy the slashing protection database to the other server (validators/slashing_protection.sqlite3)
