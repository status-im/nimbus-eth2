# The data directory

Nimbus stores all the information it needs to run in a data directory.
In this directory, you'll find a database, your validator keys and secrets, and several other items.

When following the installation guide, the chain data will be stored in `build/data` with separate directories for each chain (mainnet, holesky, etc).

!!! tip "The `--data-dir` option"
    The `--data-dir=/path/to/data` allows picking a specific data directory to store the chain.
    Make sure you use the same `--data-dir` option for all beacon node commands!

## Contents

Inside the data directory, you'll find several subdirectories and files containing various information about the node, chain and validators.

You can examine the contents of the data directory using the `ls -l` command:
```sh
cd nimbus-eth2
ls -l build/data/shared_mainnet_0
```

```sh
-rw-r--r-- 1 nimbus nimbus 234 Jul 19 18:18 beacon_node.enr
drwx------ 1 nimbus nimbus  22 Jul 19 18:18 db
drwx------ 1 nimbus nimbus 196 Jul 19 17:36 secrets
drwx------ 1 nimbus nimbus 250 Jul 19 18:18 validators
```

### `db`

The `db` folder contains historical chain data and information about the latest observed state of the chain.
If you remove the `db` folder, the beacon node will have to resync.

The growth of the database depends on the [history mode](./history.md).

### `secrets` and `validators`

These two folders contain your validator keys, as well as the passwords needed to unlock them when starting the beacon node. By default, the folders are nested directly under the selected data directory, but you can alter the location through the options `--validators-dir` and `--secrets-dir`.

!!! warning
    Be careful not to copy the `secrets` and `validator` folders, leaving them in two locations!
    Instead, always _move_ them to the new location.
    Using the same validators with two nodes poses a significant slashing risk!

For each imported validator, the validators directory includes a sub-folder named after the 0x-prefixed hex-encoded public key of the validator. The per-validator directory contains either a [local keystore file](https://eips.ethereum.org/EIPS/eip-2335) with the name `keystore.json` or [remote keystore file](./web3signer.md) with the name `remote_keystore.json`. It may also contain the following additional configuration files:

* `suggested_fee_recipient.hex` - a hex-encoded execution layer address that will receive the transaction fees from blocks produced by the particular validator.

* `suggested_gas_limit.json` - the suggested gas limit of the blocks produced by the particular validator.

For each imported validator with a local keystore, the secrets directory includes a file named after the 0x-prefixed hex-encoded public key of the validator. The contents of the file will be used as the password for unlocking the keystore. If a password file for a particular validator is missing, Nimbus obtains the password interactively from the user on start-up. If the `--non-interactive` option is specified, Nimbus considers a missing password file to be a fatal error and it will terminate with a non-zero exit code.

## Moving the data directory

You can move the data directory to another location or computer simply by moving its contents and updating the `--data-dir` option when starting the node.

## Permissions

To protect against key loss, Nimbus requires that files and directories be owned by the user running the application.
Furthermore, they should not be readable by others.

It may happen that the wrong permissions are applied, particularly when creating the directories manually.

The following errors are a sign of this:

- `Data folder has insecure ACL`
- `Data directory has insecure permissions`
- `File has insecure permissions`

Here is how to fix them.

=== "Linux / BSD / MacOS"

    Run:

    ```sh
    # Changing ownership to `user:group` for all files/directories in <data-dir>.
    chown user:group -R <data-dir>
    # Set permissions to (rwx------ 0700) for all directories starting from <data-dir>
    find <data-dir> -type d -exec chmod 700 {} \;

    # Set permissions to (rw------- 0600) for all files inside <data-dir>/validators
    find <data-dir>/validators -type f -exec chmod 0600 {} \;

    # Set permissions to (rw------- 0600) for all files inside <data-dir>/secrets
    find <data-dir>/secrets -type f -exec chmod 0600 {} \;
    ```

    In sum:

    - Directories `<data-dir>`, `<data-dir>/validators`, `<data-dir>/secrets` **must** be owned by user and have `rwx------` or `0700`permissions set.

    - Files stored inside `<data-dir>`, `<data-dir>/validators`, `/secrets` **must** be owned by user and have `rw------` or `0600` permission set.

=== "Windows"

    From inside `Git Bash`, run:

    ```sh
    # Set permissions for all the directories starting from <data-dir>
    find <data-dir> -type d -exec icacls {} /inheritance:r /grant:r $USERDOMAIN\\$USERNAME:\(OI\)\(CI\)\(F\) \;

    # Set permissions for all the files inside <data-dir>/validators
    find <data-dir>/validators -type f -exec icacls {} /inheritance:r /grant:r $USERDOMAIN\\$USERNAME:\(F\) \;

    # Set permissions for all the files inside <data-dir>/secrets
    find <data-dir>/secrets -type f -exec icacls {} /inheritance:r /grant:r $USERDOMAIN\\$USERNAME:\(F\) \;
    ```

    !!! note
        Make sure you run the above from inside `Git Bash`, these commands  will not work from inside the standard Windows Command Prompt.
        If you don't already have a `Git Bash` shell, you'll need to install [Git for Windows](https://gitforwindows.org/).

    In sum:

    - Directories `<data-dir>`, `<data-dir>/validators`, `<data-dir>/secrets` **must** be owned by user and have permissions set for the user only (OI)(CI)(F).
    All inherited permissions should be removed.

    - Files which are stored inside <data-dir>, <data-dir>/validators, <data-dir>/secrets **must** be owned by user and have permissions set for the user only (F).
    All inherited permissions should be removed.
