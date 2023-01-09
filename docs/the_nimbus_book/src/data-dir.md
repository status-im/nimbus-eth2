# The data directory

Nimbus stores all the information it needs to run in a data directory. In this directory, you'll find a database, your validator keys and secrets and several other items.

When following the installation guide, the chain data will be stored in `build/data` with separate directories for each chain (mainnet, prater, etc).

!!! tip "The `--data-dir` option"
    The `--data-dir=/path/to/data` allows picking a specific data directory to store the chain - make sure you use the same `--data-dir` option for all beacon node commands!

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

The `db` folder contains historical chain data and information about the latest observed state of the chain. If you remove the `db` folder, the beacon node will have to resync.

The growth of the database depends on the [history mode](./history.md).

### `secrets` and `validators`

These two folders contain your validator keys as well as the passwords needed to unlock them when starting the beacon node.

!!! warning
    Be careful not to copy the `secrets` and `validator` folders, leaving them in two locations - instead, always move them to the new location! Using the same validators with two nodes poses a significant slashing risk!

## Moving the data directory

You can move the data directory to another location or computer simply by moving its contents and updating the `--data-dir` option when starting the node.

## Permissions

To protect against key loss, Nimbus requires that files and directories be owned by the user running the application. Furthermore, they should not be readable by others.

It may happen that the wrong permissions are applied, particularly when creating the directories manually.

The following errors are a sign of this:

- `Data folder has insecure ACL`
- `Data directory has insecure permissions`
- `File has insecure permissions`

Here is how to fix them.

### Linux/ BSD / MacOS

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

- Directories `<data-dir>`, `<data-dir>/validators`, `<data-dir>/secrets` MUST be owned by user and have `rwx------` or `0700`permissions set.

- Files stored inside `<data-dir>`, `<data-dir>/validators`, `/secrets` MUST be owned by user and have `rw------` or `0600` permission set.

### Windows

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
    Make sure you run the above from inside `Git Bash`, these commands  will not work from inside the standard Windows Command Prompt. If you don't already have a `Git Bash` shell, you'll need to install [Git for Windows](https://gitforwindows.org/).

In sum:

- Directories `<data-dir>`, `<data-dir>/validators`, `<data-dir>/secrets` MUST be owned by user and have permissions set for the user only (OI)(CI)(F). All inherited permissions should be removed.

- Files which are stored inside <data-dir>, <data-dir>/validators, <data-dir>/secrets MUST be owned by user and have permissions set for the user only (F). All inherited permissions should be removed.
