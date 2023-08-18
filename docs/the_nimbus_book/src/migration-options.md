# Client migration (advanced)

The main migration guide is located [here](./migration.md).
Here we document a couple of advanced options you can use if you wish to have more fine-grained control.

## Export validators

The default command for exporting your slashing protection history is:

```sh
build/nimbus_beacon_node slashingdb export database.json
```

This will export your history in the correct format to `database.json`.

On success you will have a message similar to:

```
Exported slashing protection DB to 'database.json'
Export finished: '$HOME/.cache/nimbus/BeaconNode/validators/slashing_protection.sqlite3' into 'interchange.json'
```

### Export from a specific validators directory

The validator directory contains your validator's setup.

```sh
build/nimbus_beacon_node slashingdb export database.json --validators-dir=path/to/validatorsdir/
```

### Export from a specific data directory

The data directory (`data-dir`) contains your beacon node setup.

```sh
build/nimbus_beacon_node slashingdb export database.json --data-dir=path/to/datadir/
```

### Partial exports

You can perform a partial export by specifying the public key of the relevant validator you wish to export.

```sh
build/nimbus_beacon_node slashingdb export database.json --validator=0xb5da853a51d935da6f3bd46934c719fcca1bbf0b493264d3d9e7c35a1023b73c703b56d598edf0239663820af36ec615
```

If you wish to export multiple validators, you must specify the `--validator` option multiple times.


## Import validators

The default command for importing your validator's slashing protection history into the database is:

```sh
build/nimbus_beacon_node slashingdb import database.json
```

### Import to a specific validators directory

The validator directory contains your validator's setup.

```sh
build/nimbus_beacon_node slashingdb import database.json --validators-dir=path/to/validatorsdir/
```

### Import to a specific data directory

The data directory contains your beacon node's setup.

```sh
build/nimbus_beacon_node slashingdb import database.json --data-dir=path/to/datadir/
```

