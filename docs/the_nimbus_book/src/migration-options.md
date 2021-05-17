# Advanced migration options

## Importing validators

The default command for import into the database is:

```
build/nimbus_beacon_node slashingdb import --interchange=interchange.json
```

### With specified validators folder

The validators folder contains the valdiators setup.
By default it is `path/to/datadir/validators`

```
build/nimbus_beacon_node slashingdb import --interchange=interchange.json --validators-dir=path/to/validatorsdir/
```

### With the data-dir folder

The data-dir contains the beacon node setup.

```
build/nimbus_beacon_node slashingdb import --interchange=interchange.json --data-dir=path/to/datadir/
```

## Exporting all validators

The default command for exporting the database is:

```
build/nimbus_beacon_node slashingdb exportAll --interchange=interchange.json
```

On success you will have a message similar to:

```
Exported slashing protection DB to 'interchange.json'
Export finished: '$HOME/.cache/nimbus/BeaconNode/validators/slashing_protection.sqlite3' into 'interchange.json'
```

### With specified validators folder

The validators folder contains the valdiators setup.
By default it is `path/to/datadir/validators`

```
build/nimbus_beacon_node slashingdb exportAll --interchange=interchange.json --validators-dir=path/to/validatorsdir/
```

### With the data-dir folder

The data-dir contains the beacon node setup.

```
build/nimbus_beacon_node slashingdb exportAll --interchange=interchange.json --data-dir=path/to/datadir/
```

## Partial exports

Partial export can be done by specifying the public keys of the relevant validators.
The `--validators` command can be specified multiple time, once per validator.

```
build/nimbus_beacon_node slashingdb export --interchange=interchange.json --validators=0xb5da853a51d935da6f3bd46934c719fcca1bbf0b493264d3d9e7c35a1023b73c703b56d598edf0239663820af36ec615
```


