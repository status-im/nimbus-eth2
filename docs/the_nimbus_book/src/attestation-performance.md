# Attestation performance

`ncli_db validatorPerf` is an advanced tool that helps you analyze the performance of your validator over time.

The tool requires that you [build nimbus from source](./build.md).

## Steps

Make sure you're in the `nimbus-eth2` repository.

### 1. Build ncli_db

The first step is to build `ncli_db`:
```sh
make ncli_db
```

### 2. View options

To view the options available to you, run:
```sh
build/ncli_db --help
```

At the top you should see:

```
ncli_db [OPTIONS]... command

The following options are available:

 --db           Directory where `nbc.sqlite` is stored.
 --network      The Eth2 network preset to use.
```

Where:

- The `network` can be `mainnet`, `prater`, or `sepolia`.

- The default location of the `db`  is `build/data/shared_mainnet_0/db` for `mainnet`, `build/data/shared_prater_0/db` for `prater`, etc.


Near the bottom, you should see:

```
ncli_db validatorPerf [OPTIONS]...

The following options are available:

 --start-slot   Starting slot, negative = backwards from head [=-128 * SLOTS_PER_EPOCH.int64].
 --slots        Number of slots to run benchmark for, 0 = all the way to head [=0].
```

Use `start-slot` and `slots` to restrict the analysis on a specific block range.

### 3. Run

To view the performance of all validators on Prater so far across the entire block range stored in your database, run:
```sh
build/ncli_db validatorPerf \
--network=prater \
--db=build/data/shared_prater_0/db
```

You should see output that looks like to the following:

```
validator_index,attestation_hits,attestation_misses,head_attestation_hits,head_attestation_misses,target_attestation_hits,target_attestation_misses,delay_avg,first_slot_head_attester_when_first_slot_empty,first_slot_head_attester_when_first_slot_not_empty
0,128,0,127,1,128,0,1.0078125,0,3
1,128,0,125,3,127,1,1.0078125,0,2
2,128,0,127,1,127,1,1.0078125,0,5
...
```

### 4. Adjust to target a specific block range

To restrict the analysis to the performance between slots 0 and 128, say, run:
```sh
build/ncli_db validatorPerf \
--network=prater \
--db=build/data/shared_prater_0/db \
--start-slot=0 \
--slots=128
```

### 5. Compare my validators to the global average

We'll use [Paul Hauner's wonderful workbook](https://docs.google.com/spreadsheets/d/1SNFf4LsDOK91SWuQZm9DYBoX9JNQNMKHw66Rv0l5EGo/) as a template.
This workbook consists of three inter-related spreadsheets: `Summary`, `My Validators`, and `datasource`.

1. Make a copy of the document.

2. Remove the table entries in `My Validators` and delete everything in the `datasource` sheet.

3. Import the output from `validatorPerf` to `datasource`.
   The easiest way to do this is to pipe the output to a `csv`, remove the first few lines, and import the `csv` into `datasource`.

4. Manually copy over your validator(s) to the `My Validators` sheet.
   The easiest way to find your validator's `validator_index` is to search for it by its public key on [beaconcha.in](https://beaconcha.in/) (for example, [this validator's](https://beaconcha.in/validator/115733) index is 115733).

5. Go to the `Summary` page and view your results.


## Resources

The workbook's method is explained [here](https://hackmd.io/xQfi83kHQpm05-aAFVV0DA?view).

