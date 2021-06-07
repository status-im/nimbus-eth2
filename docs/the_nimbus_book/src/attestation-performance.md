# Monitor attestation performance

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Very nice, so nice I just had to port it to <a href="https://twitter.com/ethnimbus?ref_src=twsrc%5Etfw">@ethnimbus</a> - `ncli_db` now has an option to pull these stats for any block range - great for comparing changes in your setup: <a href="https://t.co/wumkswHUoR">https://t.co/wumkswHUoR</a> <a href="https://t.co/umFC5yUUNQ">https://t.co/umFC5yUUNQ</a></p>&mdash; Jacek Sieka (@jcksie) <a href="https://twitter.com/jcksie/status/1390582250077630465?ref_src=twsrc%5Etfw">May 7, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

A new `ncli_db validatorPerf` command. Use this to create a report for the attestation performance of your validator(s) over time - It records attestation performance per epoch in an sqlite database.


## Steps


### 1.

```
make build/ncli_db
```

### 2. 

```
build/ncli_db --help
```

At the top you should see

```
ncli_db [OPTIONS]... command

The following options are available:

 --db           Directory where `nbc.sqlite` is stored.
 --network      The Eth2 network preset to use.
```

--network=mainnet OR prater
--db=build/data/shared_mainnet_0/db
--db=build/data/shared_prater_0/db


Near the bottom:

```
ncli_db validatorPerf [OPTIONS]...

The following options are available:

 --start-slot   Starting slot, negative = backwards from head [=-128 * SLOTS_PER_EPOCH.int64].
 --slots        Number of slots to run benchmark for, 0 = all the way to head [=0].
```

3.

```
build/ncli_db validatorPerf --network=prater --db=build/data/shared_prater_0/db
```

output should look like:

```
validator_index,attestation_hits,attestation_misses,head_attestation_hits,head_attestation_misses,target_attestation_hits,target_attestation_misses,delay_avg,first_slot_head_attester_when_first_slot_empty,first_slot_head_attester_when_first_slot_not_empty
0,128,0,127,1,128,0,1.0078125,0,3
1,128,0,125,3,127,1,1.0078125,0,2
2,128,0,127,1,127,1,1.0078125,0,5
...
```

4. Adjust to target a specific block range

```
build/ncli_db validatorPerf --network=prater --db=build/data/shared_prater_0/db --start-slot=-128 -slots=0
```

5. get my validators vs global average

how to get index of my validators?

"dump output from validatorPerf into google sheets or something similar and take it from there"

https://docs.google.com/spreadsheets/d/1SNFf4LsDOK91SWuQZm9DYBoX9JNQNMKHw66Rv0l5EGo/edit#gid=1539392557



## Resources

Inspired by [this workbook](https://docs.google.com/spreadsheets/d/1SNFf4LsDOK91SWuQZm9DYBoX9JNQNMKHw66Rv0l5EGo/edit#gid=553688981) by Paul Hauner, which compares the on-chain attestation performance of a user-defined list of validators vs. the global average.

Method explained [here](https://hackmd.io/xQfi83kHQpm05-aAFVV0DA?view).


