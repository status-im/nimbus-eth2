# Back up your database

The best way to do this is to simply copy it over: you'll find it either in `build/data/shared_mainnet_0/db/` (if you're running Prater, `shared_prater_0`) or the directory you supplied to the `--data-dir` argument when you launched Nimbus.

TODO: This is probably not safe to do while the beacon node is running.
      We shuold recommend something based on the following suggestions:
      https://stackoverflow.com/questions/25675314/how-to-backup-sqlite-database
