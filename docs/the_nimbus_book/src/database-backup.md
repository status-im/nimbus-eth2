# Back up your database


The best way to do this is to use `.backup` sqlite command:

1. Navigate to either `build/data/shared_mainnet_0/db/` (if you're running Prater: `shared_prater_0`) or the directory you supplied to the `--data-dir` argument when you launched Nimbus.

2. Run the following command:
  ```
  sqlite3 nbc.sqlite3 ".backup 'backup_nbc.sqlite3'"
  ```
  Make sure to correctly type both single and double quotes, as written above.

