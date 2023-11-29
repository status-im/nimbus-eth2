# Logging

Nimbus offers several options for logging.
By default, logs are written to stdout using the [chronicles](https://github.com/status-im/nim-chronicles#introduction) `textlines` format which is convenient to read and can be used with tooling for [heroku/logfmt](https://brandur.org/logfmt).

## Change log level

You can customise Nimbus' verbosity with the `--log-level` option.

For example:

```
./run-mainnet-beacon-node.sh --log-level=WARN
```

The default value is `INFO`.

Possible values (in order of decreasing verbosity) are:

```
TRACE
DEBUG
INFO
NOTICE
WARN
ERROR
FATAL
NONE
```

## Change logging style

Nimbus supports three log formats: `colors`, `nocolors` and `json`.
In `auto` mode, logs will be printed using either `colors` or `nocolors`.

You can choose a log format with the `--log-format` option, which also understands `auto` and `none`:

```
./run-mainnet-beacon-node.sh --log-format=none # disable logging to std out
./run-mainnet-beacon-node.sh --log-format=json # print json logs, one line per item
```

## Logging to a file

To send logs to a file, you can redirect the stdout logs:

```
# log json to filename.jsonl
./run-mainnet-beacon-node.sh --log-format=json > filename.jsonl
```

We recommend keeping an eye on the growth of this file with a [log rotator](./log-rotate.md).
Logs are written in the "JSON Lines" format - one `json` entry per line.
