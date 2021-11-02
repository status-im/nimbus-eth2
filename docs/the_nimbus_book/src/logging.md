# Logging

Nimbus offers several options for logging - by default, logs are written to stdout using the [chronicles](https://github.com/status-im/nim-chronicles#introduction) `textlines` format which is convenient to read and can be used with tooling for [heroku/logfmt](https://brandur.org/logfmt).

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

Nimbus supports 3 styles of logging: `colors`, `nocolors` and `json`. In `auto` mode, logs will be printed using either `colors` or `nocolors`.

You can choose a log style with the `--log-stdout` option, which also understands `auto` and `none`:

```
./run-mainnet-beacon-node.sh --log-stdout=none # disable logging to std out
./run-mainnet-beacon-node.sh --log-stdout=json # print json logs, one line per item
```

## Logging to a file

To sending logs to a file, it is recommended to use a redirect of the stdout logs:

```
# log json to filename.jsonl
./run-mainnet-beacon-node.sh --log-stdout=json > filename.jsonl
```

 Keep an eye on the growth of this file with a [log rotator](./log-rotate.md). Logs will be written in the "JSON Lines" format - one `json` entry per line.

Nimbus also supports writing logs to a log file using the `--log-file` option - this is provided for historical reasons and may be removed in future releases.

```
./run-mainnet-beacon-node.sh --log-file=filename.jsonl # write json logs to the given filename
```

When the `--log-file` option is enabled, stdout logs will by default be disabled - enable them with the `--log-stdout` option choosing a format other than `auto`.
