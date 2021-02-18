# Log rotation

Nimbus logs are written to the console, and optionally to a file. Using the log file option for a long-running process may lead to difficulties when the file grows large. This is typically solved with a log rotator that will switch which file is witten to as well as compress and remove old logs.

To set up file-based log rotation, an application such as [rotatelogs](https://httpd.apache.org/docs/2.4/programs/rotatelogs.html) is used - `rotatelogs` is available on most servers and can be used with `docker`, `systemd` and manual setups to write rotated logs files.

In particular, when using `systemd` and its accompanying `journald` log daemon, this setup avoids clogging the the system log and keep the Nimbus logs in a separate location.

## Compression

`rotatelogs` works by reading stdin and redirecting it to a file based on a name pattern. Whenever the log is about to be rotated, the application will invoke a shell script with the old and new log files. Our aim is to compress the log file to save space. [repo](https://github.com/status-im/nimbus-eth2/tree/unstable/scripts/rotatelogs-compress.sh) provides a helper script to do so:

```bash
# Create a rotation script for rotatelogs
cat << EOF > rotatelogs-compress.sh
#!/bin/sh

# Helper script for Apache rotatelogs to compress log files on rotation - `$2` contains the old log file name

if [ -f "$2" ]; then
    # "nice" prevents hogging the CPU with this low-priority task
    nice gzip -9 "$2"
fi
EOF

chmod +x rotatelogs-compress.sh
```

## Build

Logs in files generally don't benefit from colors - to avoid colors being written to the file, additional flags can be added to the Nimbus [build process](./build.md) - these flags are best saved in a build script to which one can add more options. Future versions of Nimbus will support disabling colors at runtime.

```bash

# Build nimbus with colors disabled
cat << EOF > build-nbc-text.sh
#!/bin/bash
make NIMFLAGS="-d:chronicles_colors=off -d:chronicles_sinks=textlines" nimbus_beacon_node
EOF
```

## Run

The final step is to redirect logs to `rotatelogs` using a pipe when starting nimbus:

```bash
build/nimbus_beacon_node \
  --network:pyrmont \
  --web3-url="$WEB3URL" \
  --data-dir:$DATADIR | rotatelogs -L "$DATADIR/nbc_bn.log" -p "/path/to/rotatelogs-compress.sh" -D -f -c "$DATADIR/log/nbc_bn_%Y%m%d%H%M%S.log" 3600
```

The options used in this example will:

* `-L nbc_bn.log` - symlink to the latest log file, for use with `tail -F`
* `-p "/path/to/rotatelogs-compress.sh"` - script to run when rotation is about to happen
* `-D` - create the `log` directory if needed
* `-f` - open the log immediately when starting `rotatelogs`
* `-c "$DATADIR/log/nbc_bn_%Y%m%d%H%M%S.log"` - include timestamp in log filename
* `3600` - rotate logs every hour (3600 seconds)
