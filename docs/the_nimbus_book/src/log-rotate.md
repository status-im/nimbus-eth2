# Set up log rotation

Nimbus logs are written to `stdout`, and can be redirected to a file.
Writing to a file for a long-running process may lead to difficulties when the file grows large.
This is typically solved with a *log rotator*.
A log rotator is responsible for switching the written-to file, as well as compressing and removing old logs.

## Using `logrotate`

[logrotate](https://github.com/logrotate/logrotate) provides log rotation and compression.
The corresponding package will install its Cron hooks (or Systemd timer) -- all you have to do is add a configuration file for Nimbus in `/etc/logrotate.d/nimbus-eth2`:

```text
/var/log/nimbus-eth2/*.log {
	compress
	missingok
	copytruncate
}
```

The above assumes you've configured Nimbus to write its logs to `/var/log/nimbus-eth2/` (usually by redirecting `stdout` and `stderr` from your init script).

`copytruncate` is required because, when it comes to moving the log file, `logrotate`'s default behaviour requires application support for re-opening that log file at runtime (something which is currently lacking).
So, instead of a move, we tell `logrotate` to do a copy and a truncation of the existing file.
A few log lines may be lost in the process.

You can control rotation frequency and the maximum number of log files kept by using the global configuration file, `/etc/logrotate.conf`:

```text
# rotate daily
daily
# only keep logs from the last 7 days
rotate 7
```

## Using `rotatelogs`

[rotatelogs](https://httpd.apache.org/docs/2.4/programs/rotatelogs.html) captures `stdout` logging and redirects it to a file, rotating and compressing on the fly.

It is available on most servers and can be used with `Docker`, `Systemd` and manual setups to write rotated logs files.

In particular, when `systemd` and its accompanying `journald` log daemon are used, this setup avoids clogging the system log by keeping the Nimbus logs in a separate location.

### Compression

`rotatelogs` works by reading `stdin` and redirecting it to a file based on a name pattern.
Whenever the log is about to be rotated, the application invokes a shell script with the old and new log files.
Our aim is to compress the log file to save space.
The [Nimbus-eth2 repo](https://github.com/status-im/nimbus-eth2/tree/unstable/scripts/rotatelogs-compress.sh) provides a helper script that does this:

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

### Run

The final step is to redirect logs to `rotatelogs` using a pipe when starting Nimbus:

```bash
build/nimbus_beacon_node \
  --network:prater \
  --web3-url="$WEB3URL" \
  --data-dir:$DATADIR 2>&1 | rotatelogs -L "$DATADIR/nbc_bn.log" -p "/path/to/rotatelogs-compress.sh" -D -f -c "$DATADIR/log/nbc_bn_%Y%m%d%H%M%S.log" 3600
```

The options used in this example do the following:

* `-L nbc_bn.log` - symlinks to the latest log file, for use with `tail -F`
* `-p "/path/to/rotatelogs-compress.sh"` - runs `rotatelogs-compress.sh` when rotation is about to happen
* `-D` - creates the `log` directory if needed
* `-f` - opens the log immediately when starting `rotatelogs`
* `-c "$DATADIR/log/nbc_bn_%Y%m%d%H%M%S.log"` - includes timestamp in log filename
* `3600` - rotates logs every hour (3600 seconds)

### Deleting old logs

`rotatelogs` will not do this for you, so you'll need a Cron script (or Systemd timer):

```bash
# delete log files older than 7 days
find "$DATADIR/log" -name 'nbc_bn_*.log' -mtime +7 -exec rm '{}' \+
```
