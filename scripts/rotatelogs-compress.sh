#!/bin/sh

# Helper script for Apache rotatelogs to compress log files on rotation - `$2` contains the old log file name

if [ -f "$2" ]; then
    # "nice" prevents hogging the CPU with this low-priority task
    nice gzip -9 "$2"
fi

