#!/usr/bin/env python3

# Print logs that have gaps between them larger than the threshold - useful for
# finding slowdowns in the code where the thread is busy for long periods of
# time
# usage:
# tail -F logfile | python slowlogs.py 0.75

import sys, re
from datetime import datetime

THRESHOLD = 0.75

if len(sys.argv) > 0:
    THRESHOLD = float(sys.argv[1])

last = None
prevline = None

dt = re.compile(r"([0-9-]+ [0-9:.]+)")

for line in sys.stdin:
    match = dt.search(line)

    if match:
        current = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S.%f")
        if last != None and (current - last).total_seconds() > THRESHOLD:
            print((current - last).total_seconds())
            print(prevline, end="")
            print(line)
        last = current
        prevline = line
