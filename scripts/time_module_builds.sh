#!/usr/bin/env bash
set -Eeo pipefail

find beacon_chain/ ncli/ research/ tests/ -type f -name '*.nim' -print0 | shuf -z | xargs -0 -I{} bash -c "rm nimcache -rf && /usr/bin/time -f%e -- ./env.sh nim c -o:/dev/null --hints:off --warnings:off -d:release {} 2>&1 | tr -d '\n' && echo '' {}"
