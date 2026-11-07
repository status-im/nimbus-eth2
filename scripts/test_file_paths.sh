#!/usr/bin/env bash
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cd "$fixture"

printf 'contents\n' > 'source name.txt'
OS= bash "$scripts/copyfile.sh" 'source name.txt' 'destination name.txt'
cmp 'source name.txt' 'destination name.txt'
mkdir 'destination directory'
OS= bash "$scripts/copyfile.sh" 'source name.txt' 'destination directory'
cmp 'source name.txt' 'destination directory/source name.txt'
bash "$scripts/makedir.sh" 'parent directory/child directory'
[ -d 'parent directory/child directory' ]
[ ! -e 'parent' ]
echo 'file path tests passed'
