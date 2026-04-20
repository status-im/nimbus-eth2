#!/usr/bin/env bash
# scripts/getopt-wrapper.sh - exec GNU getopt on any platform.
set -eu

if [ "$(uname)" != "Darwin" ]; then
    exec getopt "$@"
fi

# macOS: prefer getopt in PATH if it's GNU (exit 4 from --test), else Homebrew.
getopt --test > /dev/null 2>&1 && rc=0 || rc=$?
if [ "$rc" -eq 4 ]; then
    exec getopt "$@"
fi

for c in /opt/homebrew/opt/gnu-getopt/bin/getopt /usr/local/opt/gnu-getopt/bin/getopt; do
    [ -x "$c" ] && exec "$c" "$@"
done

echo "GNU getopt not installed. Install via 'brew install gnu-getopt'." >&2
exit 1
