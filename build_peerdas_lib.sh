#!/usr/bin/env bash

# Copyright (c) 2024 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# Current usage: ./build_peerdas_lib.sh nimpeerdaskzg

set -eu  # Exit immediately if a command exits with a non-zero status.

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <destination_folder>"
    exit 1
fi


DESTINATION_FOLDER=$1 # Destination folder to copy the built nim library with the static lib include to

COMMIT_HASH="fc339dc9bb886432871b4fd706cf4fdaa8269cce" # commit to checkout rust lib at
REPO_URL="https://github.com/crate-crypto/peerdas-kzg"

echo "Building peerdas-kzg with commit hash: $COMMIT_HASH and destination: $DESTINATION_FOLDER"

TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

echo "Cloning repository..."
git clone "$REPO_URL" "$TEMP_DIR"
cd "$TEMP_DIR"

echo "Checking out commit: $COMMIT_HASH"
git checkout "$COMMIT_HASH"

# Check if the user is on Windows and install gnu target instead of msvc
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "Detected Windows environment. Adding x86_64-pc-windows-gnu target..."
    rustup target add x86_64-pc-windows-gnu
fi

echo "Building Rust Library: Running ./scripts/compile.sh nim"
if [ -f "./scripts/compile.sh" ]; then
    ./scripts/compile.sh nim
else
    echo "Error: ./scripts/compile.sh not found"
    exit 1
fi

if [ ! -d "bindings/nim" ]; then
    echo "Error: bindings/nim directory not found"
    exit 1
fi

# Move back to the original directory that the script was called from
cd -

echo "Creating destination folder: $DESTINATION_FOLDER"
mkdir -p "$DESTINATION_FOLDER"

# Copy the nim code to the destination folder (includes the built static lib) 
echo "Copying contents of bindings/nim/nim_code to $DESTINATION_FOLDER"
cp -a "$TEMP_DIR/bindings/nim/nim_code/." "$DESTINATION_FOLDER"

# Clean up the temporary directory
rm -rf "$TEMP_DIR"

echo "Successfully built peerdas-kzg library and copied the nimble package to $DESTINATION_FOLDER"
