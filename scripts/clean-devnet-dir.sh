#!/usr/bin/env bash

if [ -z "$1" ]; then
  echo "Usage: run-devnet-el-cl-pair.sh <network-metadata-dir>"
  exit 1
fi

if [ ! -d "$1" ]; then
  echo "Please supply a valid network metadata directory"
  exit 1
fi

set -Eeu

NETWORK=$(cd "$1"; pwd)

cd $(dirname "$0")

source ./repo_paths.sh
rm -rf "$(data_dir_for_network)"
