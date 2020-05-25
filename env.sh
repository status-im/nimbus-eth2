#!/bin/bash

# We use ${BASH_SOURCE[0]} instead of $0 to allow sourcing this file
# and we fall back to a Zsh-specific special var to also support Zsh.
REL_PATH="$(dirname ${BASH_SOURCE[0]:-${(%):-%x}})"
ABS_PATH="$(cd ${REL_PATH}; pwd)"

# Activate nvm only when this file is sourced without arguments:
if [ -z "$*" ]; then
  if command -v nvm > /dev/null; then
    nvm use
    command -v ganache-cli > /dev/null || { npm install -g ganache-cli; }
  else
    echo <<EOF
  In order to use Ganache (a development ETH1 chain), please install NVM with:
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash

  For more info:
  https://github.com/nvm-sh/nvm
EOF
  fi
fi

source ${ABS_PATH}/vendor/nimbus-build-system/scripts/env.sh

