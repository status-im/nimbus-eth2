#!/usr/bin/env bash
# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# We use ${BASH_SOURCE[0]} instead of $0 to allow sourcing this file
# and we fall back to a Zsh-specific special var to also support Zsh.
REL_PATH="$(dirname ${BASH_SOURCE[0]:-${(%):-%x}})"
ABS_PATH="$(cd "${REL_PATH}"; pwd)"

# Activate nvm only when this file is sourced without arguments:
if [ -z "$*" ]; then
  if ! command -v ganache-cli > /dev/null; then
    if command -v nvm > /dev/null; then
      nvm use
      npm install -g ganache-cli
    else
      echo <<EOF
    In order to use Ganache (a development ETH1 chain), please install NVM with:
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash

    For more info:
    https://github.com/nvm-sh/nvm
EOF
    fi
  fi
fi

# The user env file allows you to specify personal overrides for some
# settings such as WEB3_URL, CPU_LIMIT, etc:
USER_ENV_FILE="${ABS_PATH}/.env"
if [ -f "${USER_ENV_FILE}" ]; then
  set -o allexport
  source "${USER_ENV_FILE}"
  set +o allexport
fi

source "${ABS_PATH}/vendor/nimbus-build-system/scripts/env.sh"
