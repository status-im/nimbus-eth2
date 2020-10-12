#!/bin/bash

# Copyright (c) 2018-2019 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

if [[ $OS = "Windows_NT" ]]
then
  if [ ! -d "$1" ]; then
    # Create full path.
    mkdir -p $1;
    # Remove all inherited aces from path $1 ACL.
    icacls $1 /inheritance:r &> /dev/null;
    # Grant full access rights to current user only in $1 ACL.
    icacls $1 /grant:r $USERDOMAIN\\$USERNAME:\(OI\)\(CI\)F &> /dev/null;
  fi
else
  # Create full path with 0750 permissions.
  mkdir -m 0750 -p $(1)
fi
