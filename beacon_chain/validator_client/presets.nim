# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ".."/spec/[forks, presets]

const
  PHASE0_FORK_VERSION* = Version [byte 0x00, 0x00, 0x00, 0x00]
  GENESIS_FORK_VERSION* = PHASE0_FORK_VERSION
  ALTAIR_FORK_VERSION* = Version [byte 0x01, 0x00, 0x00, 0x00]
  BELLATRIX_FORK_VERSION* = Version [byte 0x02, 0x00, 0x00, 0x00]
  CAPELLA_FORK_VERSION* = Version [byte 0x03, 0x00, 0x00, 0x00]
  DENEB_FORK_VERSION* = Version [byte 0x04, 0x00, 0x00, 0x00]
  ELECTRA_FORK_VERSION* = Version [byte 0x05, 0x00, 0x00, 0x00]

static: doAssert high(ConsensusFork) == ConsensusFork.Electra
