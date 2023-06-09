# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ./gnosis/[
    phase0_preset, altair_preset, bellatrix_preset, capella_preset,
    deneb_preset]

export
  phase0_preset, altair_preset, bellatrix_preset, capella_preset,
  deneb_preset
