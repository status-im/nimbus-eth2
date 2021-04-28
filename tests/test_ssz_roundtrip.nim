# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

# this is not part of test_ssz because the roundtrip tests are incompatible
# with unittest2 as of writing
import
  serialization/testing/generic_suite,
  ../beacon_chain/ssz

executeRoundTripTests SSZ
