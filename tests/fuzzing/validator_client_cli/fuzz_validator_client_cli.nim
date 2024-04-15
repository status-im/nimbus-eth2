# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # TODO These imports shouldn't be necessary here
  #      (this is a variation of the sandwich problem)
  stew/shims/net, chronicles, ../../../beacon_chain/spec/network,

  confutils/cli_parsing_fuzzer,
  ../../../beacon_chain/conf

fuzzCliParsing ValidatorClientConf
