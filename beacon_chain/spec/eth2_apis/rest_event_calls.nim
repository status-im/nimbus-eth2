# beacon_chain
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  presto/client,
  "."/[rest_types, eth2_rest_serialization]

proc subscribeEventStream*(topics: set[EventTopic]): RestHttpResponseRef {.
     rest, endpoint: "/eth/v1/events", accept: "text/event-stream",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Events/eventstream
