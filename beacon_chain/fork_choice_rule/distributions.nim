# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# A port of https://github.com/ethereum/research/blob/master/clock_disparity/ghost_node.py
# Specs: https://ethresear.ch/t/beacon-chain-casper-ffg-rpj-mini-spec/2760
# Part of Casper+Sharding chain v2.1: https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ#
# Note that implementation is not updated to the latest v2.1 yet

import math, random

proc normal_distribution*(mean = 0, std = 1): int =
  ## Return an integer sampled from a normal distribution (gaussian)
  ## ⚠ This is not thread-safe
  # Implementation via the Box-Muller method
  # See https://en.wikipedia.org/wiki/Box–Muller_transform
  let
    mean = mean.float
    std = std.float

  var
    z1 {.global.}: float
    generate {.global.}: bool

  generate = not generate

  if not generate:
    return int(z1 * std + mean)

  let
    u1 = rand(1.0)
    u2 = rand(1.0)
    R = sqrt(-2.0 * ln(u1))
    z0 = R * cos(2 * PI * u2)
  z1 = R * sin(2 * PI * u2)
  return int(z0 * std + mean)

when isMainModule:
  import sequtils, stats, strformat

  func absolute_error(y_true, y: float): float =
    ## Absolute error: |y_true - y|
    abs(y_true - y)
  func relative_error(y_true, y: float): float =
    ## Relative error: |y_true - y|/|y_true|
    abs(y_true - y)/abs(y_true)

  let
    mu = 1000
    sigma = 12
    a = newSeqWith(10000000, normal_distribution(mean = mu, std = sigma))

  var statistics: RunningStat
  for val in a:
    statistics.push val

  # Note: we use the sample standard deviation, not population
  #       See Bessel's correction and standard deviation estimation.

  proc report(stat: string, value, expected: float) =
    echo &"{stat:<20} {value:>9.4f} | Expected: {expected:>9.4f}"

  echo &"Statistics on {a.len} samples"
  report "Mean: ", statistics.mean, mu.float
  report "Standard deviation: ", statistics.standardDeviationS, sigma.float

  # Absolute error
  doAssert absolute_error(mu.float, statistics.mean) < 0.6
  doAssert absolute_error(sigma.float, statistics.standardDeviationS) < 0.01

  # Relative error
  doAssert relative_error(mu.float, statistics.mean) < 0.01
  doAssert relative_error(sigma.float, statistics.standardDeviationS) < 0.01
