# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  strformat, strutils,
  # Bench
  bench_lab

template cpuX86(body: untyped): untyped =
  when defined(i386) or defined(amd64):
    body

cpuX86:
  import platforms/x86

# Reporting benchmark result
# -------------------------------------------------------

proc reportCli*(metrics: seq[Metadata]) =

  cpuX86:
    let name = cpuName()
    echo "CPU: ", name

  const lineSep = &"""|{'-'.repeat(50)}|{'-'.repeat(20)}|{'-'.repeat(20)}|{'-'.repeat(20)}|"""
  echo "\n\n"
  echo lineSep
  echo &"""|{"Procedures":^50}|{"# of Calls":^20}|{"Time (ms)":^20}|{"CPU cycles":^20}|"""
  echo lineSep
  for m in metrics:
    echo &"""|{m.procName:>50}|{m.numCalls:>20}|{m.cumulatedTimeNs div 1_000_000:>20}|{m.cumulatedCycles:>20}|"""
