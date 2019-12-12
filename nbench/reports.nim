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

proc reportCli*(metrics: seq[Metadata], preset: string) =

  cpuX86:
    let name = cpuName()
    echo "\nCPU: ", name

  # https://blog.trailofbits.com/2019/10/03/tsc-frequency-for-all-better-profiling-and-benchmarking/
  # https://www.agner.org/optimize/blog/read.php?i=838
  echo "The CPU Cycle Count is indicative only. It cannot be used to compare across systems, works at your CPU nominal frequency and is sensitive to overclocking, throttling and frequency scaling (powersaving and Turbo Boost)."

  const lineSep = &"""|{'-'.repeat(50)}|{'-'.repeat(20)}|{'-'.repeat(20)}|{'-'.repeat(30)}|"""
  echo "\n"
  echo lineSep
  echo &"""|{"Procedures (" & preset & ')':^50}|{"# of Calls":^20}|{"Time (ms)":^20}|{"CPU cycles (in billions)":^30}|"""
  echo &"""|{' '.repeat(50)}|{' '.repeat(20)}|{' '.repeat(20)}|{"indicative only":^30}|"""
  echo lineSep
  for m in metrics:
    if m.numCalls == 0: continue
    echo &"""|{m.procName:>50}|{m.numCalls:>20}|{m.cumulatedTimeNs.float64 * 1e-6:>20.3f}|{m.cumulatedCycles.float64 * 1e-9:>30.3f}|"""
  echo lineSep
