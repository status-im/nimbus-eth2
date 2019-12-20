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

proc reportCli*(metrics: seq[Metadata], preset, flags: string) =

  cpuX86:
    let name = cpuName()
    echo "\nCPU: ", name

  # https://blog.trailofbits.com/2019/10/03/tsc-frequency-for-all-better-profiling-and-benchmarking/
  # https://www.agner.org/optimize/blog/read.php?i=838
  echo "The CPU Cycle Count is indicative only. It cannot be used to compare across systems, works at your CPU nominal frequency and is sensitive to overclocking, throttling and frequency scaling (powersaving and Turbo Boost)."

  const lineSep = &"""|{'-'.repeat(50)}|{'-'.repeat(14)}|{'-'.repeat(15)}|{'-'.repeat(17)}|{'-'.repeat(26)}|{'-'.repeat(26)}|"""
  echo "\n"
  echo lineSep
  echo &"""|{"Procedures (" & preset & ')':^50}|{"# of Calls":^14}|{"Time (ms)":^15}|{"Avg Time (ms)":^17}|{"CPU cycles (in billions)":^26}|{"Avg cycles (in billions)":^26}|"""
  echo &"""|{flags:^50}|{' '.repeat(14)}|{' '.repeat(15)}|{' '.repeat(17)}|{"indicative only":^26}|{"indicative only":^26}|"""
  echo lineSep
  for m in metrics:
    if m.numCalls == 0:
      continue
    # TODO: running variance / standard deviation but the Welford method is quite costly.
    #       https://nim-lang.org/docs/stats.html / https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
    let cumulTimeMs = m.cumulatedTimeNs.float64 * 1e-6
    let avgTimeMs = cumulTimeMs / m.numCalls.float64
    let cumulCyclesBillions = m.cumulatedCycles.float64 * 1e-9
    let avgCyclesBillions = cumulCyclesBillions / m.numCalls.float64
    echo &"""|{m.procName:<50}|{m.numCalls:>14}|{cumulTimeMs:>15.3f}|{avgTimeMs:>17.3f}|{cumulCyclesBillions:>26.3f}|{avgCyclesBillions:>26.3f}|"""
  echo lineSep
