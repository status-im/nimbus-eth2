import random, times, stats, strformat, math
export random, times, stats, strformat, math

proc warmup*() =
  # Warmup - make sure cpu is on max perf
  let start = cpuTime()
  var foo = 123
  for i in 0 ..< 300_000_000:
    foo += i*i mod 456
    foo = foo mod 789

  # Compiler shouldn't optimize away the results as cpuTime rely on sideeffects
  let stop = cpuTime()
  echo &"Warmup: {stop - start:>4.4f} s, result {foo} (displayed to avoid compiler optimizing warmup away)"

template printStats*(experiment_name: string, compute_result: typed) {.dirty.} =
  echo "#################################################################"
  echo "\n" & experiment_name
  echo &"Collected {stats.n} samples in {global_stop - global_start:>4.3f} seconds"
  echo &"Average time: {stats.mean * 1000 :>4.3f} ms"
  echo &"Stddev  time: {stats.standardDeviationS * 1000 :>4.3f} ms"
  echo &"Min     time: {stats.min * 1000 :>4.3f} ms"
  echo &"Max     time: {stats.max * 1000 :>4.3f} ms"
  echo "\nDisplay computation result to make sure it's not optimized away"
  echo compute_result # Prevents compiler from optimizing stuff away
  echo '\n'

template bench*(name: string, compute_result: typed, body: untyped) {.dirty.}=
  block: # Actual bench
    var stats: RunningStat
    let global_start = cpuTime()
    for _ in 0 ..< nb_samples:
      let start = cpuTime()
      block:
        body
      let stop = cpuTime()
      stats.push stop - start
    let global_stop = cpuTime()
    printStats(name, compute_result)
