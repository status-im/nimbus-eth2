import
  std/[times, stats]

template withTimer*(stats: var RunningStat, body: untyped) =
  # TODO unify timing somehow
  let start = cpuTime()

  block:
    body

  let stop = cpuTime()
  stats.push stop - start

template withTimerRet*(stats: var RunningStat, body: untyped): untyped =
  let start = cpuTime()
  let tmp = block:
    body
  let stop = cpuTime()
  stats.push stop - start

  tmp
