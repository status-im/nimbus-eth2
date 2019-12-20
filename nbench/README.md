# Nimbus-bench

Nbench is a profiler dedicated to the Nimbus Beacon Chain.

It is built as a domain specific profiler that aims to be
as unintrusive as possible while providing complementary reports
to dedicated tools like ``perf``, ``Apple Instruments`` or ``Intel Vtune``
that allows you to dive deep down to a specific line or assembly instructions.

In particular, those tools cannot tell you that your cryptographic subsystem
or your parsing routines or your random number generation should be revisited,
may sample at to high a resolution (millisecond) instead of per-function statistics,
and are much less useful without debugging symbols which requires a lot of space.
I.e. ``perf`` and other generic profiler tools give you the laser-thin focused pictures
while nbench strives to give you the big picture.

Features
- by default nbench will collect the number of calls and time spent in
  each function.
- like ncli or nfuzz, you can provide nbench isolated scenarios in SSZ format
  to analyze Nimbus behaviour.

Usage:

```
nim c -d:const_preset=mainnet -d:nbench -o:build/nbench nbench/nbench.nim
export SCENARIOS=tests/official/fixtures/tests-v0.9.3/mainnet/phase0

# Full state transition
build/nbench cmdFullStateTransition -d="${SCENARIOS}"/sanity/blocks/pyspec_tests/voluntary_exit/ -q=2

# Slot processing
build/nbench cmdSlotProcessing -d="${SCENARIOS}"/sanity/slots/pyspec_tests/slots_1

# Attestation processing
build/nbench cmdBlockProcessing --blockProcessingCat=catAttestations -d="${SCENARIOS}"/operations/attestation/pyspec_tests/success_multi_proposer_index_iterations/
```

TODO Reporting:
- Dumping as CSV files also for archival, perf regression suite and/or data mining.
- Piggybacking on eth-metrics and can report over Prometheus or StatsD.
- you can augment it via label pragmas that can be applied file-wide
  to tag "cryptography", "block_transition", "database" to have a global view
  of the system.
