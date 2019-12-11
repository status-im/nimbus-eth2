# Nimbus-bench

Nbench is a profiler dedicated to the Nimbus Beacon Chain.

It is built as a domain specific profiler that aims to be
as unintrusive as possible while providing complementary reports
to dedicated tools like ``perf``, ``Apple Instruments`` or ``Intel Vtune``
that allows you to dive deep down to a specific line or assembly instructions.

In particular, those tools cannot tell you that your cryptographic subsystem
or your parsing routines or your random number generation should be revisited.
I.e. ``perf`` and other generic profiler tools give you the laser-thin focused pictures
while nbench strives to give you the big picture.

To achieve this while staying unobstrusive:
- by default nbench will collect the number of calls and time spent in
  each function.
- you can augment it via label pragmas that can be applied file-wide
  to tag "cryptography", "block_transition", "database" to have a global view
  of the system.
- like ncli or nfuzz, you can provide nbench isolated scenarios in SSZ format
  to analyze Nimbus behaviour.

Reporting:
- Data can be dumped as CSV files also for archival, perf regression suite and/or data mining.

TODO Reporting:
- Piggybacking on eth-metrics and can report over Prometheus or StatsD.
