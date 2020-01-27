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

## Usage

```
nim c -d:const_preset=mainnet -d:nbench -d:release -o:build/nbench nbench/nbench.nim
export SCENARIOS=tests/official/fixtures/tests-v0.10.1/mainnet/phase0

# Full state transition
build/nbench cmdFullStateTransition -d="${SCENARIOS}"/sanity/blocks/pyspec_tests/voluntary_exit/ -q=2

# Slot processing
build/nbench cmdSlotProcessing -d="${SCENARIOS}"/sanity/slots/pyspec_tests/slots_1

# Justification-Finalisation
build/nbench cmdEpochProcessing --epochProcessingCat=catJustificationFinalization -d="${SCENARIOS}"/epoch_processing/justification_and_finalization/pyspec_tests/234_ok_support/

# Registry updates
build/nbench cmdEpochProcessing --epochProcessingCat=catRegistryUpdates -d="${SCENARIOS}"/epoch_processing/registry_updates/pyspec_tests/activation_queue_efficiency/

# Slashings
build/nbench cmdEpochProcessing --epochProcessingCat=catSlashings -d="${SCENARIOS}"/epoch_processing/slashings/pyspec_tests/max_penalties/

# Final updates
build/nbench cmdEpochProcessing --epochProcessingCat=catFinalUpdates -d="${SCENARIOS}"/epoch_processing/final_updates/pyspec_tests/effective_balance_hysteresis/

# Block header processing
build/nbench cmdBlockProcessing --blockProcessingCat=catBlockHeader -d="${SCENARIOS}"/operations/block_header/pyspec_tests/proposer_slashed/

# Proposer slashing
build/nbench cmdBlockProcessing --blockProcessingCat=catProposerSlashings -d="${SCENARIOS}"/operations/proposer_slashing/pyspec_tests/invalid_proposer_index/

# Attester slashing
build/nbench cmdBlockProcessing --blockProcessingCat=catAttesterSlashings -d="${SCENARIOS}"/operations/attester_slashing/pyspec_tests/success_surround/

# Attestation processing
build/nbench cmdBlockProcessing --blockProcessingCat=catAttestations -d="${SCENARIOS}"/operations/attestation/pyspec_tests/success_multi_proposer_index_iterations/

# Deposit processing
build/nbench cmdBlockProcessing --blockProcessingCat=catDeposits -d="${SCENARIOS}"/operations/deposit/pyspec_tests/new_deposit_max/

# Voluntary exit
build/nbench cmdBlockProcessing --blockProcessingCat=catVoluntaryExits -d="${SCENARIOS}"/operations/voluntary_exit/pyspec_tests/validator_exit_in_future/
```

## Running the whole test suite

Warning: this is a proof-of-concept, there is a slight degree of interleaving in output.
Furthermore benchmarks are run in parallel and might interfere which each other.

```
nim c -d:const_preset=mainnet -d:nbench -d:release -o:build/nbench nbench/nbench.nim
nim c -o:build/nbench_tests nbench/nbench_official_fixtures.nim
build/nbench_tests --nbench=build/nbench --tests=tests/official/fixtures/tests-v0.10.1/mainnet/
```

## TODO Reporting
- Dumping as CSV files also for archival, perf regression suite and/or data mining.
- Piggybacking on eth-metrics and can report over Prometheus or StatsD.
- you can augment it via label pragmas that can be applied file-wide
  to tag "cryptography", "block_transition", "database" to have a global view
  of the system.
