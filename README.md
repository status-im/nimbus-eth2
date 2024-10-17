# To trigger:

reset && rm ~/Nim && ln -s ~/nim22 ~/Nim && make consensus_spec_tests_minimal && build/consensus_spec_tests_minimal && make USE_SYSTEM_NIM=1 consensus_spec_tests_minimal && build/consensus_spec_tests_minimal && rm ~/Nim && ln -s ~/nimdevel ~/Nim && make USE_SYSTEM_NIM=1 consensus_spec_tests_minimal && build/consensus_spec_tests_minimal
