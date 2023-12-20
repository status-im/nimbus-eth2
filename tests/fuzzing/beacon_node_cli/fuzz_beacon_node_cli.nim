import
  # TODO These imports shouldn't be necessary here
  #      (this is a variation of the sandwich problem)
  stew/shims/net,
  chronicles,
  confutils/cli_parsing_fuzzer,
  ../../../beacon_chain/conf,
  ../../../beacon_chain/spec/network

fuzzCliParsing BeaconNodeConf
