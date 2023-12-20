import
  # TODO These imports shouldn't be necessary here
  #      (this is a variation of the sandwich problem)
  stew/shims/net,
  chronicles,
  ../../../beacon_chain/spec/network,
  confutils/cli_parsing_fuzzer,
  ../../../beacon_chain/conf

fuzzCliParsing ValidatorClientConf
