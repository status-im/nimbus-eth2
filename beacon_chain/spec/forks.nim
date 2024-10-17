import
  "."/[
    eth2_ssz_serialization,
    crypto],
  ssz_serialization,
  stew/io2,
  snappy

proc sszDecodeEntireInput(
    input: openArray[byte],
    Decoded: type): Decoded =
  let stream = unsafeMemoryInput(input)
  var reader = init(SszReader, stream)
  reader.readValue(result)
  doAssert not stream.readable

proc parseTest(Format: typedesc[SSZ], T: typedesc): T =
  let path = "/usr/local/nimbus-eth2/vendor/nim-eth2-scenarios/tests-v1.5.0-alpha.8/minimal/altair/light_client/sync/pyspec_tests/supply_sync_committee_from_past_update/bootstrap.ssz_snappy"
  sszDecodeEntireInput(snappy.decode(io2.readAllBytes(path).get, 10_000_000), T)

var i = 0

proc runTest() =
  proc initializeStore(
      bootstrap: ref ForkedLightClientBootstrap): ForkedLightClientStore =
    let store_consensus_fork =
      case i mod 2
      of 0: LightClientDataFork.Altair
      of 1: LightClientDataFork.Capella
      else: LightClientDataFork.Altair
    inc i
    var store {.noinit.}: ForkedLightClientStore
    withLcDataFork(store_consensus_fork):
      bootstrap[].migrateToDataFork(lcDataFork)
      store = ForkedLightClientStore.init(initialize_light_client_store(
        bootstrap[].forky(lcDataFork)).get)
    store

  let bootstrap = newClone(ForkedLightClientBootstrap.init(parseTest(SSZ, crypto.LightClientBootstrap)))
  #echo bootstrap[]
  var store = initializeStore(bootstrap)
  withForkyStore(store):
    process_light_client_update(forkyStore)

for i in 1..6:
  runTest()
