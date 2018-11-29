import
  os, json,
  chronicles, json_serialization, eth_common/eth_types_json_serialization,
  spec/datatypes

type
  BeaconChainDB* = ref object
    dataRoot: string

  BeaconStateRef* = ref BeaconState

proc init*(T: type BeaconChainDB, dataDir: string): BeaconChainDB =
  new result
  result.dataRoot = dataDir / "beacon_db"
  createDir(result.dataRoot)

proc lastFinalizedState*(db: BeaconChainDB): BeaconStateRef =
  try:
    var stateJson = parseJson readFile(db.dataRoot / "BeaconState.json")
    # TODO implement this
  except:
    return nil

proc persistBlock*(db: BeaconChainDB, s: BeaconState, b: BeaconBlock) =
  let stateJson = StringJsonWriter.encode(s, pretty = true)
  writeFile(db.dataRoot / "BeaconState.json", stateJson)
  debug "State persisted"

