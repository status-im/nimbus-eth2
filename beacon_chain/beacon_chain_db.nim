import
  os, json,
  chronicles, json_serialization, eth_common/eth_types_json_serialization,
  spec/[datatypes, digest, crypto]

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
    let stateFile = db.dataRoot / "BeaconState.json"
    if fileExists stateFile:
      new result
      # TODO serialization error: Json.loadFile(stateFile, result[])
  except:
    error "Failed to load the latest finalized state",
          err = getCurrentExceptionMsg()
    return nil

proc persistBlock*(db: BeaconChainDB, s: BeaconState, b: BeaconBlock) =
  Json.saveFile(db.dataRoot / "BeaconState.json", s, pretty = true)
  debug "State persisted"

