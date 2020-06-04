import
  confutils, os, strutils, json_serialization,
  stew/byteutils,
  ../beacon_chain/spec/[crypto, datatypes]

type
  QueryCmd* = enum
    nimQuery
    get

  QueryConf = object
    file* {.
        defaultValue: ""
        desc: "BeaconState ssz file"
        name: "file" }: InputFile

    case queryCmd* {.
      defaultValue: nimQuery
      command
      desc: "Query the beacon node database and print the result" }: QueryCmd

    of nimQuery:
      nimQueryExpression* {.
        argument
        desc: "Nim expression to evaluate (using limited syntax)" }: string

    of get:
      getQueryPath* {.
        argument
        desc: "REST API path to evaluate" }: string


let
  config = QueryConf.load()

case config.queryCmd
of QueryCmd.nimQuery:
  # TODO: This will handle a simple subset of Nim using
  #       dot syntax and `[]` indexing.
  echo "nim query: ", config.nimQueryExpression

of QueryCmd.get:
  let pathFragments = config.getQueryPath.split('/', maxsplit = 1)
  let bytes =
    case pathFragments[0]
    of "genesis_state":
      readFile(config.file.string).string.toBytes()
    else:
      stderr.write config.getQueryPath & " is not a valid path"
      quit 1

  # TODO nasty compile error here
  # /home/arnetheduck/status/nim-beacon-chain/beacon_chain/ssz/navigator.nim(45, 50) template/generic instantiation of `getFieldBoundingOffsets` from here
  # Error: internal error: (filename: "semtypes.nim", line: 1864, column: 21)
  # let navigator = DynamicSszNavigator.init(bytes, BeaconState)

  # echo navigator.navigatePath(pathFragments[1 .. ^1]).toJson
