# Sanity check on constants
# ----------------------------------------------------------------

{.used.}

import
  # Standard library
  macros, os, strutils, tables, math, json, streams,
  strformat, unittest,
  # Third party
  yaml,
  # Status libraries
  stew/[byteutils, endians2],
  # Internals
  ../../beacon_chain/spec/[datatypes, digest],
  # Test utilities
  ../testutil

const
  SpecDir = currentSourcePath.rsplit(DirSep, 1)[0] /
                  ".."/".."/"beacon_chain"/"spec"
  FixturesDir = currentSourcePath.rsplit(DirSep, 1)[0] / "fixtures"
  Config = FixturesDir/"tests-v0.10.1"/const_preset/"config.yaml"

type
  CheckedType = SomeInteger or Slot or Epoch
    # Only test numerical types, constants
    # defined for other type will get a placeholder low(int64) value

macro parseNumConsts(file: static string): untyped =
  ## Important: All const are assumed to be top-level
  ##            i.e. not hidden behind a "when" statement

  var constsToCheck: seq[(string, NimNode)]
    # We can't create a table directly and quote do it
    # Nim complains about the "data" field not being accessible

  let fileAST = parseStmt(slurp(file))
  for statement in fileAST:
    if statement.kind == nnkConstSection:
      for constDef in statement:
        if constDef.len == 0 or
           constDef[0].kind notin {nnkPragmaExpr, nnkPostfix}:
          # Comments in a const section need to be skipped.
          # And we only want exported constants.
          continue
        # Note: we assume that all const with a pragma are exported
        # 1. Simple statement
        #
        #   ConstDef
        #     Postfix
        #       Ident "*"
        #       Ident "HISTORICAL_ROOTS_LIMIT"
        #     Empty
        #     IntLit 16777216
        #
        # 2. with intdefine pragma
        #
        #   ConstDef
        #     PragmaExpr
        #       Postfix
        #         Ident "*"
        #         Ident "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT"
        #       Pragma
        #         Ident "intdefine"
        #     Empty
        #     IntLit 99
        let name = if constDef[0].kind == nnkPostfix: $constDef[0][1]
                   else: $constDef[0][0][1]

        # ConstsToCheck["HISTORICAL_ROOTS_LIMIT"} = uint64(16777216)
        # Put a placeholder values for strings
        let value = block:
          let node = constDef[2]
          quote do:
            when `node` is CheckedType:
              uint64(`node`)
            else:
              high(uint64)
        constsToCheck.add (name, value)

  result = quote do: `constsToCheck`

const
  datatypesConsts = @(parseNumConsts(SpecDir/"datatypes.nim"))
  mainnetConsts   = @(parseNumConsts(SpecDir/"presets"/"mainnet.nim"))
  minimalConsts   = @(parseNumConsts(SpecDir/"presets"/"minimal.nim"))

const IgnoreKeys = [
  # Ignore all non-numeric types
  "DEPOSIT_CONTRACT_ADDRESS"
]

func parseU32LEHex(hexValue: string): uint32 =
  ## Parse little-endian uint32 hex string
  result = uint32.fromBytesLE hexToByteArray[4](hexValue)

proc checkConfig() =
  let ConstsToCheck = toTable(
    when const_preset == "minimal":
      minimalConsts & datatypesConsts
    else:
      mainnetConsts & datatypesConsts
    )

  var yamlStream = openFileStream(Config)
  defer: yamlStream.close()
  var config = yamlStream.loadToJson()
  doAssert config.len == 1
  for constant, value in config[0]:
    timedTest &"{constant:<50}{value:<20}{preset()}":
      if constant in IgnoreKeys:
        echo &"        ↶↶ Skipping {constant}"
        continue
      if constant.startsWith("DOMAIN"):
        let domain = parseEnum[DomainType](constant)
        let value = parseU32LEHex(value.getStr())
        check: uint32(domain) == value
      elif constant == "GENESIS_FORK_VERSION":
        let value = parseU32LEHex(value.getStr())
        check: ConstsToCheck[constant] == value
      else:
        check: ConstsToCheck[constant] == value.getBiggestInt().uint64()

suite "Official - 0.10.1 - constants & config " & preset():
  checkConfig()
