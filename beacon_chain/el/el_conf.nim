# beacon_chain
# Copyright (c) 2023-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[options, uri],
  results, chronicles, confutils,
  confutils/toml/defs as confTomlDefs,
  json_serialization, # for logging
  toml_serialization, toml_serialization/lexer,
  toml_serialization/std/net as confTomlNet,
  toml_serialization/std/uri as confTomlUri,
  ../spec/engine_authentication

from std/strutils import toLowerAscii, startsWith

export
  toml_serialization, confTomlDefs, confTomlNet, confTomlUri

type
  EngineApiUrl* = object
    url: string
    jwtSecret: Opt[JwtSharedKey]

  EngineApiUrlConfigValue* = object
    url*: string # TODO: Use the URI type here
    jwtSecret* {.serializedFieldName: "jwt-secret".}: Option[string]
    jwtSecretFile* {.serializedFieldName: "jwt-secret-file".}: Option[InputFile]

const
  # https://github.com/ethereum/execution-apis/pull/302
  defaultJwtSecret = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"

chronicles.formatIt EngineApiUrl:
  it.url

proc init*(T: type EngineApiUrl,
           url: string,
           jwtSecret = Opt.none JwtSharedKey): T =
  T(url: url, jwtSecret: jwtSecret)

func url*(engineUrl: EngineApiUrl): string =
  engineUrl.url

func jwtSecret*(engineUrl: EngineApiUrl): Opt[JwtSharedKey] =
  engineUrl.jwtSecret

proc parseCmdArg*(T: type EngineApiUrlConfigValue, input: string): T
                 {.raises: [ValueError].} =
  var
    uri = parseUri(input)
    jwtSecret: Option[string]
    jwtSecretFile: Option[InputFile]

  if uri.anchor != "":
    for key, value in decodeQuery(uri.anchor):
      case key
      of "jwtSecret", "jwt-secret":
        jwtSecret = some value
      of "jwtSecretFile", "jwt-secret-file":
        jwtSecretFile = some InputFile.parseCmdArg(value)
      else:
        raise newException(ValueError, "'" & key & "' is not a recognized Engine URL property")
    uri.anchor = ""

  EngineApiUrlConfigValue(
    url: $uri,
    jwtSecret: jwtSecret,
    jwtSecretFile: jwtSecretFile)

proc readValue*(reader: var TomlReader, value: var EngineApiUrlConfigValue)
               {.raises: [SerializationError, IOError].} =
  if reader.lex.readable and reader.lex.peekChar in ['\'', '"']:
    # If the input is a string, we'll reuse the command-line parsing logic
    value = try: parseCmdArg(EngineApiUrlConfigValue, reader.readValue(string))
            except ValueError as err:
              reader.lex.raiseUnexpectedValue("Valid Engine API URL expected: " & err.msg)
  else:
    # Else, we'll use the standard object-serializer in TOML
    toml_serialization.readValue(reader, value)

proc fixupWeb3Urls*(web3Url: var string) =
  var normalizedUrl = toLowerAscii(web3Url)
  if not (normalizedUrl.startsWith("https://") or
          normalizedUrl.startsWith("http://") or
          normalizedUrl.startsWith("wss://") or
          normalizedUrl.startsWith("ws://")):
    warn "The Web3 URL does not specify a protocol. Assuming a WebSocket server", web3Url
    web3Url = "ws://" & web3Url

func getDefaultEngineApiUrl*(x: Option[InputFile]): EngineApiUrlConfigValue =
  EngineApiUrlConfigValue(
    url: "http://127.0.0.1:8551",
    jwtSecret:
      if x.isSome:
        # Provided by toFinalUrl() and toFinalEngineApiUrls(); otherwise, if
        # defaultJwtSecret is specified here, no-EL-URL-specified cases when
        # JWT secret is specified get stuck with defaultJwtSecret regardless
        # of being otherwise overridden.
        none string
      else:
        some defaultJwtSecret)

proc toFinalUrl*(confValue: EngineApiUrlConfigValue,
                 confJwtSecret: Opt[JwtSharedKey]): Result[EngineApiUrl, cstring] =
  if confValue.jwtSecret.isSome and confValue.jwtSecretFile.isSome:
    return err "The options `jwtSecret` and `jwtSecretFile` should not be specified together"

  let jwtSecret = if confValue.jwtSecret.isSome:
    Opt.some(? parseJwtSharedKey(confValue.jwtSecret.get))
  elif confValue.jwtSecretFile.isSome:
    Opt.some(? loadJwtSecretFile(confValue.jwtSecretFile.get))
  else:
    confJwtSecret

  var url = confValue.url
  fixupWeb3Urls(url)

  ok EngineApiUrl.init(
    url = url,
    jwtSecret = jwtSecret)

proc loadJwtSecret*(jwtSecret: Opt[InputFile]): Opt[JwtSharedKey] =
  if jwtSecret.isSome:
    let res = loadJwtSecretFile(jwtSecret.get)
    if res.isOk:
      Opt.some res.value
    else:
      fatal "Failed to load JWT secret file", err = res.error
      quit 1
  else:
    Opt.none JwtSharedKey

proc toFinalEngineApiUrls*(elUrls: seq[EngineApiUrlConfigValue],
                           confJwtSecret: Opt[InputFile]): seq[EngineApiUrl] =
  let jwtSecret = loadJwtSecret confJwtSecret

  for elUrl in elUrls:
    let engineApiUrl = elUrl.toFinalUrl(jwtSecret).valueOr:
      fatal "Invalid EL configuration", err = error
      quit 1
    result.add engineApiUrl
