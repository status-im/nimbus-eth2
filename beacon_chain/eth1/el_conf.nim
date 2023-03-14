import
  std/[options, strutils, uri],
  stew/results, chronicles, confutils,
  confutils/toml/defs as confTomlDefs,
  confutils/toml/std/net as confTomlNet,
  confutils/toml/std/uri as confTomlUri,
  json_serialization, # for logging
  toml_serialization, toml_serialization/lexer,
  ../spec/engine_authentication

export
  toml_serialization, confTomlDefs, confTomlNet, confTomlUri

type
  EngineApiRole* = enum
    DepositSyncing = "sync-deposits"
    BlockValidation = "validate-blocks"
    BlockProduction = "produce-blocks"

  EngineApiRoles* = set[EngineApiRole]

  EngineApiUrl* = object
    url: string
    jwtSecret: Option[seq[byte]]
    roles: EngineApiRoles

  EngineApiUrlConfigValue* = object
    url*: string # TODO: Use the URI type here
    jwtSecret* {.serializedFieldName: "jwt-secret".}: Option[string]
    jwtSecretFile* {.serializedFieldName: "jwt-secret-file".}: Option[InputFile]
    roles*: Option[EngineApiRoles]

const
  defaultEngineApiRoles* = { DepositSyncing, BlockValidation, BlockProduction }

  # https://github.com/ethereum/execution-apis/pull/302
  defaultJwtSecret* = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"

  defaultEngineApiUrl* = EngineApiUrlConfigValue(
    url: "http://127.0.0.1:8551",
    jwtSecret: some defaultJwtSecret)

chronicles.formatIt EngineApiUrl:
  it.url

proc init*(T: type EngineApiUrl,
           url: string,
           jwtSecret = none seq[byte],
           roles = defaultEngineApiRoles): T =
  T(url: url, jwtSecret: jwtSecret, roles: roles)

func url*(engineUrl: EngineApiUrl): string =
  engineUrl.url

func jwtSecret*(engineUrl: EngineApiUrl): Option[seq[byte]] =
  engineUrl.jwtSecret

func roles*(engineUrl: EngineApiUrl): EngineApiRoles =
  engineUrl.roles

func unknownRoleMsg(role: string): string =
  "'" & role & "' is not a valid EL function"

template raiseError(reader: var TomlReader, msg: string) =
  raiseTomlErr(reader.lex, msg)

template raiseError(reader: var JsonReader, msg: string) =
  raiseTomlErr(reader.lex, msg)

proc readValue*(reader: var TomlReader, value: var EngineApiRoles)
               {.raises: [Defect, SerializationError, IOError].} =
  let roles = reader.readValue seq[string]
  if roles.len == 0:
    reader.raiseError "At least one role should be provided"
  for role in roles:
    case role.toLowerAscii
    of $DepositSyncing:
      value.incl DepositSyncing
    of $BlockValidation:
      value.incl BlockValidation
    of $BlockProduction:
      value.incl BlockProduction
    else:
      reader.raiseError(unknownRoleMsg role)

proc writeValue*(writer: var JsonWriter, roles: EngineApiRoles)
                {.raises: [Defect, SerializationError, IOError].} =
  var strRoles: seq[string]

  for role in EngineApiRole:
    if role in roles: strRoles.add $role

  writer.writeValue strRoles

proc parseCmdArg*(T: type EngineApiUrlConfigValue, input: string): T
                 {.raises: [ValueError, Defect].} =
  var
    uri = parseUri(input)
    jwtSecret: Option[string]
    jwtSecretFile: Option[InputFile]
    roles: Option[EngineApiRoles]

  if uri.anchor != "":
    for key, value in decodeQuery(uri.anchor):
      case key
      of "jwtSecret", "jwt-secret":
        jwtSecret = some value
      of "jwtSecretFile", "jwt-secret-file":
        jwtSecretFile = some InputFile.parseCmdArg(value)
      of "roles":
        var uriRoles: EngineApiRoles = {}
        for role in split(value, ","):
          case role.toLowerAscii
          of $DepositSyncing:
            uriRoles.incl DepositSyncing
          of $BlockValidation:
            uriRoles.incl BlockValidation
          of $BlockProduction:
            uriRoles.incl BlockProduction
          else:
            raise newException(ValueError, unknownRoleMsg role)
        if uriRoles == {}:
          raise newException(ValueError, "The list of roles should not be empty")
        roles = some uriRoles
      else:
        raise newException(ValueError, "'" & key & "' is not a recognized Engine URL property")
    uri.anchor = ""

  EngineApiUrlConfigValue(
    url: $uri,
    jwtSecret: jwtSecret,
    jwtSecretFile: jwtSecretFile,
    roles: roles)

proc readValue*(reader: var TomlReader, value: var EngineApiUrlConfigValue)
               {.raises: [Defect, SerializationError, IOError].} =
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

proc toFinalUrl*(confValue: EngineApiUrlConfigValue,
                 confJwtSecret: Option[seq[byte]]): Result[EngineApiUrl, cstring] =
  if confValue.jwtSecret.isSome and confValue.jwtSecretFile.isSome:
    return err "The options `jwtSecret` and `jwtSecretFile` should not be specified together"

  let jwtSecret = if confValue.jwtSecret.isSome:
    some(? parseJwtTokenValue(confValue.jwtSecret.get))
  elif confValue.jwtSecretFile.isSome:
    some(? loadJwtSecretFile(confValue.jwtSecretFile.get))
  else:
    confJwtSecret

  var url = confValue.url
  fixupWeb3Urls(url)

  ok EngineApiUrl.init(
    url = url,
    jwtSecret = jwtSecret,
    roles = confValue.roles.get(defaultEngineApiRoles))

proc loadJwtSecret*(jwtSecret: Option[InputFile]): Option[seq[byte]] =
  if jwtSecret.isSome:
    let res = loadJwtSecretFile(jwtSecret.get)
    if res.isOk:
      some res.value
    else:
      fatal "Failed to load JWT secret file", err = res.error
      quit 1
  else:
    none seq[byte]

proc toFinalEngineApiUrls*(elUrls: seq[EngineApiUrlConfigValue],
                           confJwtSecret: Option[InputFile]): seq[EngineApiUrl] =
  let jwtSecret = loadJwtSecret confJwtSecret

  for elUrl in elUrls:
    let engineApiUrl = elUrl.toFinalUrl(jwtSecret).valueOr:
      fatal "Invalid EL configuration", err = error
      quit 1
    result.add engineApiUrl
