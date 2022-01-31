import
  std/[tables, strutils],
  ".."/[crypto, keystore],
  ../../validators/slashing_protection_common

type
  KeystoreInfo* = object
    validating_pubkey*: ValidatorPubKey
    derivation_path*: string
    readonly*: bool

  RemoteKeystoreInfo* = object
    pubkey*: ValidatorPubKey
    url*: string

  RequestItemStatus* = object
    status*: string
    message*: string

  KeystoresAndSlashingProtection* = object
    keystores*: seq[Keystore]
    passwords*: seq[string]
    slashing_protection*: SPDIR

  DeleteKeystoresBody* = object
    pubkeys*: seq[ValidatorPubKey]

  GetKeystoresResponse* = object
    data*: seq[KeystoreInfo]

  GetRemoteKeystoresResponse* = object
    data*: seq[RemoteKeystoreInfo]

  PostKeystoresResponse* = object
    data*: seq[RequestItemStatus]

  DeleteKeystoresResponse* = object
    data*: seq[RequestItemStatus]
    slashing_protection*: SPDIR

  KeystoreStatus* = enum
    error =  "error"
    notActive = "not_active"
    notFound = "not_found"
    deleted = "deleted"
    duplicate = "duplicate"
    imported = "imported"

  AuthorizationError* = enum
    noAuthorizationHeader = "Missing Authorization Header"
    missingBearerScheme = "Bearer Authentication is not included in request"
    incorrectToken = "Authentication token is incorrect"

proc `<`*(x, y: KeystoreInfo): bool =
  for a, b in fields(x, y):
    var c = cmp(a, b)
    if c < 0: return true
    if c > 0: return false
  return false
