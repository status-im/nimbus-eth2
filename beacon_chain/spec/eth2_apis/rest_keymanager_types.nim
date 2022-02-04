import
  std/[tables, strutils, uri],
  ".."/[crypto, keystore],
  ../../validators/slashing_protection_common

type
  KeystoreInfo* = object
    validating_pubkey*: ValidatorPubKey
    derivation_path*: string
    readonly*: bool

  RemoteKeystoreInfo* = object
    pubkey*: ValidatorPubKey
    url*: HttpHostUri

  RequestItemStatus* = object
    status*: string
    message*: string

  KeystoresAndSlashingProtection* = object
    keystores*: seq[Keystore]
    passwords*: seq[string]
    slashing_protection*: Option[SPDIR]

  DeleteKeystoresBody* = object
    pubkeys*: seq[ValidatorPubKey]

  GetKeystoresResponse* = object
    data*: seq[KeystoreInfo]

  GetRemoteKeystoresResponse* = object
    data*: seq[RemoteKeystoreInfo]

  ImportRemoteKeystoresBody* = object
    remote_keys*: seq[RemoteKeystoreInfo]

  PostKeystoresResponse* = object
    data*: seq[RequestItemStatus]

  DeleteKeystoresResponse* = object
    data*: seq[RequestItemStatus]
    slashing_protection*: SPDIR

  RemoteKeystoreStatus* = object
    status*: KeystoreStatus
    message*: Option[string]

  DeleteRemoteKeystoresResponse* = object
    data*: seq[RemoteKeystoreStatus]

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

proc `<`*(x, y: KeystoreInfo | RemoteKeystoreInfo): bool =
  for a, b in fields(x, y):
    var c = cmp(a, b)
    if c < 0: return true
    if c > 0: return false
  return false
