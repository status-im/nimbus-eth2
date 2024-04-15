# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/typetraits,
  stew/byteutils,
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

  DistributedKeystoreInfo* = object
    threshold*: int
    pubkey*: ValidatorPubKey
    remotes*: seq[RemoteSignerInfo]

  RequestItemStatus* = object
    status*: string
    message*: string

  KeystoresAndSlashingProtection* = object
    keystores*: seq[Keystore]
    passwords*: seq[string]
    slashing_protection*: Opt[SPDIR]

  DeleteKeystoresBody* = object
    pubkeys*: seq[ValidatorPubKey]

  GetKeystoresResponse* = object
    data*: seq[KeystoreInfo]

  GetRemoteKeystoresResponse* = object
    data*: seq[RemoteKeystoreInfo]

  GetDistributedKeystoresResponse* = object
    data*: seq[DistributedKeystoreInfo]

  GetValidatorGasLimitResponse* = object
    pubkey*: ValidatorPubKey
    gas_limit*: uint64

  ImportRemoteKeystoresBody* = object
    remote_keys*: seq[RemoteKeystoreInfo]

  ImportDistributedKeystoresBody* = object
    remote_keys*: seq[DistributedKeystoreInfo]

  PostKeystoresResponse* = object
    data*: seq[RequestItemStatus]

  DeleteKeystoresResponse* = object
    data*: seq[RequestItemStatus]
    slashing_protection*: string

  RemoteKeystoreStatus* = object
    status*: KeystoreStatus
    message*: Opt[string]

  DeleteRemoteKeystoresResponse* = object
    data*: seq[RemoteKeystoreStatus]

  SetFeeRecipientRequest* = object
    ethaddress*: Eth1Address

  ListFeeRecipientResponse* = object
    pubkey*: ValidatorPubKey
    ethaddress*: Eth1Address

  ListGasLimitResponse* = object
    pubkey*: ValidatorPubKey
    gas_limit*: uint64

  SetGasLimitRequest* = object
    gas_limit*: uint64

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

  KeymanagerGenericError* = object
    message*: string

  GraffitiString* = distinct array[MAX_GRAFFITI_SIZE, byte]

  GraffitiResponse* = object
    pubkey*: ValidatorPubKey
    graffiti*: GraffitiString

  GetGraffitiResponse* = object
    data*: GraffitiResponse

  SetGraffitiRequest* = object
    graffiti*: GraffitiString

proc `<`*(x, y: KeystoreInfo | RemoteKeystoreInfo): bool =
  for a, b in fields(x, y):
    let c = cmp(a, b)
    if c < 0: return true
    if c > 0: return false
  return false

func init*(T: type GraffitiString,
           input: string): Result[GraffitiString, string] =
  var res: GraffitiString
  if len(input) > MAX_GRAFFITI_SIZE:
    return err("The graffiti value should be 32 characters or less")
  distinctBase(res)[0 ..< len(input)] = toBytes(input)
  ok(res)

func init*(T: type GraffitiBytes, input: GraffitiString): GraffitiBytes =
  var res: GraffitiBytes
  distinctBase(res)[0 ..< MAX_GRAFFITI_SIZE] =
    distinctBase(input)[0 ..< MAX_GRAFFITI_SIZE]
  res

func init*(T: type GraffitiString, input: GraffitiBytes): GraffitiString =
  var res: GraffitiString
  distinctBase(res)[0 ..< MAX_GRAFFITI_SIZE] =
    distinctBase(input)[0 ..< MAX_GRAFFITI_SIZE]
  res

func `$`*(input: GraffitiString): string =
  var res = newStringOfCap(MAX_GRAFFITI_SIZE)
  for ch in distinctBase(input):
    if ch != byte(0):
      res.add(char(ch))
  res
