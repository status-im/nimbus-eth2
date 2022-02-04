# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, presto/client, chronicles,
  ".."/".."/validators/slashing_protection_common,
  ".."/datatypes/[phase0, altair],
  ".."/[helpers, forks, keystore, eth2_ssz_serialization],
  "."/[rest_types, rest_common, rest_keymanager_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization,
       rest_keymanager_types

UUID.serializesAsBaseIn RestJson
KeyPath.serializesAsBaseIn RestJson
WalletName.serializesAsBaseIn RestJson

proc listKeysPlain*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/keystores",
     meth: MethodGet.}
  ## https://ethereum.github.io/keymanager-APIs/#/Keymanager/ListKeys

proc importKeystoresPlain*(body: KeystoresAndSlashingProtection
                          ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/keystores",
     meth: MethodPost.}
  ## https://ethereum.github.io/keymanager-APIs/#/Keymanager/ImportKeystores

proc deleteKeysPlain*(body: DeleteKeystoresBody): RestPlainResponse {.
     rest, endpoint: "/eth/v1/keystores/delete",
     meth: MethodPost.}
  ## https://ethereum.github.io/keymanager-APIs/#/Keymanager/DeleteKeys

proc listKeys*(client: RestClientRef,
               token: string): Future[GetKeystoresResponse] {.async.} =
  let resp = await client.listKeysPlain(
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 200:
    let keystoresRes = decodeBytes(
      GetKeystoresResponse, resp.data, resp.contentType)
    if keystoresRes.isErr():
      raise newException(RestError, $keystoresRes.error)
    return keystoresRes.get()
  of 401, 403, 500:
    raiseGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc listRemoteKeysPlain*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekey",
     meth: MethodGet.}
  ## https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ListRemoteKeys

proc importRemoteKeysPlain*(body: ImportRemoteKeystoresBody
                           ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekey",
     meth: MethodPost.}
  ## https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ImportRemoteKeys

proc deleteRemoteKeysPlain*(body: DeleteKeystoresBody): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekey",
     meth: MethodDelete.}
  ## https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/DeleteRemoteKeys

proc listRemoteKeys*(client: RestClientRef,
                     token: string): Future[GetRemoteKeystoresResponse] {.
     async.} =
  let resp = await client.listRemoteKeysPlain(
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 200:
    let res = decodeBytes(GetRemoteKeystoresResponse, resp.data,
                          resp.contentType)
    if res.isErr():
      raise newException(RestError, $res.error())
    return res.get()
  of 401, 403, 500:
    raiseGenericError(resp)
  else:
    raiseUnknownStatusError(resp)
