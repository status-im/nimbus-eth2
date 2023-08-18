# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

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

proc raiseKeymanagerGenericError*(resp: RestPlainResponse) {.
     noreturn, raises: [RestError, Defect].} =
  let error =
    block:
      let res = decodeBytes(KeymanagerGenericError, resp.data, resp.contentType)
      if res.isErr():
        let msg = "Incorrect response error format (" & $resp.status &
                  ") [" & $res.error() & "]"
        raise newException(RestError, msg)
      res.get()
  let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
  raise newException(RestError, msg)

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
     rest, endpoint: "/eth/v1/keystores",
     meth: MethodDelete.}
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
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc listRemoteKeysPlain*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekeys",
     meth: MethodGet.}
  ## https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ListRemoteKeys

proc importRemoteKeysPlain*(body: ImportRemoteKeystoresBody
                           ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekeys",
     meth: MethodPost.}
  ## https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ImportRemoteKeys

proc deleteRemoteKeysPlain*(body: DeleteKeystoresBody): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekeys",
     meth: MethodDelete.}
  ## https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/DeleteRemoteKeys

proc listFeeRecipientPlain*(pubkey: ValidatorPubKey): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/{pubkey}/feerecipient",
     meth: MethodGet.}
  ## https://ethereum.github.io/keymanager-APIs/#/Fee%20Recipient/ListFeeRecipient

proc setFeeRecipientPlain*(pubkey: ValidatorPubKey,
                           body: SetFeeRecipientRequest): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/{pubkey}/feerecipient",
     meth: MethodPost.}
  ## https://ethereum.github.io/keymanager-APIs/#/Fee%20Recipient/SetFeeRecipient

proc deleteFeeRecipientPlain*(pubkey: ValidatorPubKey,
                              body: EmptyBody): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/{pubkey}/feerecipient",
     meth: MethodDelete.}
  ## https://ethereum.github.io/keymanager-APIs/#/Fee%20Recipient/DeleteFeeRecipient

proc listGasLimitPlain*(pubkey: ValidatorPubKey): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/{pubkey}/gas_limit",
     meth: MethodGet.}
  ## https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit

proc setGasLimitPlain*(pubkey: ValidatorPubKey,
                       body: SetGasLimitRequest): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/{pubkey}/gas_limit",
     meth: MethodPost.}
  ## https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit/setGasLimit

proc deleteGasLimitPlain *(pubkey: ValidatorPubKey,
                           body: EmptyBody): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/{pubkey}/gas_limit",
     meth: MethodDelete.}
  ## https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit/deleteGasLimit

proc listRemoteDistributedKeysPlain*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekeys/distributed",
     meth: MethodGet.}

proc importRemoteDistributedKeysPlain*(body: ImportDistributedKeystoresBody
                           ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekeys/distributed",
     meth: MethodPost.}

proc deleteRemoteDistributedKeysPlain*(body: DeleteKeystoresBody): RestPlainResponse {.
     rest, endpoint: "/eth/v1/remotekeys/distributed",
     meth: MethodDelete.}

proc listRemoteKeys*(client: RestClientRef,
                     token: string): Future[GetRemoteKeystoresResponse] {.
     async.} =
  let resp = await client.listRemoteKeysPlain(
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 200:
    let res = decodeBytes(GetRemoteKeystoresResponse,
                          resp.data,
                          resp.contentType)
    if res.isErr():
      raise newException(RestError, $res.error())
    return res.get()
  of 401, 403, 500:
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc listFeeRecipient*(client: RestClientRef,
                       pubkey: ValidatorPubKey,
                       token: string): Future[Eth1Address] {.async.} =
  let resp = await client.listFeeRecipientPlain(
    pubkey,
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 200:
    let res = decodeBytes(DataEnclosedObject[ListFeeRecipientResponse],
                          resp.data,
                          resp.contentType)
    if res.isErr:
      raise newException(RestError, $res.error)
    return res.get.data.ethaddress
  of 401, 403, 404, 500:
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc setFeeRecipient*(client: RestClientRef,
                      pubkey: ValidatorPubKey,
                      feeRecipient: Eth1Address,
                      token: string) {.async.} =
  let resp = await client.setFeeRecipientPlain(
    pubkey,
    SetFeeRecipientRequest(ethaddress: feeRecipient),
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 202:
    discard
  of 400, 401, 403, 404, 500:
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc deleteFeeRecipient*(client: RestClientRef,
                         pubkey: ValidatorPubKey,
                         token: string) {.async.} =
  let resp = await client.deleteFeeRecipientPlain(
    pubkey,
    EmptyBody(),
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 204:
    discard
  of 401, 403, 404, 500:
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc listGasLimit*(client: RestClientRef,
                  pubkey: ValidatorPubKey,
                  token: string): Future[uint64] {.async.} =
  let resp = await client.listGasLimitPlain(
    pubkey,
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 200:
    let res = decodeBytes(DataEnclosedObject[ListGasLimitResponse],
                          resp.data,
                          resp.contentType)
    if res.isErr:
      raise newException(RestError, $res.error)
    return res.get.data.gas_limit
  of 400, 401, 403, 404, 500:
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc setGasLimit*(client: RestClientRef,
                  pubkey: ValidatorPubKey,
                  gasLimit: uint64,
                  token: string) {.async.} =
  let resp = await client.setGasLimitPlain(
    pubkey,
    SetGasLimitRequest(gasLimit: gasLimit),
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 202:
    discard
  of 400, 401, 403, 404, 500:
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)

proc deleteGasLimit*(client: RestClientRef,
                     pubkey: ValidatorPubKey,
                     token: string) {.async.} =
  let resp = await client.deleteGasLimitPlain(
    pubkey,
    EmptyBody(),
    extraHeaders = @[("Authorization", "Bearer " & token)])

  case resp.status:
  of 204:
    discard
  of 400, 401, 403, 404, 500:
    raiseKeymanagerGenericError(resp)
  else:
    raiseUnknownStatusError(resp)
