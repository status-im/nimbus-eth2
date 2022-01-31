# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[tables, os, strutils, uri]
import chronos, chronicles, confutils,
       stew/[base10, results, io2], bearssl, blscurve
import ".."/validators/slashing_protection
import ".."/[conf, version, filepath, beacon_node]
import ".."/spec/[keystore, crypto]
import ".."/rpc/rest_utils
import ".."/validators/[keystore_management, validator_pool, validator_duties]
import ".."/spec/eth2_apis/rest_keymanager_types

export rest_utils, results

proc listLocalValidators*(node: BeaconNode): seq[KeystoreInfo] {.
     raises: [Defect].} =
  var validators: seq[KeystoreInfo]
  for item in node.attachedValidators[].items():
    if item.kind == ValidatorKind.Local:
      validators.add KeystoreInfo(
        validating_pubkey: item.pubkey,
        derivation_path: string(item.data.path),
        readonly: false
      )
  validators

proc listRemoteValidators*(node: BeaconNode): seq[RemoteKeystoreInfo] {.
     raises: [Defect].} =
  var validators: seq[RemoteKeystoreInfo]
  for item in node.attachedValidators[].items():
    if item.kind == ValidatorKind.Remote:
      validators.add RemoteKeystoreInfo(
        pubkey: item.pubkey,
        url: $item.data.remoteUrl
      )
  validators

proc checkAuthorization*(request: HttpRequestRef,
                         node: BeaconNode): Result[void, AuthorizationError] =
  let authorizations = request.headers.getList("authorization")
  if authorizations.len > 0:
    for authHeader in authorizations:
      let parts = authHeader.split(' ', maxsplit = 1)
      if parts.len == 2 and parts[0] == "Bearer":
        if parts[1] == node.keymanagerToken.get:
          return ok()
        else:
          return err incorrectToken
    return err missingBearerScheme
  else:
    return err noAuthorizationHeader

proc validateUri*(url: string): Result[Uri, cstring] =
  let surl = parseUri(url)
  if surl.scheme notin ["http", "https"]:
    return err("Incorrect URL scheme")
  if len(surl.hostname) == 0:
    return err("Empty URL hostname")
  ok(surl)

proc installKeymanagerHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/keymanager-APIs/#/Keymanager/ListKeys
  router.api(MethodGet, "/api/eth/v1/keystores") do () -> RestApiResponse:
    let authStatus = checkAuthorization(request, node)
    if authStatus.isErr():
      return RestApiResponse.jsonError(Http401, InvalidAuthorization,
                                       $authStatus.error())
    let response = GetKeystoresResponse(data: listLocalValidators(node))
    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Keymanager/ImportKeystores
  router.api(MethodPost, "/api/eth/v1/keystores") do (
      contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, node)
    if authStatus.isErr():
      return RestApiResponse.jsonError(Http401, InvalidAuthorization,
                                       $authStatus.error())
    let request =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(KeystoresAndSlashingProtection, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, InvalidKeystoreObjects,
                                           $dres.error())
        dres.get()

    let nodeSPDIR = toSPDIR(node.attachedValidators.slashingProtection)
    if nodeSPDIR.metadata.genesis_validators_root.Eth2Digest !=
       request.slashing_protection.metadata.genesis_validators_root.Eth2Digest:
      return RestApiResponse.jsonError(
        Http400,
        "The slashing protection database and imported file refer to " &
        "different blockchains.")

    var
      response: PostKeystoresResponse
      inclRes = inclSPDIR(node.attachedValidators.slashingProtection,
                          request.slashing_protection)
    if inclRes == siFailure:
      return RestApiResponse.jsonError(
        Http500,
        "Internal server error; Failed to import slashing protection data")

    for index, item in request.keystores.pairs():
      let res = importKeystore(node.attachedValidators[], node.network.rng[],
                               node.config, item, request.passwords[index])
      if res.isErr():
        let failure = res.error()
        case failure.status
        of AddValidatorStatus.failed:
          response.data.add(
            RequestItemStatus(status: $KeystoreStatus.error,
                              message: failure.message))
        of AddValidatorStatus.existingArtifacts:
          response.data.add(
            RequestItemStatus(status: $KeystoreStatus.duplicate))
      else:
        node.addLocalValidators([res.get()])
        response.data.add(
          RequestItemStatus(status: $KeystoreStatus.imported))

    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Keymanager/DeleteKeys
  router.api(MethodPost, "/api/eth/v1/keystores/delete") do (
      contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, node)
    if authStatus.isErr():
      return RestApiResponse.jsonError(Http401, InvalidAuthorization,
                                       $authStatus.error())
    let keys =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(DeleteKeystoresBody, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, InvalidValidatorPublicKey,
                                           $dres.error())
        dres.get().pubkeys

    var
      response: DeleteKeystoresResponse
      nodeSPDIR = toSPDIR(node.attachedValidators.slashingProtection)
      # Hash table to keep the removal status of all keys form request
      keysAndDeleteStatus = initTable[PubKeyBytes, RequestItemStatus]()

    response.slashing_protection.metadata = nodeSPDIR.metadata

    for index, key in keys.pairs():
      let
        res = removeValidator(node.attachedValidators[], node.config, key,
                              KeystoreKind.Local)
        pubkey = key.blob.PubKey0x.PubKeyBytes

      if res.isOk:
        case res.value()
        of RemoveValidatorStatus.deleted:
          keysAndDeleteStatus.add(
            pubkey, RequestItemStatus(status: $KeystoreStatus.deleted))

        # At first all keys with status missing directory after removal receive
        # status 'not_found'
        of RemoveValidatorStatus.notFound:
          keysAndDeleteStatus.add(
            pubkey, RequestItemStatus(status: $KeystoreStatus.notFound))
      else:
        keysAndDeleteStatus.add(pubkey,
                                RequestItemStatus(status: $KeystoreStatus.error,
                                                  message: $res.error()))

    # If we discover slashing protection data for a validator that was not
    # found, this means the validator was active in the past, so we must
    # respond with `not_active`:
    for validator in nodeSPDIR.data:
      keysAndDeleteStatus.withValue(validator.pubkey.PubKeyBytes, value) do:
        response.slashing_protection.data.add(validator)

        if value.status == $KeystoreStatus.notFound:
          value.status = $KeystoreStatus.notActive

    for index, key in keys.pairs():
      response.data.add(keysAndDeleteStatus[key.blob.PubKey0x.PubKeyBytes])

    return RestApiResponse.jsonResponsePlain(response)

  router.api(MethodGet, "/api/eth/v1/remotekey") do () -> RestApiResponse:
    let authStatus = checkAuthorization(request, node)
    if authStatus.isErr():
      return RestApiResponse.jsonError(Http401, InvalidAuthorization,
                                       $authStatus.error())
    let response = GetRemoteKeystoresResponse(data: listRemoteValidators(node))
    return RestApiResponse.jsonResponsePlain(response)

  router.api(MethodPost, "/api/eth/v1/remotekey") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, node)
    if authStatus.isErr():
      return RestApiResponse.jsonError(Http401, InvalidAuthorization,
                                       $authStatus.error())
    let keys =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(seq[RemoteKeystoreInfo], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, InvalidKeystoreObjects,
                                           $dres.error())
        dres.get()

    var response: PostKeystoresResponse

    for index, key in keys.pairs():
      let durl = validateUri(key.url)
      if durl.isErr():
        response.data.add(RequestItemStatus(status: $KeystoreStatus.error,
                                            message: $durl.error()))
      else:
        let keystore = RemoteKeystore(
          version: 1'u64, remoteType: RemoteSignerType.Web3Signer,
          pubkey: key.pubkey, remote: durl.get()
        )
        let res = importKeystore(node.attachedValidators[], node.config,
                                 keystore)
        if res.isErr():
          case res.error().status
          of AddValidatorStatus.failed:
            response.data.add(
              RequestItemStatus(status: $KeystoreStatus.error,
                                message: $res.error().message))
          of AddValidatorStatus.existingArtifacts:
            response.data.add(
              RequestItemStatus(status: $KeystoreStatus.duplicate))
        else:
          node.addRemoteValidators([res.get()])
          response.data.add(
            RequestItemStatus(status: $KeystoreStatus.imported))

    return RestApiResponse.jsonResponsePlain(response)

  router.api(MethodDelete, "/api/eth/v1/remotekey") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, node)
    if authStatus.isErr():
      return RestApiResponse.jsonError(Http401, InvalidAuthorization,
                                       $authStatus.error())

  router.redirect(
    MethodGet,
    "/eth/v1/keystores",
    "/api/eth/v1/keystores")

  router.redirect(
    MethodPost,
    "/eth/v1/keystores",
    "/api/eth/v1/keystores")

  router.redirect(
    MethodPost,
    "/eth/v1/keystores/delete",
    "/api/eth/v1/keystores/delete")

  router.redirect(
    MethodGet,
    "/eth/v1/remotekey",
    "/api/eth/v1/remotekey")

  router.redirect(
    MethodPost,
    "/eth/v1/remotekey",
    "/api/eth/v1/remotekey")

  router.redirect(
    MethodDelete,
    "/eth/v1/remotekey",
    "/api/eth/v1/remotekey")
