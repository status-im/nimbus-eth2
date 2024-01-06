# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# NOTE: This module has been used in both `beacon_node` and `validator_client`,
# please keep imports clear of `rest_utils` or any other module which imports
# beacon node's specific networking code.

import std/[tables, strutils, uri]
import chronos, chronicles, confutils,
       stew/[base10, results, io2], blscurve, presto
import ".."/spec/[keystore, crypto]
import ".."/spec/eth2_apis/rest_keymanager_types
import ".."/validators/[slashing_protection, keystore_management,
                        validator_pool]
import ".."/rpc/rest_constants

export rest_constants, results

func validateKeymanagerApiQueries*(key: string, value: string): int =
  # There are no queries to validate
  return 0

proc listLocalValidators*(validatorPool: ValidatorPool): seq[KeystoreInfo] {.
     raises: [].} =
  var validators: seq[KeystoreInfo]
  for item in validatorPool:
    if item.kind == ValidatorKind.Local:
      validators.add KeystoreInfo(
        validating_pubkey: item.pubkey,
        derivation_path: string(item.data.path),
        readonly: false
      )
  validators

proc listRemoteValidators*(
       validatorPool: ValidatorPool): seq[RemoteKeystoreInfo] {.
     raises: [].} =
  var validators: seq[RemoteKeystoreInfo]
  for item in validatorPool:
    if item.kind == ValidatorKind.Remote and item.data.remotes.len == 1:
      validators.add RemoteKeystoreInfo(
        pubkey: item.pubkey,
        url: HttpHostUri(item.data.remotes[0].url)
      )
  validators

proc listRemoteDistributedValidators*(
       validatorPool: ValidatorPool): seq[DistributedKeystoreInfo] {.
     raises: [].} =
  var validators: seq[DistributedKeystoreInfo]
  for item in validatorPool:
    if item.kind == ValidatorKind.Remote and item.data.remotes.len > 1:
      validators.add DistributedKeystoreInfo(
        pubkey: item.pubkey,
        remotes: item.data.remotes
      )
  validators

proc keymanagerApiError(status: HttpCode, msg: string): RestApiResponse =
  let data =
    block:
      var default: string
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("message", msg)
        writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.error(status, data, "application/json")

proc checkAuthorization*(
       request: HttpRequestRef,
       host: KeymanagerHost): Result[void, AuthorizationError] =
  let authorizations = request.headers.getList("authorization")
  if authorizations.len > 0:
    for authHeader in authorizations:
      let parts = authHeader.split(' ', maxsplit = 1)
      if parts.len == 2 and parts[0] == "Bearer":
        if parts[1] == host.keymanagerToken:
          return ok()
        else:
          return err incorrectToken
    return err missingBearerScheme
  else:
    return err noAuthorizationHeader

proc authErrorResponse(error: AuthorizationError): RestApiResponse =
  let status = case error:
    of missingBearerScheme, noAuthorizationHeader:
      Http401
    of incorrectToken:
      Http403

  keymanagerApiError(status, InvalidAuthorizationError)

proc validateUri*(url: string): Result[Uri, cstring] =
  let surl = parseUri(url)
  if surl.scheme notin ["http", "https"]:
    return err("Incorrect URL scheme")
  if len(surl.hostname) == 0:
    return err("Empty URL hostname")
  ok(surl)

proc handleRemoveValidatorReq(host: KeymanagerHost,
                              key: ValidatorPubKey): RemoteKeystoreStatus =
    let res = removeValidator(host.validatorPool[],
                              host.validatorsDir, host.secretsDir,
                              key, KeystoreKind.Remote)
    if res.isOk:
      case res.value()
      of RemoveValidatorStatus.deleted:
        return RemoteKeystoreStatus(status: KeystoreStatus.deleted)
      of RemoveValidatorStatus.notFound:
        return RemoteKeystoreStatus(status: KeystoreStatus.notFound)
    else:
      return RemoteKeystoreStatus(status: KeystoreStatus.error,
                                  message: Opt.some($res.error()))

proc handleAddRemoteValidatorReq(host: KeymanagerHost,
                                 keystore: RemoteKeystore): RequestItemStatus =
  let res = importKeystore(host.validatorPool[], host.validatorsDir, keystore)
  if res.isOk:
    host.addValidator(
      res.get(), host.getValidatorWithdrawalAddress(keystore.pubkey))

    RequestItemStatus(status: $KeystoreStatus.imported)
  else:
    case res.error().status
    of AddValidatorStatus.failed:
      RequestItemStatus(status: $KeystoreStatus.error,
                        message: $res.error().message)
    of AddValidatorStatus.existingArtifacts:
      RequestItemStatus(status: $KeystoreStatus.duplicate)

proc installKeymanagerHandlers*(router: var RestRouter, host: KeymanagerHost) =
  # https://ethereum.github.io/keymanager-APIs/#/Keymanager/ListKeys
  router.api(MethodGet, "/eth/v1/keystores") do () -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let response = GetKeystoresResponse(
      data: listLocalValidators(host.validatorPool[]))
    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Keymanager/ImportKeystores
  router.api(MethodPost, "/eth/v1/keystores") do (
      contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let request =
      block:
        if contentBody.isNone():
          return keymanagerApiError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(KeystoresAndSlashingProtection, contentBody.get())
        if dres.isErr():
          return keymanagerApiError(Http400, InvalidKeystoreObjects)
        dres.get()

    if request.slashing_protection.isSome():
      let slashing_protection = request.slashing_protection.get()
      let nodeSPDIR = toSPDIR(host.validatorPool[].slashingProtection)
      if nodeSPDIR.metadata.genesis_validators_root.Eth2Digest !=
         slashing_protection.metadata.genesis_validators_root.Eth2Digest:
        return keymanagerApiError(Http400,
          "The slashing protection database and imported file refer to " &
          "different blockchains.")
      let res = inclSPDIR(host.validatorPool[].slashingProtection,
                          slashing_protection)
      if res == siFailure:
        return keymanagerApiError(Http500,
          "Internal server error; Failed to import slashing protection data")

    var response: PostKeystoresResponse

    for index, item in request.keystores:
      let res = importKeystore(host.validatorPool[], host.rng[],
                               host.validatorsDir, host.secretsDir,
                               item, request.passwords[index],
                               host.keystoreCache)
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
        host.addValidator(
          res.get(), host.getValidatorWithdrawalAddress(res.get.pubkey))
        response.data.add(
          RequestItemStatus(status: $KeystoreStatus.imported))

    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Keymanager/DeleteKeys
  router.api(MethodDelete, "/eth/v1/keystores") do (
      contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let keys =
      block:
        if contentBody.isNone():
          return keymanagerApiError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(DeleteKeystoresBody, contentBody.get())
        if dres.isErr():
          return keymanagerApiError(Http400, InvalidValidatorPublicKey)
        dres.get().pubkeys

    var
      response: DeleteKeystoresResponse
      nodeSPDIR = toSPDIR(host.validatorPool[].slashingProtection)
      # Hash table to keep the removal status of all keys form request
      keysAndDeleteStatus = initTable[PubKeyBytes, RequestItemStatus]()
      responseSPDIR: SPDIR

    responseSPDIR.metadata = nodeSPDIR.metadata

    for index, key in keys:
      let
        res = removeValidator(host.validatorPool[],
                              host.validatorsDir, host.secretsDir,
                              key, KeystoreKind.Local)
        pubkey = key.blob.PubKey0x.PubKeyBytes

      if res.isOk:
        case res.value()
        of RemoveValidatorStatus.deleted:
          keysAndDeleteStatus[pubkey] =
            RequestItemStatus(status: $KeystoreStatus.deleted)

        # At first all keys with status missing directory after removal receive
        # status 'not_found'
        of RemoveValidatorStatus.notFound:
          keysAndDeleteStatus[pubkey] =
            RequestItemStatus(status: $KeystoreStatus.notFound)
      else:
        keysAndDeleteStatus[pubkey] =
          RequestItemStatus(status: $KeystoreStatus.error,
                            message: $res.error())

    # If we discover slashing protection data for a validator that was not
    # found, this means the validator was active in the past, so we must
    # respond with `not_active`:
    for validator in nodeSPDIR.data:
      keysAndDeleteStatus.withValue(validator.pubkey.PubKeyBytes,
                                    foundKeystore) do:
        responseSPDIR.data.add(validator)

        if foundKeystore.status == $KeystoreStatus.notFound:
          foundKeystore.status = $KeystoreStatus.notActive

    for index, key in keys:
      response.data.add(keysAndDeleteStatus[key.blob.PubKey0x.PubKeyBytes])

    response.slashing_protection = RestJson.encode(responseSPDIR)

    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ListRemoteKeys
  router.api(MethodGet, "/eth/v1/remotekeys") do () -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let response = GetRemoteKeystoresResponse(
      data: listRemoteValidators(host.validatorPool[]))
    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ImportRemoteKeys
  router.api(MethodPost, "/eth/v1/remotekeys") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let keys =
      block:
        if contentBody.isNone():
          return keymanagerApiError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(ImportRemoteKeystoresBody, contentBody.get())
        if dres.isErr():
          return keymanagerApiError(Http400, InvalidKeystoreObjects)
        dres.get().remote_keys

    var response: PostKeystoresResponse

    for index, key in keys:
      let
        remoteInfo = RemoteSignerInfo(
          url: key.url,
          pubkey: key.pubkey,
          id: 0)
        keystore = RemoteKeystore(
          version: 1'u64, remoteType: RemoteSignerType.Web3Signer,
          pubkey: key.pubkey, remotes: @[remoteInfo])

      response.data.add handleAddRemoteValidatorReq(host, keystore)

    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/DeleteRemoteKeys
  router.api(MethodDelete, "/eth/v1/remotekeys") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let keys =
      block:
        if contentBody.isNone():
          return keymanagerApiError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(DeleteKeystoresBody, contentBody.get())
        if dres.isErr():
          return keymanagerApiError(Http400, InvalidValidatorPublicKey)
        dres.get().pubkeys

    var response: DeleteRemoteKeystoresResponse
    for index, key in keys:
      response.data.add handleRemoveValidatorReq(host, key)
    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/#/Fee%20Recipient/ListFeeRecipient
  router.api(MethodGet, "/eth/v1/validator/{pubkey}/feerecipient") do (
             pubkey: ValidatorPubKey) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let
      pubkey = pubkey.valueOr:
        return keymanagerApiError(Http400, InvalidValidatorPublicKey)
      perValidatorDefaultFeeRecipient = getPerValidatorDefaultFeeRecipient(
        host.defaultFeeRecipient,
        host.getValidatorWithdrawalAddress(pubkey))
      ethaddress = host.getSuggestedFeeRecipient(
        pubkey, perValidatorDefaultFeeRecipient)

    return if ethaddress.isOk:
      RestApiResponse.jsonResponse(ListFeeRecipientResponse(
        pubkey: pubkey,
        ethaddress: ethaddress.get))
    else:
      case ethaddress.error
      of noSuchValidator:
        keymanagerApiError(Http404, "No matching validator found")
      of malformedConfigFile:
        keymanagerApiError(Http500, "Error reading fee recipient file")

  # https://ethereum.github.io/keymanager-APIs/#/Fee%20Recipient/SetFeeRecipient
  router.api(MethodPost, "/eth/v1/validator/{pubkey}/feerecipient") do (
             pubkey: ValidatorPubKey,
             contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let
      pubkey= pubkey.valueOr:
        return keymanagerApiError(Http400, InvalidValidatorPublicKey)
      feeRecipientReq =
        block:
          if contentBody.isNone():
            return keymanagerApiError(Http400, InvalidFeeRecipientRequestError)
          let dres = decodeBody(SetFeeRecipientRequest, contentBody.get())
          if dres.isErr():
            return keymanagerApiError(Http400, InvalidFeeRecipientRequestError)
          dres.get()

      status = host.setFeeRecipient(pubkey, feeRecipientReq.ethaddress)

    return if status.isOk:
      RestApiResponse.response("", Http202, "text/plain")
    else:
      keymanagerApiError(
        Http500, "Failed to set fee recipient: " & status.error)

  # https://ethereum.github.io/keymanager-APIs/#/Fee%20Recipient/DeleteFeeRecipient
  router.api(MethodDelete, "/eth/v1/validator/{pubkey}/feerecipient") do (
             pubkey: ValidatorPubKey) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let
      pubkey = pubkey.valueOr:
        return keymanagerApiError(Http400, InvalidValidatorPublicKey)
      res = host.removeFeeRecipientFile(pubkey)

    return if res.isOk:
      RestApiResponse.response("", Http204, "text/plain")
    else:
      keymanagerApiError(
        Http500, "Failed to remove fee recipient file: " & res.error)

  # https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit/getGasLimit
  router.api(MethodGet, "/eth/v1/validator/{pubkey}/gas_limit") do (
             pubkey: ValidatorPubKey)  -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error

    let
      pubkey = pubkey.valueOr:
        return keymanagerApiError(Http400, InvalidValidatorPublicKey)
      gasLimit = host.getSuggestedGasLimit(pubkey)

    return if gasLimit.isOk:
      RestApiResponse.jsonResponse(GetValidatorGasLimitResponse(
        pubkey: pubkey,
        gas_limit: gasLimit.get))
    else:
      case gasLimit.error
      of noSuchValidator:
        keymanagerApiError(Http404, "No matching validator found")
      of malformedConfigFile:
        keymanagerApiError(Http500, "Error reading gas limit file")

  # https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit/setGasLimit
  router.api(MethodPost, "/eth/v1/validator/{pubkey}/gas_limit") do (
             pubkey: ValidatorPubKey,
             contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let
      pubkey = pubkey.valueOr:
        return keymanagerApiError(Http400, InvalidValidatorPublicKey)
      gasLimitReq =
        block:
          if contentBody.isNone():
            return keymanagerApiError(Http400, InvalidGasLimitRequestError)
          let dres = decodeBody(SetGasLimitRequest, contentBody.get())
          if dres.isErr():
            return keymanagerApiError(Http400, InvalidGasLimitRequestError)
          dres.get()

      status = host.setGasLimit(pubkey, gasLimitReq.gas_limit)

    return if status.isOk:
      RestApiResponse.response("", Http202, "text/plain")
    else:
      keymanagerApiError(
        Http500, "Failed to set gas limit: " & status.error)

  # https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit/deleteGasLimit
  router.api(MethodDelete, "/eth/v1/validator/{pubkey}/gas_limit") do (
             pubkey: ValidatorPubKey) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let
      pubkey = pubkey.valueOr:
        return keymanagerApiError(Http400, InvalidValidatorPublicKey)
      res = host.removeGasLimitFile(pubkey)

    return if res.isOk:
      RestApiResponse.response("", Http204, "text/plain")
    else:
      keymanagerApiError(
        Http500, "Failed to remove gas limit file: " & res.error)

  # TODO: These URLs will be changed once we submit a proposal for
  #       /eth/v2/remotekeys that supports distributed keys.
  router.api(MethodGet, "/eth/v1/remotekeys/distributed") do () -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let response = GetDistributedKeystoresResponse(
      data: listRemoteDistributedValidators(host.validatorPool[]))
    return RestApiResponse.jsonResponsePlain(response)

  # TODO: These URLs will be changed once we submit a proposal for
  #       /eth/v2/remotekeys that supports distributed keys.
  router.api(MethodPost, "/eth/v1/remotekeys/distributed") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let keys =
      block:
        if contentBody.isNone():
          return keymanagerApiError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(ImportDistributedKeystoresBody, contentBody.get())
        if dres.isErr():
          return keymanagerApiError(Http400, InvalidKeystoreObjects)
        dres.get.remote_keys

    var response: PostKeystoresResponse

    for index, key in keys:
      let keystore = RemoteKeystore(
        version: 2'u64,
        remoteType: RemoteSignerType.Web3Signer,
        pubkey: key.pubkey,
        remotes: key.remotes,
        threshold: uint32 key.threshold
      )
      response.data.add handleAddRemoteValidatorReq(host, keystore)

    return RestApiResponse.jsonResponsePlain(response)

  router.api(MethodDelete, "/eth/v1/remotekeys/distributed") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse authStatus.error
    let keys =
      block:
        if contentBody.isNone():
          return keymanagerApiError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(DeleteKeystoresBody, contentBody.get())
        if dres.isErr():
          return keymanagerApiError(Http400, InvalidValidatorPublicKey)
        dres.get.pubkeys

    var response: DeleteRemoteKeystoresResponse
    for index, key in keys:
      response.data.add handleRemoveValidatorReq(host, key)

    return RestApiResponse.jsonResponsePlain(response)

  # https://ethereum.github.io/keymanager-APIs/?urls.primaryName=dev#/Voluntary%20Exit/signVoluntaryExit
  router.api(MethodPost, "/eth/v1/validator/{pubkey}/voluntary_exit") do (
    pubkey: ValidatorPubKey, epoch: Option[Epoch],
    contentBody: Option[ContentBody]) -> RestApiResponse:

    let authStatus = checkAuthorization(request, host)
    if authStatus.isErr():
      return authErrorResponse(authStatus.error)

    let
      qpubkey = pubkey.valueOr:
        return keymanagerApiError(Http400, InvalidValidatorPublicKey)
      qepoch =
        if epoch.isSome():
          let res = epoch.get()
          if res.isErr():
            return keymanagerApiError(Http400, InvalidEpochValueError)
          res.get()
        else:
          host.getBeaconTimeFn().slotOrZero().epoch()
      validator =
        block:
          let res = host.validatorPool[].getValidator(qpubkey).valueOr:
            return keymanagerApiError(Http404, ValidatorNotFoundError)
          if res.index.isNone():
            return keymanagerApiError(Http404, ValidatorIndexMissingError)
          res
      voluntaryExit =
        VoluntaryExit(epoch: qepoch,
                      validator_index: uint64(validator.index.get()))
      fork = host.getForkFn(qepoch).valueOr:
        return keymanagerApiError(Http500, FailedToObtainForkError)
      signature =
        try:
          let res = await validator.getValidatorExitSignature(
            fork, host.getGenesisFn(), voluntaryExit)
          if res.isErr():
            return keymanagerApiError(Http500, res.error())
          res.get()
        except CancelledError as exc:
          raise exc
        except CatchableError as exc:
          error "An unexpected error occurred while signing validator exit",
                err_name = exc.name, err_msg = exc.msg
          return keymanagerApiError(Http500, $exc.msg)
      response = SignedVoluntaryExit(
        message: voluntaryExit,
        signature: signature
      )
    return RestApiResponse.jsonResponse(response)
