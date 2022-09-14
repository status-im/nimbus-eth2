# nimbus_sign_node
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import std/[tables, os, strutils]
import serialization, json_serialization,
       json_serialization/std/[options, net],
       chronos, presto, presto/secureserver, chronicles, confutils,
       stew/[base10, results, byteutils, io2]
import "."/spec/datatypes/[base, altair, phase0],
       "."/spec/[crypto, digest, network, signatures, forks],
       "."/spec/eth2_apis/[rest_types, eth2_rest_serialization],
       "."/rpc/rest_constants,
       "."/[conf, version, nimbus_binary_common],
       "."/validators/[keystore_management, validator_pool]

const
  NimbusSigningNodeIdent = "nimbus_remote_signer/" & fullVersionStr

type
  SigningNodeKind* {.pure.} = enum
    NonSecure, Secure

  SigningNodeServer* = object
    case kind: SigningNodeKind
    of SigningNodeKind.Secure:
      sserver: SecureRestServerRef
    of SigningNodeKind.NonSecure:
      nserver: RestServerRef

  SigningNode* = object
    config: SigningNodeConf
    attachedValidators: ValidatorPool
    signingServer: SigningNodeServer
    keysList: string

proc getRouter*(): RestRouter

proc router(sn: SigningNode): RestRouter =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    sn.signingServer.sserver.router
  of SigningNodeKind.NonSecure:
    sn.signingServer.nserver.router

proc start(sn: SigningNode) =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    sn.signingServer.sserver.start()
  of SigningNodeKind.NonSecure:
    sn.signingServer.nserver.start()

proc stop(sn: SigningNode) {.async.} =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    await sn.signingServer.sserver.stop()
  of SigningNodeKind.NonSecure:
    await sn.signingServer.nserver.stop()

proc close(sn: SigningNode) {.async.} =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    await sn.signingServer.sserver.stop()
  of SigningNodeKind.NonSecure:
    await sn.signingServer.nserver.stop()

proc loadTLSCert(pathName: InputFile): Result[TLSCertificate, cstring] =
  let data =
    block:
      let res = io2.readAllChars(string(pathName))
      if res.isErr():
        return err("Could not read certificate file")
      res.get()
  let cert =
    try:
      TLSCertificate.init(data)
    except TLSStreamProtocolError:
      return err("Invalid certificate or incorrect file format")
  ok(cert)

proc loadTLSKey(pathName: InputFile): Result[TLSPrivateKey, cstring] =
  let data =
    block:
      let res = io2.readAllChars(string(pathName))
      if res.isErr():
        return err("Could not read private key file")
      res.get()
  let key =
    try:
      TLSPrivateKey.init(data)
    except TLSStreamProtocolError:
      return err("Invalid private key or incorrect file format")
  ok(key)

proc initValidators(sn: var SigningNode): bool =
  info "Initializaing validators", path = sn.config.validatorsDir()
  var publicKeyIdents: seq[string]
  for keystore in listLoadableKeystores(sn.config):
    # Not relevant in signing node
    # TODO don't print when loading validators
    let feeRecipient = default(Eth1Address)
    case keystore.kind
    of KeystoreKind.Local:
      # Signing node is not supposed to know genesis time, so we just set
      # `start_slot` to GENESIS_SLOT.
      sn.attachedValidators.addLocalValidator(
        keystore, feeRecipient, GENESIS_SLOT)
      publicKeyIdents.add("\"0x" & keystore.pubkey.toHex() & "\"")
    of KeystoreKind.Remote:
      error "Signing node do not support remote validators",
            validator_pubkey = keystore.pubkey
      return false
  sn.keysList = "[" & publicKeyIdents.join(", ") & "]"
  true

proc init(t: typedesc[SigningNode], config: SigningNodeConf): SigningNode =
  var sn = SigningNode(config: config)

  if not(initValidators(sn)):
    fatal "Could not find/initialize local validators"
    quit 1

  let
    address = initTAddress(config.bindAddress, config.bindPort)
    serverFlags = {HttpServerFlags.QueryCommaSeparatedArray,
                   HttpServerFlags.NotifyDisconnect}
    timeout =
      if config.requestTimeout < 0:
        warn "Negative value of request timeout, using default instead"
        seconds(defaultSigningNodeRequestTimeout)
      else:
        seconds(config.requestTimeout)
    serverIdent =
      if config.serverIdent.isSome():
        config.serverIdent.get()
      else:
        NimbusSigningNodeIdent

  sn.signingServer =
    if config.tlsEnabled:
      if config.tlsCertificate.isNone():
        fatal "TLS certificate path is missing, please use --tls-cert option"
        quit 1

      if config.tlsPrivateKey.isNone():
        fatal "TLS private key path is missing, please use --tls-key option"
        quit 1

      let cert =
        block:
          let res = loadTLSCert(config.tlsCertificate.get())
          if res.isErr():
            fatal "Could not initialize SSL certificate", reason = $res.error()
            quit 1
          res.get()
      let key =
        block:
          let res = loadTLSKey(config.tlsPrivateKey.get())
          if res.isErr():
            fatal "Could not initialize SSL private key", reason = $res.error()
            quit 1
          res.get()
      let res = SecureRestServerRef.new(getRouter(), address, key, cert,
                                        serverFlags = serverFlags,
                                        httpHeadersTimeout = timeout,
                                        serverIdent = serverIdent)
      if res.isErr():
        fatal "HTTPS(REST) server could not be started", address = $address,
              reason = $res.error()
        quit 1
      SigningNodeServer(kind: SigningNodeKind.Secure, sserver: res.get())
    else:
      let res = RestServerRef.new(getRouter(), address,
                                  serverFlags = serverFlags,
                                  httpHeadersTimeout = timeout,
                                  serverIdent = serverIdent)
      if res.isErr():
        fatal "HTTP(REST) server could not be started", address = $address,
               reason = $res.error()
        quit 1
      SigningNodeServer(kind: SigningNodeKind.NonSecure, nserver: res.get())
  sn

template errorResponse(code: HttpCode, message: string): RestApiResponse =
  RestApiResponse.response("{\"error\": \"" & message & "\"}", code)

template signatureResponse(code: HttpCode, signature: string): RestApiResponse =
  RestApiResponse.response("{\"signature\": \"0x" & signature & "\"}", code, "application/json")

proc installApiHandlers*(node: SigningNode) =
  var router = node.router()

  router.api(MethodGet, "/api/v1/eth2/publicKeys") do () -> RestApiResponse:
    return RestApiResponse.response(node.keysList, Http200,
                                    "application/json")

  router.api(MethodGet, "/upcheck") do () -> RestApiResponse:
    return RestApiResponse.response("{\"status\": \"OK\"}", Http200,
                                    "application/json")

  router.api(MethodPost, "/api/v1/eth2/sign/{validator_key}") do (
    validator_key: ValidatorPubKey,
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let request =
      block:
        if contentBody.isNone():
          return errorResponse(Http400, EmptyRequestBodyError)
        let res = decodeBody(Web3SignerRequest, contentBody.get())
        if res.isErr():
          return errorResponse(Http400, $res.error())
        res.get()

    let validator =
      block:
        if validator_key.isErr():
          return errorResponse(Http400, InvalidValidatorPublicKey)
        let key = validator_key.get()
        let validator = node.attachedValidators.getValidator(key)
        if isNil(validator):
          return errorResponse(Http404, ValidatorNotFoundError)
        validator

    return
      case request.kind
      of Web3SignerRequestKind.AggregationSlot:
        let
          forkInfo = request.forkInfo.get()
          cooked = get_slot_signature(forkInfo.fork,
            forkInfo.genesis_validators_root,
            request.aggregationSlot.slot, validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.AggregateAndProof:
        let
          forkInfo = request.forkInfo.get()
          cooked = get_aggregate_and_proof_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.aggregateAndProof,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.Attestation:
        let
          forkInfo = request.forkInfo.get()
          cooked = get_attestation_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.attestation,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.Block:
        let
          forkInfo = request.forkInfo.get()
          blck = request.blck
          blockRoot = hash_tree_root(blck)
          cooked = get_block_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, blck.slot, blockRoot,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.BlockV2:
        let
          forkInfo = request.forkInfo.get()
          forked = request.beaconBlock
          blockRoot = hash_tree_root(forked)
          cooked =
            withBlck(forked):
              get_block_signature(forkInfo.fork,
                forkInfo.genesis_validators_root, blck.slot, blockRoot,
                validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.Deposit:
        let
          data = DepositMessage(pubkey: request.deposit.pubkey,
            withdrawal_credentials: request.deposit.withdrawalCredentials,
            amount: request.deposit.amount)
          cooked = get_deposit_signature(data,
            request.deposit.genesisForkVersion, validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.RandaoReveal:
        let
          forkInfo = request.forkInfo.get()
          cooked = get_epoch_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.randaoReveal.epoch,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.VoluntaryExit:
        let
          forkInfo = request.forkInfo.get()
          cooked = get_voluntary_exit_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.voluntaryExit,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.SyncCommitteeMessage:
        let
          forkInfo = request.forkInfo.get()
          msg = request.syncCommitteeMessage
          cooked = get_sync_committee_message_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, msg.slot, msg.beaconBlockRoot,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.SyncCommitteeSelectionProof:
        let
          forkInfo = request.forkInfo.get()
          msg = request.syncAggregatorSelectionData
          subcommittee = SyncSubcommitteeIndex.init(msg.subcommittee_index).valueOr:
            return errorResponse(Http400, InvalidSubCommitteeIndexValueError)
          cooked = get_sync_committee_selection_proof(forkInfo.fork,
            forkInfo.genesis_validators_root, msg.slot, subcommittee,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.SyncCommitteeContributionAndProof:
        let
          forkInfo = request.forkInfo.get()
          msg = request.syncCommitteeContributionAndProof
          cooked = get_contribution_and_proof_signature(
            forkInfo.fork, forkInfo.genesis_validators_root, msg,
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.ValidatorRegistration:
        let
          forkInfo = request.forkInfo.get()
          cooked = get_builder_signature(
            forkInfo.fork, ValidatorRegistrationV1(
              fee_recipient:
                ExecutionAddress(data: distinctBase(Eth1Address.fromHex(
                  request.validatorRegistration.feeRecipient))),
              gas_limit: request.validatorRegistration.gasLimit,
              timestamp: request.validatorRegistration.timestamp,
              pubkey: request.validatorRegistration.pubkey,
            ),
            validator.data.privateKey)
          signature = cooked.toValidatorSig().toHex()
        signatureResponse(Http200, signature)

proc validate(key: string, value: string): int =
  case key
  of "{validator_key}":
    0
  else:
    1

proc getRouter*(): RestRouter =
  RestRouter.init(validate)

programMain:
  let config = makeBannerAndConfig("Nimbus signing node " & fullVersionStr,
                                   SigningNodeConf)
  setupLogging(config.logLevel, config.logStdout, config.logFile)

  var sn = SigningNode.init(config)
  notice "Launching signing node", version = fullVersionStr,
         cmdParams = commandLineParams(), config,
         validators_count = sn.attachedValidators.count()
  sn.installApiHandlers()
  sn.start()
  try:
    runForever()
  finally:
    waitFor sn.stop()
    waitFor sn.close()
  discard sn.stop()
