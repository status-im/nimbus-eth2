# nimbus_signing_node
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[tables, os, strutils]
import serialization, json_serialization,
       json_serialization/std/[options, net],
       chronos, presto, presto/secureserver, chronicles, confutils,
       stew/[base10, results, byteutils, io2, bitops2]
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
    keystoreCache: KeystoreCacheRef
    keysList: string
    runKeystoreCachePruningLoopFut: Future[void]
    sigintHandleFut: Future[void]
    sigtermHandleFut: Future[void]

  SigningNodeRef* = ref SigningNode

  SigningNodeError* = object of CatchableError

func validate(key: string, value: string): int =
  case key
  of "{validator_key}":
    0
  else:
    1

proc getRouter*(): RestRouter =
  RestRouter.init(validate)

proc router(sn: SigningNodeRef): RestRouter =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    sn.signingServer.sserver.router
  of SigningNodeKind.NonSecure:
    sn.signingServer.nserver.router

proc start(sn: SigningNodeRef) =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    sn.signingServer.sserver.start()
  of SigningNodeKind.NonSecure:
    sn.signingServer.nserver.start()

proc stop(sn: SigningNodeRef) {.async.} =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    await sn.signingServer.sserver.stop()
  of SigningNodeKind.NonSecure:
    await sn.signingServer.nserver.stop()

proc close(sn: SigningNodeRef) {.async.} =
  case sn.signingServer.kind
  of SigningNodeKind.Secure:
    await sn.signingServer.sserver.closeWait()
  of SigningNodeKind.NonSecure:
    await sn.signingServer.nserver.closeWait()

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

proc new(t: typedesc[SigningNodeRef], config: SigningNodeConf): SigningNodeRef =
  when declared(waitSignal):
    SigningNodeRef(
      config: config,
      sigintHandleFut: waitSignal(SIGINT),
      sigtermHandleFut: waitSignal(SIGTERM),
      keystoreCache: KeystoreCacheRef.init()
    )
  else:
    SigningNodeRef(
      config: config,
      sigintHandleFut: newFuture[void]("sigint_placeholder"),
      sigtermHandleFut: newFuture[void]("sigterm_placeholder"),
      keystoreCache: KeystoreCacheRef.init()
    )

template errorResponse(code: HttpCode, message: string): RestApiResponse =
  RestApiResponse.response("{\"error\": \"" & message & "\"}", code)

template signatureResponse(code: HttpCode, signature: string): RestApiResponse =
  RestApiResponse.response("{\"signature\": \"0x" & signature & "\"}",
                           code, "application/json")

proc loadKeystores*(node: SigningNodeRef) =
  var keysList: seq[string]
  for keystore in listLoadableKeystores(node.config, node.keystoreCache):
    # Not relevant in signing node
    # TODO don't print when loading validators
    let feeRecipient = default(Eth1Address)
    case keystore.kind
    of KeystoreKind.Local:
      discard node.attachedValidators.addValidator(keystore,
                                                   feeRecipient,
                                                   defaultGasLimit)
      keysList.add("\"0x" & keystore.pubkey.toHex() & "\"")
    of KeystoreKind.Remote:
      warn "Signing node do not support remote validators",
           path = node.config.validatorsDir(),
           validator_pubkey = keystore.pubkey

  node.keysList = "[" & keysList.join(", ") & "]"

proc installApiHandlers*(node: SigningNodeRef) =
  var router = node.router()

  router.api(MethodGet, "/api/v1/eth2/publicKeys") do () -> RestApiResponse:
    return RestApiResponse.response(node.keysList, Http200,
                                    "application/json")

  router.api(MethodGet, "/upcheck") do () -> RestApiResponse:
    return RestApiResponse.response("{\"status\": \"OK\"}", Http200,
                                    "application/json")

  router.api(MethodPost, "/reload") do () -> RestApiResponse:
    node.attachedValidators.close()
    node.loadKeystores()
    return RestApiResponse.response(Http200)

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
        let validator = node.attachedValidators.getValidator(key).valueOr:
          return errorResponse(Http404, ValidatorNotFoundError)
        validator

    return
      case request.kind
      of Web3SignerRequestKind.AggregationSlot:
        let
          forkInfo = request.forkInfo.get()
          signature = get_slot_signature(forkInfo.fork,
            forkInfo.genesis_validators_root,
            request.aggregationSlot.slot,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.AggregateAndProof:
        let
          forkInfo = request.forkInfo.get()
          signature = get_aggregate_and_proof_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.aggregateAndProof,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.Attestation:
        let
          forkInfo = request.forkInfo.get()
          signature = get_attestation_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.attestation,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.BlockV2:
        if node.config.expectedFeeRecipient.isNone():
          let
            forkInfo = request.forkInfo.get()
            blockRoot = hash_tree_root(request.beaconBlockHeader)
            signature = get_block_signature(
              forkInfo.fork, forkInfo.genesis_validators_root,
              request.beaconBlockHeader.data.slot, blockRoot,
              validator.data.privateKey).toValidatorSig().toHex()
          return signatureResponse(Http200, signature)

        let (feeRecipientIndex, blockHeader) =
          case request.beaconBlockHeader.kind
          of ConsensusFork.Phase0, ConsensusFork.Altair:
            # `phase0` and `altair` blocks do not have `fee_recipient`, so
            # we return an error.
            return errorResponse(Http400, BlockIncorrectFork)
          of ConsensusFork.Bellatrix, ConsensusFork.Capella:
            (GeneralizedIndex(401), request.beaconBlockHeader.data)
          of ConsensusFork.Deneb:
            (GeneralizedIndex(801), request.beaconBlockHeader.data)

        if request.proofs.isNone() or len(request.proofs.get()) == 0:
          return errorResponse(Http400, MissingMerkleProofError)

        let proof = request.proofs.get()[0]

        if proof.index != feeRecipientIndex:
          return errorResponse(Http400, InvalidMerkleProofIndexError)

        let feeRecipientRoot = hash_tree_root(distinctBase(
          node.config.expectedFeeRecipient.get()))

        if not(is_valid_merkle_branch(feeRecipientRoot, proof.proof,
                                      log2trunc(proof.index),
                                      get_subtree_index(proof.index),
                                      blockHeader.body_root)):
          return errorResponse(Http400, InvalidMerkleProofError)

        let
          forkInfo = request.forkInfo.get()
          blockRoot = hash_tree_root(request.beaconBlockHeader)
          signature = get_block_signature(forkInfo.fork,
            forkInfo.genesis_validators_root,
            request.beaconBlockHeader.data.slot, blockRoot,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.Deposit:
        let
          data = DepositMessage(pubkey: request.deposit.pubkey,
            withdrawal_credentials: request.deposit.withdrawalCredentials,
            amount: request.deposit.amount)
          signature = get_deposit_signature(data,
            request.deposit.genesisForkVersion,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.RandaoReveal:
        let
          forkInfo = request.forkInfo.get()
          signature = get_epoch_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.randaoReveal.epoch,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.VoluntaryExit:
        let
          forkInfo = request.forkInfo.get()
          signature = get_voluntary_exit_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, request.voluntaryExit,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.SyncCommitteeMessage:
        let
          forkInfo = request.forkInfo.get()
          msg = request.syncCommitteeMessage
          signature = get_sync_committee_message_signature(forkInfo.fork,
            forkInfo.genesis_validators_root, msg.slot, msg.beaconBlockRoot,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.SyncCommitteeSelectionProof:
        let
          forkInfo = request.forkInfo.get()
          msg = request.syncAggregatorSelectionData
          subcommittee =
            SyncSubcommitteeIndex.init(msg.subcommittee_index).valueOr:
              return errorResponse(Http400, InvalidSubCommitteeIndexValueError)
          signature = get_sync_committee_selection_proof(forkInfo.fork,
            forkInfo.genesis_validators_root, msg.slot, subcommittee,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.SyncCommitteeContributionAndProof:
        let
          forkInfo = request.forkInfo.get()
          msg = request.syncCommitteeContributionAndProof
          signature = get_contribution_and_proof_signature(
            forkInfo.fork, forkInfo.genesis_validators_root, msg,
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)
      of Web3SignerRequestKind.ValidatorRegistration:
        let
          forkInfo = request.forkInfo.get()
          signature = get_builder_signature(forkInfo.fork,
            ValidatorRegistrationV1(
              fee_recipient:
                ExecutionAddress(data: distinctBase(Eth1Address.fromHex(
                  request.validatorRegistration.feeRecipient))),
              gas_limit: request.validatorRegistration.gasLimit,
              timestamp: request.validatorRegistration.timestamp,
              pubkey: request.validatorRegistration.pubkey,
            ),
            validator.data.privateKey).toValidatorSig().toHex()
        signatureResponse(Http200, signature)

proc asyncInit(sn: SigningNodeRef) {.async.} =
  notice "Launching signing node", version = fullVersionStr,
         cmdParams = commandLineParams(), config = sn.config

  info "Initializaing validators", path = sn.config.validatorsDir()
  sn.loadKeystores()

  if sn.attachedValidators.count() == 0:
    fatal "Could not find/initialize local validators"
    raise newException(SigningNodeError, "")

  let
    address = initTAddress(sn.config.bindAddress, sn.config.bindPort)
    serverFlags = {HttpServerFlags.QueryCommaSeparatedArray,
                   HttpServerFlags.NotifyDisconnect}
    timeout =
      if sn.config.requestTimeout < 0:
        warn "Negative value of request timeout, using default instead"
        seconds(defaultSigningNodeRequestTimeout)
      else:
        seconds(sn.config.requestTimeout)
    serverIdent =
      if sn.config.serverIdent.isSome():
        sn.config.serverIdent.get()
      else:
        NimbusSigningNodeIdent

  sn.signingServer =
    if sn.config.tlsEnabled:
      if sn.config.tlsCertificate.isNone():
        fatal "TLS certificate path is missing, please use --tls-cert option"
        raise newException(SigningNodeError, "")

      if sn.config.tlsPrivateKey.isNone():
        fatal "TLS private key path is missing, please use --tls-key option"
        raise newException(SigningNodeError, "")

      let cert =
        block:
          let res = loadTLSCert(sn.config.tlsCertificate.get())
          if res.isErr():
            fatal "Could not initialize SSL certificate",
                  reason = $res.error()
            raise newException(SigningNodeError, "")
          res.get()
      let key =
        block:
          let res = loadTLSKey(sn.config.tlsPrivateKey.get())
          if res.isErr():
            fatal "Could not initialize SSL private key",
                  reason = $res.error()
            raise newException(SigningNodeError, "")
          res.get()
      let res = SecureRestServerRef.new(getRouter(), address, key, cert,
                                        serverFlags = serverFlags,
                                        httpHeadersTimeout = timeout,
                                        serverIdent = serverIdent)
      if res.isErr():
        fatal "HTTPS(REST) server could not be started", address = $address,
              reason = $res.error()
        raise newException(SigningNodeError, "")
      SigningNodeServer(kind: SigningNodeKind.Secure, sserver: res.get())
    else:
      let res = RestServerRef.new(getRouter(), address,
                                  serverFlags = serverFlags,
                                  httpHeadersTimeout = timeout,
                                  serverIdent = serverIdent)
      if res.isErr():
        fatal "HTTP(REST) server could not be started", address = $address,
               reason = $res.error()
        raise newException(SigningNodeError, "")
      SigningNodeServer(kind: SigningNodeKind.NonSecure, nserver: res.get())

proc asyncRun*(sn: SigningNodeRef) {.async.} =
  sn.runKeystoreCachePruningLoopFut =
    runKeystoreCachePruningLoop(sn.keystoreCache)
  sn.installApiHandlers()
  sn.start()

  var future = newFuture[void]("signing-node-mainLoop")
  try:
    await future
  except CancelledError:
    debug "Main loop interrupted"
  except CatchableError as exc:
    warn "Main loop failed with unexpected error", err_name = $exc.name,
         reason = $exc.msg

  debug "Stopping main processing loop"
  var pending: seq[Future[void]]
  if not(sn.runKeystoreCachePruningLoopFut.finished()):
    pending.add(cancelAndWait(sn.runKeystoreCachePruningLoopFut))
  pending.add(sn.stop())
  pending.add(sn.close())
  await noCancel allFutures(pending)

template runWithSignals(sn: SigningNodeRef, body: untyped): bool =
  let future = body
  discard await race(future, sn.sigintHandleFut, sn.sigtermHandleFut)
  if future.finished():
    if future.failed() or future.cancelled():
      discard future.readError()
      debug "Signing node initialization failed"
      var pending: seq[Future[void]]
      if not(sn.sigintHandleFut.finished()):
        pending.add(cancelAndWait(sn.sigintHandleFut))
      if not(sn.sigtermHandleFut.finished()):
        pending.add(cancelAndWait(sn.sigtermHandleFut))
      await noCancel allFutures(pending)
      false
    else:
      true
  else:
    let signal = if sn.sigintHandleFut.finished(): "SIGINT" else: "SIGTERM"
    info "Got interrupt, trying to shutdown gracefully", signal = signal
    var pending = @[cancelAndWait(future)]
    if not(sn.sigintHandleFut.finished()):
      pending.add(cancelAndWait(sn.sigintHandleFut))
    if not(sn.sigtermHandleFut.finished()):
      pending.add(cancelAndWait(sn.sigtermHandleFut))
    await noCancel allFutures(pending)
    false

proc runSigningNode(config: SigningNodeConf) {.async.} =
  let sn = SigningNodeRef.new(config)
  if not sn.runWithSignals(asyncInit sn):
    return
  if not sn.runWithSignals(asyncRun sn):
    return

programMain:
  let config =
    makeBannerAndConfig("Nimbus signing node " & fullVersionStr,
                        SigningNodeConf)
  setupLogging(config.logLevel, config.logStdout, config.logFile)
  waitFor runSigningNode(config)
