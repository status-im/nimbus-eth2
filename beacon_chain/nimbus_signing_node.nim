# nimbus_sign_node
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import std/[tables, os, strutils]
import chronos, presto, presto/secureserver, chronicles, confutils,
       stew/[base10, results, byteutils, io2],
       json_serialization/std/[options, net]

import "."/[conf, version, nimbus_binary_common, beacon_node_types]
import "."/spec/[crypto, digest, network, signatures],
       "."/spec/datatypes/[base, altair, phase0]
import "."/rpc/[rest_utils]
import "."/validators/[keystore_management, validator_pool]

const HttpHeadersTimeout = 10.seconds

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

  SignRequestKind* {.pure.} = enum
    Phase0Block, AltairBlock, Attestation, Randao

  SignRequest* = object
    fork: Fork
    genesisValidatorsRoot: Eth2Digest
    case kind: SignRequestKind
    of SignRequestKind.Phase0Block:
      phase0Block: phase0.BeaconBlock
    of SignRequestKind.AltairBlock:
      altairBlock: altair.BeaconBlock
    of SignRequestKind.Attestation:
      attestation: AttestationData
    of SignRequestKind.Randao:
      epoch: Epoch

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

proc readValue*(reader: var JsonReader[RestJson], value: var SignRequest) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    kind: Option[SignRequestKind]
    fork: Option[Fork]
    root: Option[Eth2Digest]
    data: Option[JsonString]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "bls_domain":
      if kind.isSome():
        reader.raiseUnexpectedField("Multiple bls_domain fields found",
                                    "SignRequest")
      let domain = reader.readValue(string)
      case domain
      of "beacon_proposer": kind = some(SignRequestKind.Phase0Block)
      of "beacon_attester": kind = some(SignRequestKind.Attestation)
      of "randao": kind = some(SignRequestKind.Randao)
      else:
        reader.raiseUnexpectedValue("Incorrect bls_domain value")
    of "fork":
      if fork.isSome():
        reader.raiseUnexpectedField("Multiple fork fields found", "SignRequest")
      fork = some(reader.readValue(Fork))
    of "genesis_validators_root":
      if root.isSome():
        reader.raiseUnexpectedField("Multiple genesis_validators_root " &
                                    "fields found", "SignRequest")
      root = some(reader.readValue(Eth2Digest))
    of "data":
      if data.isSome():
        reader.raiseUnexpectedField("Multiple data fields found", "SignRequest")
      data = some(reader.readValue(JsonString))
    else:
      reader.raiseUnexpectedField(fieldName, "SignRequest")

  if kind.isNone():
    reader.raiseUnexpectedValue("Field bls_domain is missing")
  if fork.isNone():
    reader.raiseUnexpectedValue("Field fork is missing")
  if root.isNone():
    reader.raiseUnexpectedValue("Field genesis_validators_root is missing")
  if data.isNone():
    reader.raiseUnexpectedValue("Field data is missing")

  let kkind = kind.get()
  case kkind
  of SignRequestKind.Phase0Block, SignRequestKind.AltairBlock:
    let altairBlock =
      try:
        some(RestJson.decode(string(data.get()), altair.BeaconBlock,
                             requireAllFields = true))
      except SerializationError:
        none[altair.BeaconBlock]()
    if altairBlock.isSome():
      value = SignRequest(
        kind: SignRequestKind.AltairBlock,
        fork: fork.get(),
        genesisValidatorsRoot: root.get(),
        altairBlock: altairBlock.get()
      )
    else:
      let phase0Block =
        try:
          some(RestJson.decode(string(data.get()), phase0.BeaconBlock,
                               requireAllFields = true))
        except SerializationError:
          none[phase0.BeaconBlock]()
      if phase0Block.isSome():
        value = SignRequest(
          kind: SignRequestKind.Phase0Block,
          fork: fork.get(),
          genesisValidatorsRoot: root.get(),
          phase0Block: phase0Block.get()
        )
      else:
        reader.raiseUnexpectedValue("Incorrect beacon block format")
  of SignRequestKind.Attestation:
    let attestation = RestJson.decode(string(data.get()), AttestationData,
                                      requireAllFields = true)
    value = SignRequest(
      kind: SignRequestKind.Attestation,
      fork: fork.get(),
      genesisValidatorsRoot: root.get(),
      attestation: attestation
    )
  of SignRequestKind.Randao:
    let epoch = RestJson.decode(string(data.get()), Epoch,
                                requireAllFields = true)
    value = SignRequest(
      kind: SignRequestKind.Randao,
      fork: fork.get(),
      genesisValidatorsRoot: root.get(),
      epoch: epoch
    )

proc initValidators(sn: var SigningNode): bool =
  info "Initializaing validators", path = sn.config.validatorsDir()
  var duplicates: seq[ValidatorPubKey]
  var publicKeyIdents: seq[string]
  for key in sn.config.validatorKeys():
    let pubkey = key.toPubKey().toPubKey()
    if pubkey in duplicates:
      error "Duplicate validator's key found", validator_pubkey = pubkey
      return false
    else:
      duplicates.add(pubkey)
      sn.attachedValidators.addLocalValidator(key)
      publicKeyIdents.add("\"" & pubkey.toHex() & "\"")
  sn.keysList = "{\"keys\": [" & publicKeyIdents.join(", ") & "]}"
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
    timeout = HttpHeadersTimeout

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
                                        httpHeadersTimeout = timeout)
      if res.isErr():
        fatal "HTTPS(REST) server could not be started", address = $address,
              reason = $res.error()
        quit 1
      SigningNodeServer(kind: SigningNodeKind.Secure, sserver: res.get())
    else:
      let res = RestServerRef.new(getRouter(), address,
                                  serverFlags = serverFlags,
                                  httpHeadersTimeout = timeout)
      if res.isErr():
        fatal "HTTP(REST) server could not be started", address = $address,
               reason = $res.error()
        quit 1
      SigningNodeServer(kind: SigningNodeKind.NonSecure, nserver: res.get())
  sn

template errorResponse(code: HttpCode, message: string): RestApiResponse =
  RestApiResponse.response("{\"error\": \"" & message & "\"}", code)

template signatureResponse(code: HttpCode, signature: string): RestApiResponse =
  RestApiResponse.response("{\"signature\": \"" & signature & "\"}", code)

proc installApiHandlers*(node: SigningNode) =
  var router = node.router()

  router.api(MethodGet, "/keys") do () -> RestApiResponse:
    return RestApiResponse.response(node.keysList, Http200,
                                    "application/json")

  router.api(MethodGet, "/upcheck") do () -> RestApiResponse:
    return RestApiResponse.response("{\"status\": \"OK\"}", Http200,
                                    "application/json")

  router.api(MethodPost, "/sign/{validator_key_wo0x}") do (
    validator_key_wo0x: ValidatorPubKey,
    contentBody: Option[ContentBody]) -> RestApiResponse:

    let request =
      block:
        if contentBody.isNone():
          return errorResponse(Http400, EmptyRequestBodyError)
        let res = decodeBody(SignRequest, contentBody.get())
        if res.isErr():
          return errorResponse(Http400, $res.error())
        res.get()

    let validator =
      block:
        if validator_key_wo0x.isErr():
          return errorResponse(Http400, "Invalid validator key")
        let key = validator_key_wo0x.get()
        let validator = node.attachedValidators.getValidator(key)
        if isNil(validator):
          return errorResponse(Http404, "Validator key not found")
        validator

    case request.kind
    of SignRequestKind.Phase0Block:
      discard
    of SignRequestKind.AltairBlock:
      discard
    of SignRequestKind.Attestation:
      let cooked = get_attestation_signature(request.fork,
                                             request.genesis_validators_root,
                                             request.attestation,
                                             validator.privKey)
      let signature = cooked.toValidatorSig().toHex()
      return signatureResponse(Http200, signature)
    of SignRequestKind.Randao:
      let cooked = get_epoch_signature(request.fork,
                                       request.genesisValidatorsRoot,
                                       request.epoch, validator.privKey)
      let signature = cooked.toValidatorSig().toHex()
      return signatureResponse(Http200, signature)

programMain:
  let config = makeBannerAndConfig("Nimbus signing node " & fullVersionStr,
                                   SigningNodeConf)

  setupStdoutLogging(config.logLevel)
  setupLogging(config.logLevel, config.logFile)

  case config.cmd
    of SNNoCommand:
      var sn = SigningNode.init(config)
      notice "Launching signing node", version = fullVersionStr,
             cmdParams = commandLineParams(), config,
             validators_count = sn.attachedValidators.count()
      sn.installApiHandlers()
      discard sn.stop()

  #     waitFor asyncInit(vc)
  #     waitFor asyncRun(vc)
