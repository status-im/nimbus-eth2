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
import "."/spec/[crypto, digest, network],
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

  SignRequestKind* = enum
    Phase0Block, AltairBlock, Attestation, Randao

  SignRequestBase* = object of RootObj
    blsDomain* {.
      serializedFieldName: "bls_domain".}: string
    fork*: Fork
    genesisValidatorsRoot* {.
      serializedFieldName: "genesis_validators_root".}: Eth2Digest

  SignRequestPhase0Block* = object of SignRequestBase
    data*: phase0.BeaconBlock

  SignRequestAltairBlock* = object of SignRequestBase
    data*: altair.BeaconBlock

  SignRequestAttestation* = object of SignRequestBase
    data*: AttestationData

  SignRequestRandao* = object of SignRequestBase
    data*: Epoch

  SignRequest* = object of SignRequestBase
    case kind: SignRequestKind
    of Phase0Block:
      phase0Block: phase0.BeaconBlock
    of AltairBlock:
      altairBlock: altair.BeaconBlock
    of Attestation:
      attestation: AttestationData
    of Randao:
      epoch: Epoch

# proc state*(rs: RestServerRef): RestServerState {.raises: [Defect].} =
#   ## Returns current REST server's state.
#   case rs.server.state
#   of HttpServerState.ServerClosed:
#     RestServerState.Closed
#   of HttpServerState.ServerStopped:
#     RestServerState.Stopped
#   of HttpServerState.ServerRunning:
#     RestServerState.Running

# template server(sn: SigningNode): untyped =
#   case sn.signingServer.kind
#   of SigningNodeKind.Secure:
#     sn.signingServer.sserver
#   of SigningNodeKind.NonSecure:
#     sn.signingServer.nserver

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

proc init*(t: typedesc[SignRequest],
           data: ContentBody): Result[SignRequest, cstring] =
  let base = ? decodeBodyWithUnknownFields(SignRequestBase, data)
  case base.blsDomain
  of "beacon_proposer":
    let altairRes = decodeBodyWithUnknownFields(SignRequestAltairBlock, data)
    if altairRes.isErr():
      let phase0res = decodeBodyWithUnknownFields(SignRequestPhase0Block, data)
      if phase0res.isErr():
        err("Incorrect block format")
      else:
        let data = phase0res.get()
        let req = SignRequest(kind: SignRequestKind.Phase0Block,
                              phase0Block: data.data,
                              blsDomain: data.blsDomain, fork: data.fork,
                              genesisValidatorsRoot: data.genesisValidatorsRoot)
        ok(req)
    else:
      let data = altairRes.get()
      let req = SignRequest(kind: SignRequestKind.AltairBlock,
                            altairBlock: data.data,
                            blsDomain: data.blsDomain, fork: data.fork,
                            genesisValidatorsRoot: data.genesisValidatorsRoot)
      ok(req)
  of "beacon_attester":
    let data = ? decodeBodyWithUnknownFields(SignRequestAttestation, data)
    let req = SignRequest(kind: SignRequestKind.Attestation,
                          attestation: data.data,
                          blsDomain: data.blsDomain, fork: data.fork,
                          genesisValidatorsRoot: data.genesisValidatorsRoot)
    ok(req)
  of "randao":
    let data = ? decodeBodyWithUnknownFields(SignRequestRandao, data)
    let req = SignRequest(kind: SignRequestKind.Randao, epoch: data.data,
                          blsDomain: data.blsDomain, fork: data.fork,
                          genesisValidatorsRoot: data.genesisValidatorsRoot)
    ok(req)
  else:
    err("Incorrect BLS domain value")

template errorResponse(t: typedesc[RestApiResponse], code: HttpCode,
                       message: string): RestApiResponse =
  RestApiResponse.response("{\"error\": \"" & message & "\"}", code)

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
          return RestApiResponse.errorResponse(Http400, EmptyRequestBodyError)
        let body = contentBody.get()
        let res = SignRequest.init(body)
        if res.isErr():
          return RestApiResponse.errorResponse(Http400, $res.error())
        res.get()

    let validator =
      block:
        if validator_key_wo0x.isErr():
          return RestApiResponse.errorResponse(Http400,
                 "Invalid validator key")
        let key = validator_key_wo0x.get()
        let validator = node.attachedValidators.getValidator(key)
        if isNil(validator):
          return RestApiResponse.errorResponse(Http404,
                 "Validator key not found: " & key.toHex())
        validator


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
