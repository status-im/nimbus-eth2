# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[tables, os, sequtils, strutils]
import chronos, presto, presto/client as presto_client, chronicles, confutils,
       json_serialization/std/[options, net],
       stew/[base10, results, byteutils, io2], bearssl, blscurve
# Local modules
import ".."/[conf, version, filepath, beacon_node_types, beacon_node_common]
import ".."/spec/[keystore, crypto]
import ".."/rpc/rest_utils
import ".."/validators/[keystore_management, validator_pool]

export results

type
  ValidatorToggleAction {.pure.} = enum
    Enable, Disable

  KmResult*[T] = Result[T, cstring]

  StoredValidatorKeyFlag* {.pure.} = enum
    Valid, NoPassword, NoPermission, Disabled

  StoredValidatorKey* = object
    name*: string
    filename*: string
    flag*: StoredValidatorKeyFlag
    pubkey*: ValidatorPubKey

  ValidatorListItem* = object
    pubkey*: ValidatorPubKey
    status*: string

  ValidatorKeystoreItem* = object
    keystore*: Keystore
    password*: string

proc `$`*(s: StoredValidatorKeyFlag): string =
  case s
  of StoredValidatorKeyFlag.Valid:
    "enabled"
  of StoredValidatorKeyFlag.NoPassword:
    "failed"
  of StoredValidatorKeyFlag.NoPermission:
    "failed"
  of StoredValidatorKeyFlag.Disabled:
    "disabled"

proc init*(t: typedesc[ValidatorListItem], key: ValidatorPubKey,
           flag: StoredValidatorKeyFlag): ValidatorListItem {.
     raises: [Defect].} =
  ValidatorListItem(pubkey: key, status: $flag)

proc listValidators*(conf: AnyConf): seq[StoredValidatorKey] {.
     raises: [Defect].} =
  var validators: seq[StoredValidatorKey]
  try:
    for kind, file in walkDir(conf.validatorsDir()):
      if kind == pcDir:
        let keyName = splitFile(file).name
        let rkey = ValidatorPubKey.fromHex(keyName)
        if rkey.isErr():
          # Skip folders which represents invalid public key
          continue
        let secretFile = conf.secretsDir() / keyName
        let keystoreFile = conf.validatorsDir() / keyName / KeystoreFileName
        let disableFile = conf.validatorsDir() / keyName / DisableFileName
        let flag =
          if fileExists(secretFile):
            if checkSensitiveFilePermissions(secretFile):
              if not(fileExists(disableFile)):
                StoredValidatorKeyFlag.Valid
              else:
                StoredValidatorKeyFlag.Disabled
            else:
              StoredValidatorKeyFlag.NoPermission
          else:
            StoredValidatorKeyFlag.NoPassword
        let item = StoredValidatorKey(name: keyName, filename: keystoreFile,
                                      flag: flag, pubkey: rkey.get())
        validators.add(item)
    validators
  except OSError:
    return validators

func getPubKey*(privkey: ValidatorPrivKey): KmResult[ValidatorPubKey] {.
     raises: [Defect].} =
  ## Derive a public key from a private key
  var pubKey: blscurve.PublicKey
  let ok = publicFromSecret(pubKey, SecretKey privkey)
  if not(ok):
    return err("Invalid private key or zero key")
  ok(ValidatorPubKey(blob: pubKey.exportRaw()))

proc addValidator(pool: var ValidatorPool,
                  rng: var BrHmacDrbgContext,
                  conf: AnyConf, keystore: Keystore,
                  password: string): KmResult[void] {.
     raises: [Defect].} =
  let keypass = KeystorePass.init(password)
  let privateKey =
    block:
      let res = decryptKeystore(keystore, keypass)
      if res.isOk():
        res.get()
      else:
        return err("Keystore decryption failed")

  let publicKey = ? privateKey.getPubKey()
  let keyName = publicKey.toHex()

  let secretFile = conf.secretsDir() / keyName
  let keystorePath = conf.validatorsDir() / keyName
  let keystoreFile = keystorePath / KeystoreFileName

  if fileExists(keystoreFile) or fileExists(secretFile):
    return err("Keystore artifacts already exists")

  let plainStorage = createKeystore(kdfScrypt, rng, privateKey, keypass)

  let encodedStorage =
    try:
      Json.encode(plainStorage)
    except SerializationError:
      error "Could not serialize keystore", key_path = keystoreFile
      return err("Could not serialize keystore")

  let cleanupSecretsDir =
    if not(dirExists(conf.secretsDir())):
      let res = secureCreatePath(conf.secretsDir())
      if res.isErr():
        return err("Unable to create data secrets folder")
      true
    else:
      false

  let cleanupValidatorsDir =
    if not(dirExists(conf.validatorsDir())):
      let res = secureCreatePath(conf.validatorsDir())
      if res.isErr():
        if cleanupSecretsDir: discard io2.removeDir(conf.secretsDir())
        return err("Unable to create data validators folder")
      true
    else:
      false

  block:
    let res = secureCreatePath(keystorePath)
    if res.isErr():
      if cleanupSecretsDir: discard io2.removeDir(conf.secretsDir())
      if cleanupValidatorsDir: discard io2.removeDir(conf.validatorsDir())
      return err("Unable to create folder for keystore")

  block:
    let res = secureWriteFile(secretFile, keypass.str)
    if res.isErr():
      discard io2.removeDir(keystorePath)
      if cleanupSecretsDir: discard io2.removeDir(conf.secretsDir())
      if cleanupValidatorsDir: discard io2.removeDir(conf.validatorsDir())
      return err("Could not store password file")

  block:
    let res = secureWriteFile(keystoreFile, encodedStorage)
    if res.isErr():
      discard io2.removeFile(secretFile)
      discard io2.removeDir(keystorePath)
      if cleanupSecretsDir: discard io2.removeDir(conf.secretsDir())
      if cleanupValidatorsDir: discard io2.removeDir(conf.validatorsDir())
      return err("Could not store keystore file")

  pool.addLocalValidator(privateKey)
  ok()

proc removeValidator(pool: var ValidatorPool, conf: AnyConf,
                     publicKey: ValidatorPubKey): KmResult[void] {.
     raises: [Defect].} =
  let keyName = publicKey.toHex()
  let keystorePath = conf.validatorsDir() / keyName
  let keystoreFile = keystorePath / KeystoreFileName
  let secretFile = conf.secretsDir() / keyName
  try:
    removeDir(keystorePath, false)
  except OSError:
    return err("Could not remove keystore directory")
  if dirExists(keystorePath):
    return err("Could not remove keystore directory")
  let res = io2.removeFile(secretFile)
  if res.isErr():
    return err("Could not remove password file")
  pool.removeValidator(publicKey)
  ok()

proc toggleValidator(pool: var ValidatorPool,
                     conf: AnyConf,
                     publicKey: ValidatorPubKey,
                     action: ValidatorToggleAction): KmResult[void] {.
     raises:[Defect].} =
  let keyName = publicKey.toHex()
  let keystorePath = conf.validatorsDir() / keyName
  let disableFile = keystorePath / DisableFileName
  let secretFile = conf.secretsDir() / keyName
  let keystoreFile = keystorePath / KeystoreFileName

  if dirExists(keystorePath) and checkSensitivePathPermissions(keyStorePath):
    case action
    of ValidatorToggleAction.Enable:
      if fileExists(disableFile):
        if checkSensitivePathPermissions(secretFile) and
           checkSensitivePathPermissions(keystoreFile):
          let privateKey =
            block:
              let res = loadKeystoreUnsafe(conf.validatorsDir(),
                                           conf.secretsDir(), keyName)
              if res.isErr():
                return err("Could not decrypt validator's keystore")
              res.get()
          let res = io2.removeFile(disableFile)
          if res.isErr():
            return err("Could not enable validator's keystore")
          if isNil(pool.getValidator(publicKey)):
            pool.addLocalValidator(privateKey)
          ok()
        else:
          err("Could not read validator's keystore")
      else:
        # Disable file is already missing.
        if isNil(pool.getValidator(publicKey)):
          # If validator pool do not have ``publicKey`` validator we going to
          # add it.
          if checkSensitivePathPermissions(secretFile) and
             checkSensitivePathPermissions(keystoreFile):
            let privateKey =
              block:
                let res = loadKeystoreUnsafe(conf.validatorsDir(),
                                             conf.secretsDir(), keyName)
                if res.isErr():
                  return err("Could not decrypt validator's keystore")
                res.get()
            if isNil(pool.getValidator(publicKey)):
              pool.addLocalValidator(privateKey)
            ok()
          else:
            err("Could not read validator's keystore")
        else:
          ok()
    of ValidatorToggleAction.Disable:
      if not(fileExists(disableFile)):
        # Disable file is not present, we first create `.disable` file and in
        # case of success we removing validator from validators pool.
        block:
          let res = secureWriteFile(disableFile, DisableFileContent)
          if res.isErr():
            return err("Could not create disable file")
        pool.removeValidator(publicKey)
        ok()
      else:
        # Disable file is already present.
        pool.removeValidator(publicKey)
        ok()
  else:
    err("No validator keystore found")

proc installValidatorManagementHandlers*(router: var RestRouter,
                                         node: BeaconNode) =
  router.api(MethodGet, "/api/nimbus/v1/validators") do (
    ) -> RestApiResponse:
    let validators = node.config.listValidators().mapIt(
      ValidatorListItem.init(it.pubkey, it.flag)
    )
    return RestApiResponse.jsonResponse(validators)

  router.api(MethodPost, "/api/nimbus/v1/validators") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let keystores =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(seq[ValidatorKeystoreItem], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, InvalidKeystoreObjects,
                                           $dres.error())
        dres.get()

    var failures: seq[RestFailureItem]
    for index, item in keystores.pairs():
      let res = addValidator(node.attachedValidators[], node.network.rng[],
                             node.config, item.keystore, item.password)
      if res.isErr():
        failures.add(RestFailureItem(index: uint64(index),
                                     message: $res.error()))
    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400, KeystoreAdditionFailure,
                                           failures)
    else:
      return RestApiResponse.jsonMsgResponse(KeystoreAdditionSuccess)

  router.api(MethodPost, "/api/nimbus/v1/validators/enable") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let keys =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(seq[ValidatorPubKey], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, InvalidValidatorPublicKey,
                                           $dres.error())
        dres.get()

    var failures: seq[RestFailureItem]
    for index, key in keys.pairs():
      let res = toggleValidator(node.attachedValidators[], node.config, key,
                                ValidatorToggleAction.Enable)
      if res.isErr():
        failures.add(RestFailureItem(index: uint64(index),
                                     message: $res.error()))
    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400, KeystoreModificationFailure,
                                           failures)
    else:
      return RestApiResponse.jsonMsgResponse(KeystoreModificationSuccess)

  router.api(MethodPost, "/api/nimbus/v1/validators/disable") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let keys =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(seq[ValidatorPubKey], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, InvalidValidatorPublicKey,
                                           $dres.error())
        dres.get()

    var failures: seq[RestFailureItem]
    for index, key in keys.pairs():
      let res = toggleValidator(node.attachedValidators[], node.config, key,
                                ValidatorToggleAction.Disable)
      if res.isErr():
        failures.add(RestFailureItem(index: uint64(index),
                                     message: $res.error()))
    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400, KeystoreModificationFailure,
                                           failures)
    else:
      return RestApiResponse.jsonMsgResponse(KeystoreModificationSuccess)

  router.api(MethodPost, "/api/nimbus/v1/validators/remove") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let keys =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http404, EmptyRequestBodyError)
        let dres = decodeBody(seq[ValidatorPubKey], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, InvalidValidatorPublicKey,
                                           $dres.error())
        dres.get()

    var failures: seq[RestFailureItem]
    for index, key in keys.pairs():
      let res = removeValidator(node.attachedValidators[], node.config, key)
      if res.isErr():
        failures.add(RestFailureItem(index: uint64(index),
                                     message: $res.error()))
    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400, KeystoreRemovalFailure,
                                           failures)
    else:
      return RestApiResponse.jsonMsgResponse(KeystoreRemovalSuccess)

  router.redirect(
    MethodGet,
    "/nimbus/v1/validators",
    "/api/nimbus/v1/validators"
  )

  router.redirect(
    MethodPost,
    "/nimbus/v1/validators",
    "/api/nimbus/v1/validators"
  )

  router.redirect(
    MethodPost,
    "/nimbus/v1/validators/enable",
    "/api/nimbus/v1/validators/enable"
  )

  router.redirect(
    MethodPost,
    "/nimbus/v1/validators/disable",
    "/api/nimbus/v1/validators/disable"
  )

  router.redirect(
    MethodPost,
    "/nimbus/v1/validators/remove",
    "/api/nimbus/v1/validators/remove"
  )
