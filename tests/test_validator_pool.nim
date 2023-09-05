# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[algorithm, sequtils],
  chronos/unittest2/asynctests,
  presto, confutils,
  ../beacon_chain/validators/[validator_pool, keystore_management],
  ../beacon_chain/[conf, beacon_node]

func createPubKey(number: int8): ValidatorPubKey =
  var res = ValidatorPubKey()
  res.blob[0] = uint8(number)
  res

func createLocal(pubkey: ValidatorPubKey): KeystoreData =
  KeystoreData(kind: KeystoreKind.Local, pubkey: pubkey)

func createRemote(pubkey: ValidatorPubKey): KeystoreData =
  KeystoreData(kind: KeystoreKind.Remote, pubkey: pubkey)

func createDynamic(url: Uri, pubkey: ValidatorPubKey): KeystoreData =
  KeystoreData(kind: KeystoreKind.Remote, pubkey: pubkey,
               remotes: @[RemoteSignerInfo(url: HttpHostUri(url))],
               flags: {RemoteKeystoreFlag.DynamicKeystore})

const
  remoteSignerUrl = parseUri("http://nimbus.team/signer1")

func makeValidatorAndIndex(
    index: ValidatorIndex, activation_epoch: Epoch): Opt[ValidatorAndIndex] =
  Opt.some ValidatorAndIndex(
    index: index,
    validator: Validator(activation_epoch: activation_epoch)
  )

func cmp(a, b: array[48, byte]): int =
  for index, ch in a.pairs():
    if ch < b[index]:
      return -1
    elif ch > b[index]:
      return 1
  0

func cmp(a, b: KeystoreData): int =
  if (a.kind == b.kind) and (a.pubkey == b.pubkey):
    if a.kind == KeystoreKind.Remote:
      if a.flags == b.flags:
        0
      else:
        card(a.flags) - card(b.flags)
    else:
      0
  else:
    cmp(a.pubkey.blob, b.pubkey.blob)

func checkResponse(a, b: openArray[KeystoreData]): bool =
  if len(a) != len(b): return false
  for index, item in a.pairs():
    if cmp(item, b[index]) != 0:
      return false
  true

suite "Validator pool":
  test "Doppelganger for genesis validator":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)

    check:
      not v.triggersDoppelganger(GENESIS_EPOCH) # no check
      not v.doppelgangerReady(GENESIS_EPOCH.start_slot) # no activation

    v.updateValidator(makeValidatorAndIndex(ValidatorIndex(1), GENESIS_EPOCH))

    check:
      not v.triggersDoppelganger(GENESIS_EPOCH) # no check
      v.doppelgangerReady(GENESIS_EPOCH.start_slot) # ready in activation epoch
      not v.doppelgangerReady((GENESIS_EPOCH + 1).start_slot) # old check

    v.doppelgangerChecked(GENESIS_EPOCH)

    check:
      v.triggersDoppelganger(GENESIS_EPOCH) # checked, triggered
      v.doppelgangerReady((GENESIS_EPOCH + 1).start_slot) # checked
      v.doppelgangerReady((GENESIS_EPOCH + 2).start_slot) # 1 slot lag allowance
      not v.doppelgangerReady((GENESIS_EPOCH + 2).start_slot + 1) # old check

  test "Doppelganger for validator that activates in same epoch as check":
    let
      v = AttachedValidator(activationEpoch: FAR_FUTURE_EPOCH)
      now = Epoch(10).start_slot()

    check: # We don't know when validator activates so we wouldn't trigger
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      not v.doppelgangerReady(now)

    v.updateValidator(makeValidatorAndIndex(ValidatorIndex(5), FAR_FUTURE_EPOCH))

    check: # We still don't know when validator activates so we wouldn't trigger
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      not v.doppelgangerReady(now)

    v.updateValidator(makeValidatorAndIndex(ValidatorIndex(5), now.epoch()))

    check: # No check done yet
      not v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      v.doppelgangerReady(now)

    v.doppelgangerChecked(GENESIS_EPOCH)

    check:
      v.triggersDoppelganger(GENESIS_EPOCH)
      not v.triggersDoppelganger(now.epoch())

      not v.doppelgangerReady(GENESIS_EPOCH.start_slot)
      v.doppelgangerReady(now)

  asyncTest "Dynamic validator set: queryValidatorsSource() test":
    proc makeJson(keys: openArray[ValidatorPubKey]): string =
      var res = "["
      res.add(keys.mapIt("\"0x" & it.toHex() & "\"").join(","))
      res.add("]")
      res

    var testStage = 0
    proc testValidate(pattern: string, value: string): int = 0
    var router = RestRouter.init(testValidate)
    router.api(MethodGet, "/api/v1/eth2/publicKeys") do () -> RestApiResponse:
      case testStage
      of 0:
        let data = [createPubKey(1), createPubKey(2)].makeJson()
        return RestApiResponse.response(data, Http200, "application/json")
      of 1:
        let data = [createPubKey(1)].makeJson()
        return RestApiResponse.response(data, Http200, "application/json")
      of 2:
        var data: seq[ValidatorPubKey]
        return RestApiResponse.response(data.makeJson(), Http200,
                                        "application/json")
      else:
        return RestApiResponse.response("INCORRECT TEST STAGE", Http400,
                                        "text/plain")

    var sres = RestServerRef.new(router, initTAddress("127.0.0.1:0"))
    let
      server = sres.get()
      serverAddress = server.server.instance.localAddress()
      config =
        try:
          BeaconNodeConf.load(cmdLine =
            mapIt(["--web3-signer-url=http://" & $serverAddress], it))
        except Exception as exc:
          raiseAssert exc.msg

    server.start()
    try:
      block:
        testStage = 0
        let res = await queryValidatorsSource(config.web3signers[0])
        check:
          res.isOk()
          checkResponse(
            res.get(),
            [
              createDynamic(remoteSignerUrl, createPubKey(1)),
              createDynamic(remoteSignerUrl, createPubKey(2))
            ])
      block:
        testStage = 1
        let res = await queryValidatorsSource(config.web3signers[0])
        check:
          res.isOk()
          checkResponse(res.get(), [createDynamic(remoteSignerUrl, createPubKey(1))])
      block:
        testStage = 2
        let res = await queryValidatorsSource(config.web3signers[0])
        check:
          res.isOk()
          len(res.get()) == 0
      block:
        testStage = 3
        let res = await queryValidatorsSource(config.web3signers[0])
        check:
          res.isErr()
    finally:
      await server.closeWait()

  test "Dynamic validator set: updateDynamicValidators() test":
    let
      fee = default(Eth1Address)
      gas = 30000000'u64

    proc checkPool(pool: ValidatorPool, expected: openArray[KeystoreData]) =
      let
        attachedKeystores =
          block:
            var res: seq[KeystoreData]
            for validator in pool:
              res.add(validator.data)
            sorted(res, cmp)
        sortedExpected = sorted(expected, cmp)

      for index, value in attachedKeystores:
        check cmp(value, sortedExpected[index]) == 0

    var pool = (ref ValidatorPool)()
    discard pool[].addValidator(createLocal(createPubKey(1)), fee, gas)
    discard pool[].addValidator(createRemote(createPubKey(2)), fee, gas)
    discard pool[].addValidator(createDynamic(remoteSignerUrl, createPubKey(3)), fee, gas)

    proc addValidator(data: KeystoreData) {.gcsafe.} =
      discard pool[].addValidator(data, fee, gas)

    # Adding new dynamic keystores.
    block:
      let
        expected = [
          createLocal(createPubKey(1)),
          createRemote(createPubKey(2)),
          createDynamic(remoteSignerUrl, createPubKey(3)),
          createDynamic(remoteSignerUrl, createPubKey(4)),
          createDynamic(remoteSignerUrl, createPubKey(5))
        ]
        keystores = [
          createDynamic(remoteSignerUrl, createPubKey(3)),
          createDynamic(remoteSignerUrl, createPubKey(4)),
          createDynamic(remoteSignerUrl, createPubKey(5))
        ]
      pool.updateDynamicValidators(remoteSignerUrl, keystores, addValidator)
      pool[].checkPool(expected)

    # Removing dynamic keystores.
    block:
      let
        expected = [
          createLocal(createPubKey(1)),
          createRemote(createPubKey(2)),
          createDynamic(remoteSignerUrl, createPubKey(3))
        ]
        keystores = [
          createDynamic(remoteSignerUrl, createPubKey(3)),
        ]
      pool.updateDynamicValidators(remoteSignerUrl, keystores, addValidator)
      pool[].checkPool(expected)

    # Adding and removing keystores at same time.
    block:
      let
        expected = [
          createLocal(createPubKey(1)),
          createRemote(createPubKey(2)),
          createDynamic(remoteSignerUrl, createPubKey(4)),
          createDynamic(remoteSignerUrl, createPubKey(5))
        ]
        keystores = [
          createDynamic(remoteSignerUrl, createPubKey(4)),
          createDynamic(remoteSignerUrl, createPubKey(5))
        ]
      pool.updateDynamicValidators(remoteSignerUrl, keystores, addValidator)
      pool[].checkPool(expected)

    # Adding dynamic keystores with keys which are static.
    block:
      let
        expected = [
          createLocal(createPubKey(1)),
          createRemote(createPubKey(2)),
          createDynamic(remoteSignerUrl, createPubKey(3))
        ]
        keystores = [
          createDynamic(remoteSignerUrl, createPubKey(1)),
          createDynamic(remoteSignerUrl, createPubKey(2)),
          createDynamic(remoteSignerUrl, createPubKey(3)),
        ]
      pool.updateDynamicValidators(remoteSignerUrl, keystores, addValidator)
      pool[].checkPool(expected)

    # Empty response
    block:
      let
        expected = [
          createLocal(createPubKey(1)),
          createRemote(createPubKey(2))
        ]
      var keystores: seq[KeystoreData]
      pool.updateDynamicValidators(remoteSignerUrl, keystores, addValidator)
      pool[].checkPool(expected)
