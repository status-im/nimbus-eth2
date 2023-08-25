# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/strutils
import chronos/unittest2/asynctests
import ../beacon_chain/validator_client/[api, common, scoring, fallback_service]

const
  HostNames = [
    "[2001:db8::1]",
    "127.0.0.1",
    "hostname.com",
    "localhost",
    "username:password@[2001:db8::1]",
    "username:password@127.0.0.1",
    "username:password@hostname.com",
    "username:password@localhost",
  ]

  GoodTestVectors = [
    ("http://$1",
     "ok(http://$1)"),
    ("http://$1?q=query",
     "ok(http://$1?q=query)"),
    ("http://$1?q=query#anchor",
     "ok(http://$1?q=query#anchor)"),
    ("http://$1/subpath/",
     "ok(http://$1/subpath/)"),
    ("http://$1/subpath/q=query",
     "ok(http://$1/subpath/q=query)"),
    ("http://$1/subpath/q=query#anchor",
     "ok(http://$1/subpath/q=query#anchor)"),
    ("http://$1/subpath",
     "ok(http://$1/subpath)"),
    ("http://$1/subpath?q=query",
     "ok(http://$1/subpath?q=query)"),
    ("http://$1/subpath?q=query#anchor",
     "ok(http://$1/subpath?q=query#anchor)"),

    ("https://$1",
     "ok(https://$1)"),
    ("https://$1?q=query",
     "ok(https://$1?q=query)"),
    ("https://$1?q=query#anchor",
     "ok(https://$1?q=query#anchor)"),
    ("https://$1/subpath/",
     "ok(https://$1/subpath/)"),
    ("https://$1/subpath/q=query",
     "ok(https://$1/subpath/q=query)"),
    ("https://$1/subpath/q=query#anchor",
     "ok(https://$1/subpath/q=query#anchor)"),
    ("https://$1/subpath",
     "ok(https://$1/subpath)"),
    ("https://$1/subpath?q=query",
     "ok(https://$1/subpath?q=query)"),
    ("https://$1/subpath?q=query#anchor",
     "ok(https://$1/subpath?q=query#anchor)"),

    ("$1:5052",
     "ok(http://$1:5052)"),
    ("$1:5052?q=query",
     "ok(http://$1:5052?q=query)"),
    ("$1:5052?q=query#anchor",
     "ok(http://$1:5052?q=query#anchor)"),
    ("$1:5052/subpath/",
     "ok(http://$1:5052/subpath/)"),
    ("$1:5052/subpath/q=query",
     "ok(http://$1:5052/subpath/q=query)"),
    ("$1:5052/subpath/q=query#anchor",
     "ok(http://$1:5052/subpath/q=query#anchor)"),
    ("$1:5052/subpath",
     "ok(http://$1:5052/subpath)"),
    ("$1:5052/subpath?q=query",
     "ok(http://$1:5052/subpath?q=query)"),
    ("$1:5052/subpath?q=query#anchor",
     "ok(http://$1:5052/subpath?q=query#anchor)"),

    ("bnode://$1:5052",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052?q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052?q=query#anchor",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/q=query#anchor",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath?q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath?q=query#anchor",
     "err(Unknown scheme value)"),

    ("//$1:5052",
     "ok(http://$1:5052)"),
    ("//$1:5052?q=query",
     "ok(http://$1:5052?q=query)"),
    ("//$1:5052?q=query#anchor",
     "ok(http://$1:5052?q=query#anchor)"),
    ("//$1:5052/subpath/",
     "ok(http://$1:5052/subpath/)"),
    ("//$1:5052/subpath/q=query",
     "ok(http://$1:5052/subpath/q=query)"),
    ("//$1:5052/subpath/q=query#anchor",
     "ok(http://$1:5052/subpath/q=query#anchor)"),
    ("//$1:5052/subpath",
     "ok(http://$1:5052/subpath)"),
    ("//$1:5052/subpath?q=query",
     "ok(http://$1:5052/subpath?q=query)"),
    ("//$1:5052/subpath?q=query#anchor",
     "ok(http://$1:5052/subpath?q=query#anchor)"),

    ("//$1", "err(Missing port number)"),
    ("//$1?q=query", "err(Missing port number)"),
    ("//$1?q=query#anchor", "err(Missing port number)"),
    ("//$1/subpath/", "err(Missing port number)"),
    ("//$1/subpath/q=query", "err(Missing port number)"),
    ("//$1/subpath/q=query#anchor", "err(Missing port number)"),
    ("//$1/subpath", "err(Missing port number)"),
    ("//$1/subpath?q=query", "err(Missing port number)"),
    ("//$1/subpath?q=query#anchor", "err(Missing port number)"),

    ("$1", "err(Missing port number)"),
    ("$1?q=query", "err(Missing port number)"),
    ("$1?q=query#anchor", "err(Missing port number)"),
    ("$1/subpath/", "err(Missing port number)"),
    ("$1/subpath/q=query", "err(Missing port number)"),
    ("$1/subpath/q=query#anchor", "err(Missing port number)"),
    ("$1/subpath", "err(Missing port number)"),
    ("$1/subpath?q=query", "err(Missing port number)"),
    ("$1/subpath?q=query#anchor", "err(Missing port number)"),

    ("", "err(Missing hostname)")
  ]

type
  AttestationDataTuple* = tuple[
    slot: uint64,
    index: uint64,
    beacon_block_root: string,
    source: uint64,
    target: uint64
  ]

const
  AttestationDataVectors = [
    # Attestation score with block monitoring enabled (perfect).
    ((6002798'u64, 10'u64, "22242212", 187586'u64, 187587'u64),
     ("22242212", 6002798'u64), "<perfect>"),
    ((6002811'u64, 24'u64, "26ec78d6", 187586'u64, 187587'u64),
     ("26ec78d6", 6002811'u64), "<perfect>"),
    ((6002821'u64, 11'u64, "10c6d1a2", 187587'u64, 187588'u64),
     ("10c6d1a2", 6002821'u64), "<perfect>"),
    ((6002836'u64, 15'u64, "42354ded", 187587'u64, 187588'u64),
     ("42354ded", 6002836'u64), "<perfect>"),
    ((6002859'u64, 10'u64, "97d8ac69", 187588'u64, 187589'u64),
     ("97d8ac69", 6002859'u64), "<perfect>"),
    # Attestation score with block monitoring enabled #1 (not perfect).
    ((6002871'u64, 25'u64, "524a9e2b", 187588'u64, 187589'u64),
     ("524a9e2b", 6002870'u64), "375177.5000"),
    ((6002871'u64, 25'u64, "524a9e2b", 187588'u64, 187589'u64),
     ("524a9e2b", 6002869'u64), "375177.3333"),
    ((6002871'u64, 25'u64, "524a9e2b", 187588'u64, 187589'u64),
     ("524a9e2b", 6002868'u64), "375177.2500"),
    ((6002871'u64, 25'u64, "524a9e2b", 187588'u64, 187589'u64),
     ("524a9e2b", 6002867'u64), "375177.2000"),
    ((6002871'u64, 25'u64, "524a9e2b", 187588'u64, 187589'u64),
     ("524a9e2b", 6002866'u64), "375177.1667"),
    # Attestation score with block monitoring enabled #2 (not perfect).
    ((6002962'u64, 14'u64, "22a19d87", 187591'u64, 187592'u64),
     ("22a19d87", 6002961'u64), "375183.5000"),
    ((6002962'u64, 14'u64, "22a19d87", 187591'u64, 187592'u64),
     ("22a19d87", 6002960'u64), "375183.3333"),
    ((6002962'u64, 14'u64, "22a19d87", 187591'u64, 187592'u64),
     ("22a19d87", 6002959'u64), "375183.2500"),
    ((6002962'u64, 14'u64, "22a19d87", 187591'u64, 187592'u64),
     ("22a19d87", 6002958'u64), "375183.2000"),
    ((6002962'u64, 14'u64, "22a19d87", 187591'u64, 187592'u64),
     ("22a19d87", 6002957'u64), "375183.1667"),
    # Attestation score with block monitoring disabled #1.
    ((6003217'u64, 52'u64, "5e945218", 187599'u64, 187600'u64),
     ("00000000", 0'u64), "375199.0000"),
    ((6003217'u64, 52'u64, "5e945218", 187598'u64, 187600'u64),
     ("00000000", 0'u64), "375198.0000"),
    ((6003217'u64, 52'u64, "5e945218", 187597'u64, 187600'u64),
     ("00000000", 0'u64), "375197.0000"),
    ((6003217'u64, 52'u64, "5e945218", 187596'u64, 187600'u64),
     ("00000000", 0'u64), "375196.0000"),
    ((6003217'u64, 52'u64, "5e945218", 187595'u64, 187600'u64),
     ("00000000", 0'u64), "375195.0000"),
    # Attestation score with block monitoring disabled #2.
    ((6003257'u64, 9'u64, "7bfa464e", 187600'u64, 187601'u64),
     ("00000000", 0'u64), "375201.0000"),
    ((6003257'u64, 9'u64, "7bfa464e", 187599'u64, 187601'u64),
     ("00000000", 0'u64), "375200.0000"),
    ((6003257'u64, 9'u64, "7bfa464e", 187598'u64, 187601'u64),
     ("00000000", 0'u64), "375199.0000"),
    ((6003257'u64, 9'u64, "7bfa464e", 187597'u64, 187601'u64),
     ("00000000", 0'u64), "375198.0000"),
    ((6003257'u64, 9'u64, "7bfa464e", 187596'u64, 187601'u64),
     ("00000000", 0'u64), "375197.0000"),
  ]

proc init(t: typedesc[Eth2Digest], data: string): Eth2Digest =
  let length = len(data)
  var dst = Eth2Digest()
  try:
    hexToByteArray(data.toOpenArray(0, len(data) - 1),
                   dst.data.toOpenArray(0, (length div 2) - 1))
  except ValueError:
    discard
  dst

proc init*(t: typedesc[ProduceAttestationDataResponse],
           ad: AttestationDataTuple): ProduceAttestationDataResponse =
  ProduceAttestationDataResponse(data: AttestationData(
    slot: Slot(ad.slot), index: ad.index,
    beacon_block_root: Eth2Digest.init(ad.beacon_block_root),
    source: Checkpoint(epoch: Epoch(ad.source)),
    target: Checkpoint(epoch: Epoch(ad.target))
  ))

proc createRootsSeen(
       root: tuple[root: string, slot: uint64]): Table[Eth2Digest, Slot] =
  var res: Table[Eth2Digest, Slot]
  res[Eth2Digest.init(root.root)] = Slot(root.slot)
  res

suite "Validator Client test suite":
  test "normalizeUri() test vectors":
    for hostname in HostNames:
      for vector in GoodTestVectors:
        let expect = vector[1] % (hostname)
        check $normalizeUri(parseUri(vector[0] % (hostname))) == expect

  test "getAttestationDataScore() test vectors":
    for vector in AttestationDataVectors:
      let
        adata = ProduceAttestationDataResponse.init(vector[0])
        roots = createRootsSeen(vector[1])
        score = shortScore(roots.getAttestationDataScore(adata))
      check score == vector[2]

  asyncTest "firstSuccessParallel() API timeout test":
    let
      uri = parseUri("http://127.0.0.1/")
      beaconNodes = @[BeaconNodeServerRef.init(uri, 0).tryGet()]
      vconf = ValidatorClientConf.load(
        cmdLine = mapIt(["--beacon-node=http://127.0.0.1"], it))
      epoch = Epoch(1)
      strategy = ApiStrategyKind.Priority

    var gotCancellation = false
    var vc = ValidatorClientRef(config: vconf, beaconNodes: beaconNodes)
    vc.fallbackService = await FallbackServiceRef.init(vc)

    proc getTestDuties(client: RestClientRef,
                       epoch: Epoch): Future[RestPlainResponse] {.async.} =
      try:
        await sleepAsync(1.seconds)
      except CancelledError as exc:
        gotCancellation = true
        raise exc

    const
      RequestName = "getTestDuties"

    let response = vc.firstSuccessParallel(
      RestPlainResponse,
      uint64,
      100.milliseconds,
      AllBeaconNodeStatuses,
      {BeaconNodeRole.Duties},
      getTestDuties(it, epoch)):
        check:
          apiResponse.isErr()
          apiResponse.error ==
            "Timeout exceeded while awaiting for the response"
        ApiResponse[uint64].err(apiResponse.error)

    check:
      response.isErr()
      gotCancellation == true

  asyncTest "bestSuccess() API timeout test":
    let
      uri = parseUri("http://127.0.0.1/")
      beaconNodes = @[BeaconNodeServerRef.init(uri, 0).tryGet()]
      vconf = ValidatorClientConf.load(
        cmdLine = mapIt(["--beacon-node=http://127.0.0.1"], it))
      epoch = Epoch(1)
      strategy = ApiStrategyKind.Priority

    var gotCancellation = false
    var vc = ValidatorClientRef(config: vconf, beaconNodes: beaconNodes)
    vc.fallbackService = await FallbackServiceRef.init(vc)

    proc getTestDuties(client: RestClientRef,
                       epoch: Epoch): Future[RestPlainResponse] {.async.} =
      try:
        await sleepAsync(1.seconds)
      except CancelledError as exc:
        gotCancellation = true
        raise exc

    proc getTestScore(data: uint64): float64 = Inf

    const
      RequestName = "getTestDuties"

    let response = vc.bestSuccess(
      RestPlainResponse,
      uint64,
      100.milliseconds,
      AllBeaconNodeStatuses,
      {BeaconNodeRole.Duties},
      getTestDuties(it, epoch),
      getTestScore(itresponse)):
        check:
          apiResponse.isErr()
          apiResponse.error ==
            "Timeout exceeded while awaiting for the response"
        ApiResponse[uint64].err(apiResponse.error)

    check:
      response.isErr()
      gotCancellation == true
