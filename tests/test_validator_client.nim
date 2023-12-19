# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/strutils
import httputils
import chronos/unittest2/asynctests
import ../beacon_chain/spec/eth2_apis/eth2_rest_serialization,
       ../beacon_chain/validator_client/[api, common, scoring, fallback_service]

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

  ObolBeaconRequestTestVector = """
[
  {
    "validator_index": "1",
    "slot": "1",
    "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "slot": "2",
    "validator_index": "2",
    "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "validator_index": "3",
    "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
    "slot": "3"
  },
  {
    "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
    "validator_index": "4",
    "slot": "4"
  }
]"""
  ObolBeaconResponseTestVector = """
{
  "data": [
    {
      "validator_index": "1",
      "slot": "1",
      "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "2",
      "slot": "2",
      "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "3",
      "slot": "3",
      "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "4",
      "slot": "4",
      "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    }
  ]
}"""
  ObolBeaconResponseTestVectorObject = [
    (
      validator_index: RestValidatorIndex(1),
      slot: Slot(1),
      selection_proof: "1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(2),
      slot: Slot(2),
      selection_proof: "2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(3),
      slot: Slot(3),
      selection_proof: "3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(4),
      slot: Slot(4),
      selection_proof: "4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    )
  ]
  ObolSyncRequestTestVector = """
[
  {
    "validator_index": "1",
    "slot": "1",
    "subcommittee_index": "1",
    "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "validator_index": "2",
    "subcommittee_index": "2",
    "slot": "2",
    "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "subcommittee_index": "3",
    "validator_index": "3",
    "slot": "3",
    "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "validator_index": "4",
    "slot": "4",
    "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
    "subcommittee_index": "4"
  }
]"""
  ObolSyncResponseTestVector = """
{
  "data": [
    {
      "validator_index": "1",
      "slot": "1",
      "subcommittee_index": "1",
      "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "2",
      "subcommittee_index": "2",
      "slot": "2",
      "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "subcommittee_index": "3",
      "validator_index": "3",
      "slot": "3",
      "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "4",
      "slot": "4",
      "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
      "subcommittee_index": "4"
    }
  ]
}"""
  ObolSyncResponseTestVectorObject = [
    (
      validator_index: RestValidatorIndex(1),
      slot: Slot(1),
      subcommittee_index: 1'u64,
      selection_proof: "1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(2),
      slot: Slot(2),
      subcommittee_index: 2'u64,
      selection_proof: "2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(3),
      slot: Slot(3),
      subcommittee_index: 3'u64,
      selection_proof: "3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(4),
      slot: Slot(4),
      subcommittee_index: 4'u64,
      selection_proof: "4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    )
  ]

type
  TestDecodeTypes = seq[RestBeaconCommitteeSelection] |
                    seq[RestSyncCommitteeSelection]

  AttestationDataTuple* = tuple[
    slot: uint64,
    index: uint64,
    beacon_block_root: string,
    source: uint64,
    target: uint64
  ]

  AttestationBitsObject = object
    data: CommitteeValidatorsBits

  SyncCommitteeBitsObject = object
    data: SyncCommitteeAggregationBits

RestJson.useDefaultSerializationFor(
  AttestationBitsObject,
  SyncCommitteeBitsObject
)

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

  AggregatedDataVectors = [
    ("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01", "<perfect>"),
    ("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "0.2500"),
    ("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "0.5000"),
    ("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "0.7500"),
    ("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01", "0.9995"),
    ("0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101", "0.0005"),
  ]
  ContributionDataVectors = [
    ("0xffffffffffffffffffffffffffff7f7f", "0.9844"),
    ("0xffffffffffffffffffffffff7f7f7f7f", "0.9688"),
    ("0xffffffffffffffffffff7f7f7f7f7f7f", "0.9531"),
    ("0xffffffffffffffff7f7f7f7f7f7f7f7f", "0.9375"),
    ("0xffffffffffff7f7f7f7f7f7f7f7f7f7f", "0.9219"),
    ("0xffffffff7f7f7f7f7f7f7f7f7f7f7f7f", "0.9062"),
    ("0xffff7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "0.8906"),
    ("0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "0.8750"),
    ("0xffffffffffffffffffffffffffffffff", "<perfect>")
  ]

  SyncMessageDataVectors = [
    # Sync committee messages score with block monitoring enabled (perfect)
    (6002798'u64, "22242212", "22242212", 6002798'u64, Opt.some(false),
     "<perfect>"),
    (6002811'u64, "26ec78d6", "26ec78d6", 6002811'u64, Opt.some(false),
     "<perfect>"),
    (6002836'u64, "42354ded", "42354ded", 6002836'u64, Opt.some(false),
     "<perfect>"),
    (6002859'u64, "97d8ac69", "97d8ac69", 6002859'u64, Opt.some(false),
     "<perfect>"),
    # Sync committee messages score when beacon node is optimistically synced
    (6002798'u64, "22242212", "22242212", 6002798'u64, Opt.some(true),
     "<bad>"),
    (6002811'u64, "26ec78d6", "26ec78d6", 6002811'u64, Opt.some(true),
     "<bad>"),
    (6002836'u64, "42354ded", "42354ded", 6002836'u64, Opt.some(true),
     "<bad>"),
    (6002859'u64, "97d8ac69", "97d8ac69", 6002859'u64, Opt.some(true),
     "<bad>"),
    # Sync committee messages score with block monitoring enabled (not perfect)
    (6002797'u64, "22242212", "22242212", 6002798'u64, Opt.some(false),
     "1.5000"),
    (6002809'u64, "26ec78d6", "26ec78d6", 6002811'u64, Opt.some(false),
     "1.3333"),
    (6002826'u64, "42354ded", "42354ded", 6002836'u64, Opt.some(false),
     "1.0909"),
    (6002819'u64, "97d8ac69", "97d8ac69", 6002859'u64, Opt.some(false),
     "1.0244"),
    # Sync committee messages score with block monitoring disabled
    (6002797'u64, "00000000", "22242212", 6002798'u64, Opt.some(false),
     "0.1334"),
    (6002809'u64, "00000000", "26ec78d6", 6002811'u64, Opt.some(false),
     "0.1520"),
    (6002826'u64, "00000000", "42354ded", 6002836'u64, Opt.some(false),
     "0.2586"),
    (6002819'u64, "00000000", "97d8ac69", 6002859'u64, Opt.some(false),
     "0.5931"),
  ]

  AttestationBitsVectors = [
    ([("0xff01", Slot(0), 0'u64), ("0xff01", Slot(0), 0'u64)], 8),
    ([("0xff01", Slot(0), 0'u64), ("0xff01", Slot(1), 0'u64)], 16),
    ([("0xff01", Slot(0), 0'u64), ("0xff01", Slot(0), 1'u64)], 16)
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

proc init(t: typedesc[ProduceAttestationDataResponse],
          ad: AttestationDataTuple): ProduceAttestationDataResponse =
  ProduceAttestationDataResponse(data: AttestationData(
    slot: Slot(ad.slot), index: ad.index,
    beacon_block_root: Eth2Digest.init(ad.beacon_block_root),
    source: Checkpoint(epoch: Epoch(ad.source)),
    target: Checkpoint(epoch: Epoch(ad.target))
  ))

proc init(t: typedesc[Attestation], bits: string,
          slot: Slot = GENESIS_SLOT, index: uint64 = 0'u64): Attestation =
  let
    jdata = "{\"data\":\"" & bits & "\"}"
    bits =
      try:
        RestJson.decode(jdata, AttestationBitsObject)
      except SerializationError as exc:
        raiseAssert "Serialization error from [" & $exc.name & "]: " & $exc.msg
  Attestation(aggregation_bits: bits.data,
              data: AttestationData(slot: slot, index: index))

proc init(t: typedesc[GetAggregatedAttestationResponse],
          bits: string): GetAggregatedAttestationResponse =
  GetAggregatedAttestationResponse(data: Attestation.init(bits))

proc init(t: typedesc[ProduceSyncCommitteeContributionResponse],
          bits: string): ProduceSyncCommitteeContributionResponse =
  let
    jdata = "{\"data\":\"" & bits & "\"}"
    bits =
      try:
        RestJson.decode(jdata, SyncCommitteeBitsObject)
      except SerializationError as exc:
        raiseAssert "Serialization error from [" & $exc.name & "]: " & $exc.msg
  ProduceSyncCommitteeContributionResponse(data: SyncCommitteeContribution(
    aggregation_bits: bits.data
  ))

proc init(t: typedesc[GetBlockRootResponse],
          optimistic: Opt[bool], root: Eth2Digest): GetBlockRootResponse =
  let optopt =
    if optimistic.isNone():
      none[bool]()
    else:
      some(optimistic.get())
  GetBlockRootResponse(data: RestRoot(root: root), execution_optimistic: optopt)

proc createRootsSeen(
       root: tuple[root: string, slot: uint64]): Table[Eth2Digest, Slot] =
  var res: Table[Eth2Digest, Slot]
  res[Eth2Digest.init(root.root)] = Slot(root.slot)
  res

suite "Validator Client test suite":

  proc decodeBytes[T: TestDecodeTypes](
       t: typedesc[T],
       value: openArray[byte],
       contentType: Opt[ContentTypeData] = Opt.none(ContentTypeData)
     ): RestResult[T] =
    let mediaType =
      if contentType.isNone():
        ApplicationJsonMediaType
      else:
        if isWildCard(contentType.get().mediaType):
          return err("Incorrect Content-Type")
        contentType.get().mediaType

    if mediaType == ApplicationJsonMediaType:
      try:
        ok RestJson.decode(value, T,
                           requireAllFields = true,
                           allowUnknownFields = true)
      except SerializationError:
        err("Serialization error")
    else:
      err("Content-Type not supported")

  proc submitBeaconCommitteeSelectionsPlain(
         body: seq[RestBeaconCommitteeSelection]
       ): RestPlainResponse {.
       rest, endpoint: "/eth/v1/validator/beacon_committee_selections",
       meth: MethodPost.}
    ## https://ethereum.github.io/beacon-APIs/#/Validator/submitBeaconCommitteeSelections

  proc submitSyncCommitteeSelectionsPlain(
         body: seq[RestSyncCommitteeSelection]
       ): RestPlainResponse {.
       rest, endpoint: "/eth/v1/validator/sync_committee_selections",
       meth: MethodPost.}
    ## https://ethereum.github.io/beacon-APIs/#/Validator/submitSyncCommitteeSelections

  proc createServer(address: TransportAddress,
                    process: HttpProcessCallback, secure: bool): HttpServerRef =
    let
      socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      res = HttpServerRef.new(address, process, socketFlags = socketFlags)
    res.get()

  test "normalizeUri() test vectors":
    for hostname in HostNames:
      for vector in GoodTestVectors:
        let expect = vector[1] % (hostname)
        check $normalizeUri(parseUri(vector[0] % (hostname))) == expect

  asyncTest "/eth/v1/validator/beacon_committee_selections " &
            "serialization/deserialization test":
    var clientRequest: seq[byte]
    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/eth/v1/validator/beacon_committee_selections":
          clientRequest = await request.getBody()
          let headers = HttpTable.init([("Content-Type", "application/json")])
          return await request.respond(Http200, ObolBeaconResponseTestVector,
                                       headers)
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return dumbResponse()

    let  server = createServer(initTAddress("127.0.0.1:0"), process, false)
    server.start()
    defer:
      await server.stop()
      await server.closeWait()

    let
      serverAddress = server.instance.localAddress
      flags = {RestClientFlag.CommaSeparatedArray}
      remoteUri = "http://" & $serverAddress
      client =
        block:
          let res = RestClientRef.new(remoteUri, flags = flags)
          check res.isOk()
          res.get()
      selections =
        block:
          let res = decodeBytes(
            seq[RestBeaconCommitteeSelection],
            ObolBeaconRequestTestVector.toOpenArrayByte(
              0, len(ObolBeaconRequestTestVector) - 1))
          check res.isOk()
          res.get()

    defer:
      await client.closeWait()

    let resp = await client.submitBeaconCommitteeSelectionsPlain(selections)
    check:
      resp.status == 200
      resp.contentType == MediaType.init("application/json")

    let request =
      block:
        let res = decodeBytes(
          seq[RestBeaconCommitteeSelection],
          clientRequest)
        check res.isOk()
        res.get()

    let response = block:
      let res = decodeBytes(SubmitBeaconCommitteeSelectionsResponse,
                            resp.data, resp.contentType)
      check res.isOk()
      res.get()

    check:
      len(request) == len(selections)
      len(response.data) == len(ObolBeaconResponseTestVectorObject)

    # Checking response
    for index, item in response.data.pairs():
      check:
        item.validator_index ==
          ObolBeaconResponseTestVectorObject[index].validator_index
        item.slot ==
          ObolBeaconResponseTestVectorObject[index].slot
        item.selection_proof.toHex() ==
          ObolBeaconResponseTestVectorObject[index].selection_proof

    # Checking request
    for index, item in selections.pairs():
      check:
        item.validator_index == request[index].validator_index
        item.slot == request[index].slot
        item.selection_proof.toHex() == request[index].selection_proof.toHex()

  asyncTest "/eth/v1/validator/sync_committee_selections " &
            "serialization/deserialization test":
    var clientRequest: seq[byte]
    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/eth/v1/validator/sync_committee_selections":
          clientRequest = await request.getBody()
          let headers = HttpTable.init([("Content-Type", "application/json")])
          return await request.respond(Http200, ObolSyncResponseTestVector,
                                       headers)
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return dumbResponse()

    let  server = createServer(initTAddress("127.0.0.1:0"), process, false)
    server.start()
    defer:
      await server.stop()
      await server.closeWait()

    let
      serverAddress = server.instance.localAddress
      flags = {RestClientFlag.CommaSeparatedArray}
      remoteUri = "http://" & $serverAddress
      client =
        block:
          let res = RestClientRef.new(remoteUri, flags = flags)
          check res.isOk()
          res.get()
      selections =
        block:
          let res = decodeBytes(
            seq[RestSyncCommitteeSelection],
            ObolSyncRequestTestVector.toOpenArrayByte(
              0, len(ObolSyncRequestTestVector) - 1))
          check res.isOk()
          res.get()

    defer:
      await client.closeWait()

    let resp = await client.submitSyncCommitteeSelectionsPlain(selections)
    check:
      resp.status == 200
      resp.contentType == MediaType.init("application/json")

    let request =
      block:
        let res = decodeBytes(
          seq[RestSyncCommitteeSelection],
          clientRequest)
        check res.isOk()
        res.get()

    let response = block:
      let res = decodeBytes(SubmitSyncCommitteeSelectionsResponse,
                            resp.data, resp.contentType)
      check res.isOk()
      res.get()

    check:
      len(request) == len(selections)
      len(response.data) == len(ObolSyncResponseTestVectorObject)

    # Checking response
    for index, item in response.data.pairs():
      check:
        item.validator_index ==
          ObolSyncResponseTestVectorObject[index].validator_index
        item.slot ==
          ObolSyncResponseTestVectorObject[index].slot
        item.selection_proof.toHex() ==
          ObolSyncResponseTestVectorObject[index].selection_proof
        item.subcommittee_index == request[index].subcommittee_index

    # Checking request
    for index, item in selections.pairs():
      check:
        item.validator_index == request[index].validator_index
        item.slot == request[index].slot
        item.subcommittee_index == request[index].subcommittee_index
        item.selection_proof.toHex() == request[index].selection_proof.toHex()

  test "getAttestationDataScore() test vectors":
    for vector in AttestationDataVectors:
      let
        adata = ProduceAttestationDataResponse.init(vector[0])
        roots = createRootsSeen(vector[1])
        score = shortScore(roots.getAttestationDataScore(adata))
      check score == vector[2]

  test "getAggregatedAttestationDataScore() test vectors":
    for vector in AggregatedDataVectors:
      let
        adata = GetAggregatedAttestationResponse.init(vector[0])
        score = shortScore(getAggregatedAttestationDataScore(adata))
      check score == vector[1]

  test "getSyncCommitteeContributionDataScore() test vectors":
    for vector in ContributionDataVectors:
      let
        adata = ProduceSyncCommitteeContributionResponse.init(vector[0])
        score = shortScore(getSyncCommitteeContributionDataScore(adata))
      check score == vector[1]

  test "getSyncCommitteeMessageDataScore() test vectors":
    for vector in SyncMessageDataVectors:
      let
        roots = createRootsSeen((vector[1], vector[0]))
        rdata = GetBlockRootResponse.init(vector[4], Eth2Digest.init(vector[2]))
        currentSlot = Slot(vector[3])
        score = shortScore(getSyncCommitteeMessageDataScore(roots, currentSlot,
                                                            rdata))
      check:
        score == vector[5]

  test "getUniqueVotes() test vectors":
    var data = CommitteeValidatorsBits.init(16)

    for vector in AttestationBitsVectors:
      let
        a1 = Attestation.init(vector[0][0][0], vector[0][0][1], vector[0][0][2])
        a2 = Attestation.init(vector[0][1][0], vector[0][1][1], vector[0][1][2])
      check getUniqueVotes([a1, a2]) == vector[1]

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

  test "getLiveness() response deserialization test":
    proc generateLivenessResponse(T: typedesc[string],
                                  start, count, modv: int): string =
      var res: seq[string]
      for index in start ..< (start + count):
        let
          validator = Base10.toString(uint64(index))
          visibility = if index mod modv == 0: "true" else: "false"
        res.add("{\"index\":\"" & validator & "\",\"is_live\":" &
                visibility & "}")
      "{\"data\":[" & res.join(",") & "]}"

    proc generateLivenessResponse(
      T: typedesc[RestLivenessItem],
      start, count, modv: int
    ): seq[RestLivenessItem] =
      var res: seq[RestLivenessItem]
      for index in start ..< (start + count):
        let visibility = if index mod modv == 0: true else: false
        res.add(RestLivenessItem(index: ValidatorIndex(uint64(index)),
                                 is_live: visibility))
      res

    const Tests = [(0, 2_000_000, 3)]

    for test in Tests:
      let
        datastr = string.generateLivenessResponse(
          test[0], test[1], test[2])
        data = stringToBytes(datastr)
        contentType = getContentType("application/json").get()
        res = decodeBytes(GetValidatorsLivenessResponse,
                          data, Opt.some(contentType))
        expect = RestLivenessItem.generateLivenessResponse(
          test[0], test[1], test[2])
      check:
        res.isOk()
        res.get().data == expect

    let vector = stringToBytes(
      "{\"data\":[{\"index\":\"100000\",\"epoch\":\"202919\",\"is_live\":true}]}")

    let contentType = getContentType("application/json").tryGet()
    let res = decodeBytes(
      GetValidatorsLivenessResponse, vector, Opt.some(contentType))
    check:
      res.isOk()
      len(res.get().data) == 1
      res.get().data[0].index == 100000
      res.get().data[0].is_live == true
