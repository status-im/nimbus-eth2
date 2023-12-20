# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/strutils,
  unittest2,
  ../beacon_chain/spec/[eth2_ssz_serialization, crypto],
  ../beacon_chain/spec/datatypes/base

# Sanity checks to make sure all the workarounds introduced
# to deal with https://github.com/status-im/nimbus-eth2/issues/374
# and https://github.com/ethereum/consensus-specs/issues/1396
# don't blow up.

suite "Zero signature sanity checks":
  # See:
  # - https://github.com/ethereum/consensus-specs/issues/1713
  # - https://github.com/status-im/nimbus-eth2/pull/2733

  test "SSZ serialization roundtrip of SignedBeaconBlockHeader":
    # For the Genesis block only
    # - https://github.com/status-im/nimbus-eth2/issues/396

    let defaultBlockHeader = SignedBeaconBlockHeader()

    check:
      block:
        var allZeros = true
        for val in defaultBlockHeader.signature.blob:
          allZeros = allZeros and val == 0
        allZeros

    let sszDefaultBlockHeader = SSZ.encode(defaultBlockHeader)
    let deserBlockHeader = SSZ.decode(sszDefaultBlockHeader, SignedBeaconBlockHeader)

    check(defaultBlockHeader == deserBlockHeader)

  test "default initialization of signatures":
    block:
      let sig = default(CookedSig)
      doAssert sig.toValidatorSig().toHex() == "c" & '0'.repeat(191)

    block:
      let sig = AggregateSignature()
      doAssert sig.toHex() == "c" & '0'.repeat(191)

    block:
      let sig = ValidatorSig()
      doAssert sig.toHex() == '0'.repeat(192)

  test "Zero signatures cannot be loaded into a BLS signature object":
    let zeroSig = ValidatorSig()
    let s = zeroSig.load()
    check:
      s.isNone()
