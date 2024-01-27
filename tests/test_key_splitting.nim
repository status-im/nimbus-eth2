# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[typetraits, sequtils],
  unittest2, stew/byteutils,
  ../beacon_chain/spec/[crypto, keystore],
  ./testutil

func sign(secrets: seq[SecretShare], message: seq[byte]): seq[SignatureShare] =
  let msg = message
  return secrets.mapIt(it.key.blsSign(message).toSignatureShare(it.id))

suite "Key spliting":
  let
    privateKey = ValidatorPrivKey.init("0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866")
    pubKey = privateKey.toPubKey.toPubKey
    password = string.fromBytes hexToSeqByte("7465737470617373776f7264f09f9491")
    salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
    iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"
    rng = HmacDrbgContext.new()
    msg = rng[].generateBytes(32)

  test "single share":
    let maybeShares = generateSecretShares(privateKey, rng[], 1, 1)
    check maybeShares.isOk
    let shares = maybeShares.get
    check shares.len == 1
    let signs = shares.sign(msg)
    let recovered = signs.recoverSignature()
    check pubKey.blsVerify(msg, recovered)
    check pubKey.confirmShares(shares, rng[])

  test "k < n":
    let maybeShares = generateSecretShares(privateKey, rng[], 2, 3)
    doAssert maybeShares.isOk
    let shares = maybeShares.get
    check shares.len == 3
    let signs = shares.sign(msg)

    var invalidShare = shares[2]
    invalidShare.id = 1000 # 1000 is an arbitrary wrong value

    check pubKey.blsVerify(msg, signs.recoverSignature())
    check pubKey.blsVerify(msg, @[signs[0], signs[1]].recoverSignature())
    check pubKey.blsVerify(msg, @[signs[1], signs[2]].recoverSignature())
    check pubKey.blsVerify(msg, @[signs[2], signs[0]].recoverSignature())
    check not pubKey.blsVerify(msg, @[signs[0]].recoverSignature())
    check pubKey.confirmShares(shares, rng[])
    check pubKey.confirmShares(@[shares[0], shares[1]], rng[])
    check pubKey.confirmShares(@[shares[1], shares[2]], rng[])
    check pubKey.confirmShares(@[shares[2], shares[0]], rng[])
    check pubKey.confirmShares(@[shares[0], shares[2]], rng[])
    check not pubKey.confirmShares(@[shares[0]], rng[])
    check not pubKey.confirmShares(@[shares[1]], rng[])
    check not pubKey.confirmShares(@[shares[2]], rng[])
    check not pubKey.confirmShares(@[invalidShare], rng[])
    check not pubKey.confirmShares(@[shares[0], invalidShare], rng[])
    check not pubKey.confirmShares(@[shares[1], invalidShare], rng[])
    check not pubKey.confirmShares(@[shares[2], invalidShare], rng[])

  test "k == n":
    let maybeShares = generateSecretShares(privateKey, rng[], 3, 3)
    check maybeShares.isOk
    let shares = maybeShares.get
    check shares.len == 3
    let signs = shares.sign(msg)
    let recovered = signs.recoverSignature()
    check pubKey.blsVerify(msg, recovered)
    check not pubKey.blsVerify(msg, @[signs[0]].recoverSignature())
    check not pubKey.blsVerify(msg, @[signs[0], signs[1]].recoverSignature())
    check pubKey.confirmShares(shares, rng[])

  test "k == n == 100":
    let maybeShares = generateSecretShares(privateKey, rng[], 100, 100)
    check maybeShares.isOk
    let shares = maybeShares.get
    check shares.len == 100
    let signs = shares.sign(msg)
    let recovered = signs.recoverSignature()
    check pubKey.blsVerify(msg, recovered)
    check pubKey.confirmShares(shares, rng[])
