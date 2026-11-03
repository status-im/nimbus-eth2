# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/os,
  results,
  json_serialization,
  bearssl/rand,
  stew/[io2, byteutils],
  ../spec/[blake3, crypto, keystore],
  ../filepath

export blake3

const
  HashChainSecretFileName* = "hash_chain_secret"
  HashChainLength* = 1 shl 16

func compute_hash_chain*(
    secret: Eth2Digest, length: int): Opt[seq[Eth2Digest]] =
  var chain = newSeqOfCap[Eth2Digest](length + 1)
  chain.add secret
  for i in 1 .. length:
    chain.add compute_hash_chain_link(chain[^1])
  for link in chain:
    if link.isZero:
      return Opt.none(seq[Eth2Digest])
  Opt.some(chain)

proc generateHashChainSecret*(rng: var HmacDrbgContext): Eth2Digest =
  Eth2Digest(data: rng.generate(array[32, byte]))

func hashChainSecretPath*(
    hashChainsDir: string, pubkey: ValidatorPubKey): string =
  hashChainsDir / ("0x" & pubkey.toHex())

func hashChainPasswordPath*(
    secretsDir: string, pubkey: ValidatorPubKey): string =
  secretsDir / ("hash_chain_0x" & pubkey.toHex())

proc readHashChainPassword(
    secretsDir: string, pubkey: ValidatorPubKey): Result[KeystorePass, string] =
  let path = hashChainPasswordPath(secretsDir, pubkey)
  let data = readAllChars(path).valueOr:
    return err("Cannot read " & path & ": " & ioErrorMsg(error))
  ok KeystorePass.init(data)

proc saveHashChainSecret*(
    rng: var HmacDrbgContext, hashChainsDir, secretsDir: string,
    pubkey: ValidatorPubKey, secret: Eth2Digest): Result[void, string] =
  let passwordPath = hashChainPasswordPath(secretsDir, pubkey)
  if not fileExists(passwordPath):
    secureCreatePath(secretsDir).isOkOr:
      return err("Cannot create " & secretsDir & ": " & ioErrorMsg(error))
    secureWriteFile(
        passwordPath, rng.generate(array[32, byte]).toHex()).isOkOr:
      return err("Cannot write " & passwordPath & ": " & ioErrorMsg(error))

  let crypto = createHashChainCrypto(
    rng, secret, ? readHashChainPassword(secretsDir, pubkey))
  secureCreatePath(hashChainsDir).isOkOr:
    return err("Cannot create " & hashChainsDir & ": " & ioErrorMsg(error))
  let path = hashChainSecretPath(hashChainsDir, pubkey)
  secureWriteFile(path, Json.encode(crypto)).isOkOr:
    return err("Cannot write " & path & ": " & ioErrorMsg(error))
  ok()

proc loadHashChainSecret*(
    hashChainsDir, secretsDir: string,
    pubkey: ValidatorPubKey): Result[Opt[Eth2Digest], string] =
  ## `none` when no secret is stored, `err` when one is stored but unreadable
  let path = hashChainSecretPath(hashChainsDir, pubkey)
  if not fileExists(path):
    return ok Opt.none(Eth2Digest)
  let data = readAllChars(path).valueOr:
    return err("Cannot read " & path & ": " & ioErrorMsg(error))
  let crypto =
    try:
      Json.decode(data, Crypto)
    except SerializationError as exc:
      return err("Invalid hash chain secret in " & path & ": " & exc.msg)
  let secret = decryptHashChainCrypto(
      crypto, ? readHashChainPassword(secretsDir, pubkey)).valueOr:
    return err("Cannot decrypt " & path & ": " & error)
  ok Opt.some(secret)

func getHashChainReveal*(
    secret, commitment: Eth2Digest): Opt[Eth2Digest] =
  var link = secret
  for _ in 0 ..< HashChainLength:
    let next = compute_hash_chain_link(link)
    if next == commitment:
      return Opt.some(link)
    link = next
  Opt.none(Eth2Digest)
