# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[os, strutils],
  results,
  bearssl/rand,
  stew/[io2, byteutils],
  ../spec/[blake3, crypto],
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
    validatorsDir: string, pubkey: ValidatorPubKey): string =
  validatorsDir / ("0x" & pubkey.toHex()) / HashChainSecretFileName

proc saveHashChainSecret*(
    validatorsDir: string, pubkey: ValidatorPubKey,
    secret: Eth2Digest): Result[void, string] =
  secureWriteFile(
    hashChainSecretPath(validatorsDir, pubkey), secret.data.toHex()).mapErr(
      proc(e: auto): string = ioErrorMsg(e))

proc loadHashChainSecret*(
    validatorsDir: string, pubkey: ValidatorPubKey): Opt[Eth2Digest] =
  let path = hashChainSecretPath(validatorsDir, pubkey)
  if not fileExists(path):
    return Opt.none(Eth2Digest)
  let data = readAllChars(path).valueOr:
    return Opt.none(Eth2Digest)
  try:
    Opt.some(Eth2Digest.fromHex(strip(data)))
  except ValueError:
    Opt.none(Eth2Digest)

func getHashChainReveal*(
    secret, commitment: Eth2Digest): Opt[Eth2Digest] =
  var link = secret
  for _ in 0 ..< HashChainLength:
    let next = compute_hash_chain_link(link)
    if next == commitment:
      return Opt.some(link)
    link = next
  Opt.none(Eth2Digest)
