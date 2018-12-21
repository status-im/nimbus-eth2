# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# At the time of writing, the exact definitions of what should be used for
# cryptography in the spec is in flux, with sizes and test vectors still being
# hashed out. This layer helps isolate those chagnes.

import
  hashes,
  milagro_crypto, json_serialization

export
  json_serialization, milagro_crypto.`$`

type
  ValidatorPubKey* = milagro_crypto.VerKey
  ValidatorPrivKey* = milagro_crypto.SigKey
  ValidatorSig* = milagro_crypto.Signature

template hash*(k: ValidatorPubKey|ValidatorPrivKey): Hash =
  hash(k.getRaw)

func pubKey*(pk: ValidatorPrivKey): ValidatorPubKey = fromSigKey(pk)

func bls_aggregate_pubkeys*(keys: openArray[ValidatorPubKey]): ValidatorPubKey =
  var empty = true
  for key in keys:
    if empty:
      result = key
      empty = false
    else:
      result.combine(key)

func bls_verify*(
    pubkey: ValidatorPubKey, msg: openArray[byte], sig: ValidatorSig,
    domain: uint64): bool =
  # name from spec!
  # TODO domain!
  sig.verifyMessage(msg, pubkey)

proc writeValue*(writer: var JsonWriter, value: ValidatorPubKey) {.inline.} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var ValidatorPubKey) {.inline.} =
  value = initVerKey reader.readValue(string)

proc writeValue*(writer: var JsonWriter, value: ValidatorSig) {.inline.} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var ValidatorSig) {.inline.} =
  value = initSignature reader.readValue(string)

proc writeValue*(writer: var JsonWriter, value: ValidatorPrivKey) {.inline.} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var ValidatorPrivKey) {.inline.} =
  value = initSigKey reader.readValue(string)

