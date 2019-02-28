# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# At the time of writing, the exact definitions of what should be used for
# cryptography in the spec is in flux, with sizes and test vectors still being
# hashed out. This layer helps isolate those chagnes.

# Useful conversation about BLS signatures (TODO: condense this)
#
#   I can probably google this somehow, but bls signatures, anyone knows off the
#   top of their head if they have to be combined one by one, or can two group
#   signatures be combined? what happens to overlap then?
#   Danny Ryan
#   @djrtwo
#   Dec 21 12:00
#   Yeah, you can do any linear combination of signatures. but you have to
#   remember the linear combination of pubkeys that constructed
#   if you have two instances of a signature from pubkey p, then you need 2*p in
#   the group pubkey
#   because the attestation bitfield is only 1 bit per pubkey right now,
#   attestations do not support this
#   it could be extended to support N overlaps up to N times per pubkey if we
#   had N bits per validator instead of 1
#   We are shying away from this for the time being. If there end up being
#   substantial difficulties in network layer aggregation, then adding bits
#   to aid in supporting overlaps is one potential solution
#   Jacek Sieka
#   @arnetheduck
#   Dec 21 12:02
#   ah nice, you anticipated my followup question there :) so it's not a
#   straight-off set union operation
#   Danny Ryan
#   @djrtwo
#   Dec 21 12:02
#   depending on the particular network level troubles we run into
#   right
#   aggregatng sigs and pubkeys are both just ec adds
#   https://github.com/ethereum/py-evm/blob/d82b10ae361cde6abbac62f171fcea7809c4e3cf/eth/_utils/bls.py#L191-L202
#   subtractions work too (i suppose this is obvious). You can linearly combine
#   sigs or pubs in any way


import
  hashes,
  blscurve, json_serialization, eth/rlp

export
  json_serialization, rlp

export blscurve.init, blscurve.getBytes, blscurve.combine, blscurve.`$`, blscurve.`==`

type
  ValidatorPubKey* = blscurve.VerKey
  ValidatorPrivKey* = blscurve.SigKey
  ValidatorSig* = blscurve.Signature
  ValidatorPKI* = ValidatorPrivKey|ValidatorPubKey|ValidatorSig

template hash*(k: ValidatorPubKey|ValidatorPrivKey): Hash =
  hash(k.getBytes())

func pubKey*(pk: ValidatorPrivKey): ValidatorPubKey = pk.getKey()

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/bls_signature.md#bls_aggregate_pubkeys
func bls_aggregate_pubkeys*(keys: openArray[ValidatorPubKey]): ValidatorPubKey =
  var empty = true
  for key in keys:
    if empty:
      result = key
      empty = false
    else:
      result.combine(key)

# https://github.com/ethereum/eth2.0-specs/blob/v0.3.0/specs/bls_signature.md#bls_verify
func bls_verify*(
    pubkey: ValidatorPubKey, msg: openArray[byte], sig: ValidatorSig,
    domain: uint64): bool =
  # name from spec!
  sig.verify(msg, domain, pubkey)

# https://github.com/ethereum/eth2.0-specs/blob/master/specs/bls_signature.md#bls_verify_multiple
func bls_verify_multiple*(
    pubkeys: seq[ValidatorPubKey], messages: seq[array[0..31, byte]],
    sig: ValidatorSig, domain: uint64): bool =
  let L = len(pubkeys)
  assert L == len(messages)

  # TODO calculate product of ate pairings; check how sig.verify works
  true

func bls_sign*(key: ValidatorPrivKey, msg: openarray[byte],
               domain: uint64): ValidatorSig =
  # name from spec!
  key.sign(domain, msg)

proc writeValue*(writer: var JsonWriter, value: ValidatorPubKey) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var ValidatorPubKey) {.inline.} =
  value = VerKey.init(reader.readValue(string))

proc writeValue*(writer: var JsonWriter, value: ValidatorSig) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var ValidatorSig) {.inline.} =
  value = Signature.init(reader.readValue(string))

proc writeValue*(writer: var JsonWriter, value: ValidatorPrivKey) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var ValidatorPrivKey) {.inline.} =
  value = SigKey.init(reader.readValue(string))

proc newPrivKey*(): ValidatorPrivKey = SigKey.random()

# RLP serialization (TODO: remove if no longer necessary)
proc append*(writer: var RlpWriter, value: ValidatorPubKey) =
  writer.append value.getBytes()

proc read*(rlp: var Rlp, T: type ValidatorPubKey): T {.inline.} =
  ValidatorPubKey.init rlp.toBytes.toOpenArray

proc append*(writer: var RlpWriter, value: ValidatorSig) =
  writer.append value.getBytes()

proc read*(rlp: var Rlp, T: type ValidatorSig): T {.inline.} =
  ValidatorSig.init rlp.toBytes.toOpenArray

