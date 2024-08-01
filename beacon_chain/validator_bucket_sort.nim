# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/typetraits
import "."/spec/crypto
from "."/spec/datatypes/base import Validator, ValidatorIndex, pubkey, `==`

const
  BUCKET_BITS = 9    # >= 13 gets slow to construct
  NUM_BUCKETS = 1 shl BUCKET_BITS

type
  # `newSeqUninitialized` requires its type to be SomeNumber
  IntValidatorIndex = distinctBase ValidatorIndex

  BucketSortedValidators* = object
    bucketSorted*: seq[IntValidatorIndex]
    bucketUpperBounds: array[NUM_BUCKETS, uint] # avoids over/underflow checks
    extraItems*: seq[ValidatorIndex]

template getBucketNumber(h: ValidatorPubKey): uint =
  # This assumes https://en.wikipedia.org/wiki/Avalanche_effect for uniform
  # distribution across pubkeys. ValidatorPubKey specifically satisfies this
  # criterion. If required, can look at more input bytes, but ultimately it
  # doesn't affect correctness, only speed.

  # Otherwise need more than 2 bytes of input
  static: doAssert BUCKET_BITS <= 16

  const BUCKET_MASK = (NUM_BUCKETS - 1)
  ((h.blob[0] * 256 + h.blob[1]) and BUCKET_MASK)

func sortValidatorBuckets*(validators: openArray[Validator]):
    ref BucketSortedValidators {.noinline.} =
  var bucketSizes: array[NUM_BUCKETS, uint]
  for validator in validators:
    inc bucketSizes[getBucketNumber(validator.pubkey)]

  var
    bucketInsertPositions: array[NUM_BUCKETS, uint]
    accum: uint
  for i, s in bucketSizes:
    accum += s
    bucketInsertPositions[i] = accum
  doAssert accum == validators.len.uint
  let res = (ref BucketSortedValidators)(
    bucketSorted: newSeqUninitialized[IntValidatorIndex](validators.len),
    bucketUpperBounds: bucketInsertPositions)

  for i, validator in validators:
    let insertPos =
      addr bucketInsertPositions[getBucketNumber(validator.pubkey)]
    dec insertPos[]
    res.bucketSorted[insertPos[]] = i.IntValidatorIndex

  doAssert bucketInsertPositions[0] == 0
  for i in 1 ..< NUM_BUCKETS:
    doAssert res.bucketUpperBounds[i - 1] == bucketInsertPositions[i]

  res

func add*(
    bucketSortedValidators: var BucketSortedValidators,
    validatorIndex: ValidatorIndex) =
  bucketSortedValidators.extraItems.add validatorIndex

func findValidatorIndex*(
    validators: openArray[Validator], bsv: BucketSortedValidators,
    pubkey: ValidatorPubKey): Opt[ValidatorIndex] =
  for validatorIndex in bsv.extraItems:
    if validators[validatorIndex.distinctBase].pubkey == pubkey:
      return Opt.some validatorIndex.ValidatorIndex
  let
    bucketNumber = getBucketNumber(pubkey)
    lowerBounds =
      if bucketNumber == 0:
        0'u
      else:
        bsv.bucketUpperBounds[bucketNumber - 1]

  for i in lowerBounds ..< bsv.bucketUpperBounds[bucketNumber]:
    if validators[bsv.bucketSorted[i]].pubkey == pubkey:
      return Opt.some bsv.bucketSorted[i].ValidatorIndex
  Opt.none ValidatorIndex
