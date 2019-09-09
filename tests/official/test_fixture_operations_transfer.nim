# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest, strutils,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, state_transition_block, validator],
  ../../beacon_chain/[ssz, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

const OpTransferDir = SszTestsDir/const_preset/"phase0"/"operations"/"transfer"/"pyspec_tests"

template runTest(identifier: untyped) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  const testDir = OpTransferDir / astToStr(identifier)

  proc `testImpl _ transfer _ identifier`() =

    var flags: UpdateFlags
    var prefix: string
    if not existsFile(testDir/"meta.yaml"):
      flags.incl skipValidation
    if existsFile(testDir/"post.ssz"):
      prefix = "[Valid]   "
    else:
      prefix = "[Invalid] "

    test prefix & astToStr(identifier):
      var stateRef, postRef: ref BeaconState
      var transfer: ref Transfer
      new transfer
      new stateRef

      transfer[] = parseTest(testDir/"transfer.ssz", SSZ, Transfer)
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      if existsFile(testDir/"post.ssz"):
        new postRef
        postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      var cache = get_empty_per_epoch_cache()

      if postRef.isNil:
        let done = process_transfer(stateRef[], transfer[], cache, flags)
        doAssert done == false, "We didn't expect this invalid transfer to be processed."
      else:
        let done = process_transfer(stateRef[], transfer[], cache, flags)
        doAssert done, "Valid transfer not processed"
        check: stateRef.hash_tree_root() == postRef.hash_tree_root()
        reportDiff(stateRef, postRef)

  `testImpl _ transfer _ identifier`()

suite "Official - Operations - Transfers " & preset():
  runTest(success_non_activated)
  runTest(success_withdrawable)
  runTest(success_active_above_max_effective)
  runTest(success_active_above_max_effective_fee)
  runTest(invalid_signature)
  runTest(active_but_transfer_past_effective_balance)
  runTest(incorrect_slot)
  runTest(transfer_clean)
  runTest(transfer_clean_split_to_fee)
  runTest(insufficient_balance_for_fee)
  runTest(insufficient_balance_for_amount_result_full)
  runTest(insufficient_balance_for_combined_result_dust)
  runTest(insufficient_balance_for_combined_result_full)
  runTest(insufficient_balance_for_combined_big_amount)
  runTest(insufficient_balance_for_combined_big_fee)
  runTest(insufficient_balance_off_by_1_fee)
  runTest(insufficient_balance_off_by_1_amount)
  runTest(insufficient_balance_duplicate_as_fee_and_amount)
  runTest(no_dust_sender)
  runTest(no_dust_recipient)
  runTest(non_existent_sender)
  runTest(non_existent_recipient)
  runTest(invalid_pubkey)
