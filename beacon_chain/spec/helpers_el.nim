# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/typetraits,
  eth/common/eth_types_rlp,
  "."/[helpers, state_transition_block]

func readExecutionTransaction(
    txBytes: bellatrix.Transaction): Result[ExecutionTransaction, string] =
  try:
    ok rlp.decode(distinctBase(txBytes), ExecutionTransaction)
  except RlpError as exc:
    err("Invalid transaction: " & exc.msg)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/deneb/beacon-chain.md#is_valid_versioned_hashes
func is_valid_versioned_hashes*(blck: ForkyBeaconBlock): Result[void, string] =
  static: doAssert typeof(blck).kind >= ConsensusFork.Deneb
  template transactions: untyped = blck.body.execution_payload.transactions
  template commitments: untyped = blck.body.blob_kzg_commitments

  var i = 0
  for txBytes in transactions:
    if txBytes.len == 0 or txBytes[0] != TxEip4844.byte:
      continue  # Only blob transactions may have blobs
    let tx = ? txBytes.readExecutionTransaction()
    for vHash in tx.versionedHashes:
      if commitments.len <= i:
        return err("Extra blobs without matching `blob_kzg_commitments`")
      if vHash.data != kzg_commitment_to_versioned_hash(commitments[i]):
        return err("Invalid `blob_versioned_hash` at index " & $i)
      inc i
  if i != commitments.len:
    return err("Extra `blob_kzg_commitments` without matching blobs")
  ok()
