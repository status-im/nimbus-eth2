# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## Persistent record of the XMSS leaves signed by local PQ validators.
##
## An XMSS key must never sign two different messages at the same leaf: the
## second signature exposes the leaf and lets others forge signatures at it.
## The signing root of each leaf is recorded before signing, and signing a
## different root at a recorded leaf is refused, across restarts.
##
## https://github.com/ethereum/consensus-specs/blob/4c296784bb6ff54cbdcf72ebdda2a1057cce8893/specs/_features/pq/validator.md#protection-best-practices

import
  results,
  eth/db/kvstore_sqlite3,
  stew/endians2,
  ../spec/[digest, xmss]

export results

const XmssLeafRecordName* = "pq_xmss_leaves"

type
  XmssLeafRecord* = ref object
    backend: SqStoreRef
    leaves: SqKeyspaceRef

proc init*(
    T: type XmssLeafRecord, basePath: string,
    name = XmssLeafRecordName): Result[T, string] =
  let
    backend = SqStoreRef.init(basePath, name).valueOr:
      return err("cannot open XMSS leaf record: " & error)
    leaves = backend.openKvStore("signed_leaves", withoutRowid = true).valueOr:
      backend.close()
      return err("cannot open XMSS leaf record table: " & error)
  ok T(backend: backend, leaves: leaves)

proc close*(record: XmssLeafRecord) =
  if record.isNil:
    return
  record.leaves.close()
  record.backend.close()

func leafKey(pubkey: XMSSPubkey, leaf_index: uint64): array[40, byte] =
  var res: array[40, byte]
  res[0 ..< 32] = pubkey.blob
  res[32 ..< 40] = leaf_index.toBytesBE()
  res

proc register*(
    record: XmssLeafRecord, pubkey: XMSSPubkey, leaf_index: uint64,
    signing_root: Eth2Digest): Result[void, string] =
  ## Record ``signing_root`` at ``leaf_index`` of ``pubkey`` ahead of signing
  ## it; fails if another signing root is recorded at that leaf.
  let key = leafKey(pubkey, leaf_index)
  var existing = Opt.none(Eth2Digest)
  let found = record.leaves.get(key, proc(data: openArray[byte]) =
    if data.len == sizeof(Eth2Digest):
      var root: Eth2Digest
      root.data[0 ..< 32] = data
      existing = Opt.some(root)
  ).valueOr:
    return err("cannot read XMSS leaf record: " & error)

  if found:
    if existing != Opt.some(signing_root):
      return err("another message is recorded at XMSS leaf " & $leaf_index)
    return ok()

  record.leaves.put(key, signing_root.data).isOkOr:
    return err("cannot write XMSS leaf record: " & error)
  ok()
