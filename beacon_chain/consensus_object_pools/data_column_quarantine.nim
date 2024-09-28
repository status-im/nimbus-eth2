# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/tables,
  ../spec/datatypes/eip7594,
  ../spec/helpers

from std/sequtils import mapIt
from std/strutils import join

const
  MaxDataColumns = 3 * SLOTS_PER_EPOCH * NUMBER_OF_COLUMNS
  ## Same limit as `MaxOrphans` in `block_quarantine`
  ## data columns may arrive before an orphan is tagged `columnless`

type
  DataColumnQuarantine* = object
    data_columns*:
      OrderedTable[DataColumnIdentifier, ref DataColumnSidecar]
    onDataColumnSidecarCallback*: OnDataColumnSidecarCallback
  
  DataColumnFetchRecord* = object
    block_root*: Eth2Digest
    indices*: seq[ColumnIndex]

  OnDataColumnSidecarCallback = proc(data: DataColumnSidecar) {.gcsafe, raises: [].}


func shortLog*(x: seq[DataColumnFetchRecord]): string =
  "[" & x.mapIt(shortLog(it.block_root) & shortLog(it.indices)).join(", ") & "]"

func put*(quarantine: var DataColumnQuarantine,
          dataColumnSidecar: ref DataColumnSidecar) =
  if quarantine.data_columns.len >= static(MaxDataColumns.int):
    # FIFO if full. For example, sync manager and request manager can race
    # to put data columns in at the same time, so one gets data column
    # insert -> block resolve -> data column insert, which leaves
    # garbage data columns.
    #
    # This also therefore automatically garbage-collects otherwise valid 
    # data columns that are correctly signed, point to either correct block
    # root which isn't ever seen, and then for any reason simply never used.
    var oldest_column_key: DataColumnIdentifier
    for k in quarantine.data_columns.keys:
      oldest_column_key = k
      break
    quarantine.data_columns.del(oldest_column_key)
  let block_root = 
    hash_tree_root(dataColumnSidecar.signed_block_header.message)
  discard quarantine.data_columns.hasKeyOrPut(
    DataColumnIdentifier(block_root: block_root,
                         index: dataColumnSidecar.index),
                         dataColumnSidecar)

func hasDataColumn*(
    quarantine: DataColumnQuarantine,
    slot: Slot,
    proposer_index: uint64,
    index: ColumnIndex): bool =
  for data_column_sidecar in quarantine.data_columns.values:
    template block_header: untyped =
      data_column_sidecar.signed_block_header.message
    if block_header.slot == slot and
        block_header.proposer_index == proposer_index and
        data_column_sidecar.index == index:
      return true
  false

func popDataColumns*(
    quarantine: var DataColumnQuarantine, digest: Eth2Digest,
    blck: electra.SignedBeaconBlock):
    seq[ref DataColumnSidecar] =
  var r: DataColumnSidecars
  for idx in 0..<len(blck.message.body.blob_kzg_commitments):
    var c: ref DataColumnSidecar
    if quarantine.data_columns.pop(
        DataColumnIdentifier(block_root: digest,
                             index: ColumnIndex idx),
                             c):
      r.add(c)
  r

func hasDataColumns*(quarantine: DataColumnQuarantine,
    blck: electra.SignedBeaconBlock): bool =
  for idx in 0..<len(blck.message.body.blob_kzg_commitments):
    let dc_id = DataColumnIdentifier(
      block_root: blck.root,
      index: ColumnIndex idx)
    if dc_id notin quarantine.data_columns:
      return false
  true

func dataColumnFetchRecord*(quarantine: DataColumnQuarantine,
                            blck: electra.SignedBeaconBlock):
                            DataColumnFetchRecord =
  var indices: seq[ColumnIndex]
  for i in 0..<len(blck.message.body.blob_kzg_commitments):
    let
      idx = ColumnIndex(i)
      dc_id = DataColumnIdentifier(
        block_root: blck.root,
        index: idx)
    if not quarantine.data_columns.hasKey(
        dc_id):
      indices.add(idx)
  DataColumnFetchRecord(block_root: blck.root, indices: indices)