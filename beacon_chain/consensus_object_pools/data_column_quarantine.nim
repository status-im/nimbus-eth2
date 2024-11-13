# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/tables,
  ../spec/datatypes/fulu,
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
    supernode*: bool
    custody_columns*: seq[ColumnIndex]
    onDataColumnSidecarCallback*: OnDataColumnSidecarCallback
  
  DataColumnFetchRecord* = object
    block_root*: Eth2Digest
    indices*: seq[ColumnIndex]

  OnDataColumnSidecarCallback = proc(data: DataColumnSidecar) {.gcsafe, raises: [].}

func init*(T: type DataColumnQuarantine): T =
  T()

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

func peekColumnIndices*(quarantine: DataColumnQuarantine,
                        blck: electra.SignedBeaconBlock):
                        seq[ColumnIndex] =
  # Peeks into the currently received column indices
  # from quarantine, necessary data availability checks
  var indices: seq[ColumnIndex]
  for col_idx in quarantine.custody_columns:
    if quarantine.data_columns.hasKey(
        DataColumnIdentifier(block_root: blck.root,
                             index: ColumnIndex col_idx)):
      indices.add(col_idx)
  indices

func gatherDataColumns*(quarantine: DataColumnQuarantine,
                       digest: Eth2Digest): 
                       seq[ref DataColumnSidecar] =
  # Returns the current data columns quried by a 
  # block header
  var columns: seq[ref DataColumnSidecar]
  for i in quarantine.custody_columns:
    let dc_identifier = 
      DataColumnIdentifier(
        block_root: digest,
        index: i)
    if quarantine.data_columns.hasKey(dc_identifier):
      let value = 
        quarantine.data_columns.getOrDefault(dc_identifier,
                                             default(ref DataColumnSidecar))
      columns.add(value)
  columns

func popDataColumns*(
    quarantine: var DataColumnQuarantine, digest: Eth2Digest,
    blck: electra.SignedBeaconBlock):
    seq[ref DataColumnSidecar] =
  var r: DataColumnSidecars
  for idx in quarantine.custody_columns:
    var c: ref DataColumnSidecar
    if quarantine.data_columns.pop(
        DataColumnIdentifier(block_root: digest,
                             index: idx),
                             c):
      r.add(c)
  r

func hasMissingDataColumns*(quarantine: DataColumnQuarantine,
    blck: electra.SignedBeaconBlock): bool =
  # `hasMissingDataColumns` consists of the data columns that,
  # have been missed over gossip, also in case of a supernode,
  # the method would return missing columns when the supernode
  # has not received data columns upto the requisite limit (i.e 50%
  # of NUMBER_OF_COLUMNS).

  # This method shall be actively used by the `RequestManager` to
  # root request columns over RPC.
  var col_counter = 0
  for idx in quarantine.custody_columns:
    let dc_identifier = 
      DataColumnIdentifier(
        block_root: blck.root,
        index: idx)
    if dc_identifier notin quarantine.data_columns:
      inc col_counter
  if quarantine.supernode and col_counter != NUMBER_OF_COLUMNS:
    return false
  elif quarantine.supernode == false and
      col_counter != max(SAMPLES_PER_SLOT, CUSTODY_REQUIREMENT):
    return false
  else:
    return true

func hasEnoughDataColumns*(quarantine: DataColumnQuarantine,
    blck: electra.SignedBeaconBlock): bool =
  # `hasEnoughDataColumns` dictates whether there is `enough`
  # data columns for a block to be enqueued, ideally for a supernode
  # if it receives atleast 50%+ gossip and RPC

  # Once 50%+ columns are available we can use this function to
  # check it, and thereby check column reconstructability, right from 
  # gossip validation, consequently populating the quarantine with
  # rest of the data columns.
  if quarantine.supernode:
    let
      collectedColumns = quarantine.gatherDataColumns(blck.root)
    if collectedColumns.len >= (quarantine.custody_columns.len div 2):
      return true
  else:
    for i in quarantine.custody_columns:
      let dc_identifier = 
        DataColumnIdentifier(
          block_root: blck.root,
          index: i)
      if dc_identifier notin quarantine.data_columns:
        return false
      else:
        return true

func dataColumnFetchRecord*(quarantine: DataColumnQuarantine,
                            blck: electra.SignedBeaconBlock):
                            DataColumnFetchRecord =
  var indices: seq[ColumnIndex]
  for i in quarantine.custody_columns:
    let
      idx = ColumnIndex(i)
      dc_id = DataColumnIdentifier(
        block_root: blck.root,
        index: idx)
    if not quarantine.data_columns.hasKey(
        dc_id):
      indices.add(idx)
  DataColumnFetchRecord(block_root: blck.root, indices: indices)