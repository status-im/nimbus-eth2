# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/tables,
  ../spec/[helpers, eip7594_helpers]

from std/sequtils import mapIt
from std/strutils import join

const
  MaxDataColumns = 3 * SLOTS_PER_EPOCH * NUMBER_OF_COLUMNS
  ## Same limit as `MaxOrphans` in `block_quarantine`
  ## data columns may arrive before an orphan is tagged `columnless`

type
  DataColumnQuarantine* = object
    data_columns*:
      OrderedTable[(Eth2Digest, ColumnIndex), ref DataColumnSidecar]
    onDataColumnSidecarCallback*: OnDataColumnSidecarCallback

  DataColumnFetchRecord* = object
    block_root*: Eth2Digest
    indices*: seq[ColumnIndex]

  OnDataColumnSidecarCallback = proc(data: DataColumnSidecar) {.gcsafe, raises: [].}

func shortLog*(x: seq[ColumnIndex]): string =
  "<" & x.mapIt($it).join(", ") & ">"

func shortLog*(x: seq[DataColumnFetchRecord]): string =
  "[" & x.mapIt(shortLog(it.block_root) & shortLog(it.indices)).join(", ") & "]"

func put*(quarantine: var DataColumnQuarantine, dataColumnSidecar: ref DataColumnSidecar) =
  if quarantine.data_columns.lenu64 >= MaxDataColumns:
    # FIFO if full. For example, sync manager and request manager can race to
    # put data columns in at the same time, so one gets blob insert -> block resolve
    # -> data columns insert sequence, which leaves garbage data columns.
    #
    # This also therefore automatically garbage-collects otherwise valid garbage
    # data columns which are correctly signed, point to either correct block roots or a
    # block root which isn't ever seen, and then are for any reason simply never
    # used.
    var oldest_column_key: (Eth2Digest, ColumnIndex)
    for k in quarantine.data_columns.keys:
      oldest_column_key = k
      break
    quarantine.data_columns.del(oldest_column_key)
  let block_root = hash_tree_root(dataColumnSidecar.signed_block_header.message)
  discard quarantine.data_columns.hasKeyOrPut(
    (block_root, dataColumnSidecar.index), dataColumnSidecar)

func hasDataColumn*(
    quarantine: DataColumnQuarantine,
    slot: Slot,
    proposer_index: uint64,
    index: ColumnIndex): bool =
  for data_column_sidecar in quarantine.data_columns.values:
    template block_header: untyped = data_column_sidecar.signed_block_header.message
    if block_header.slot == slot and
        block_header.proposer_index == proposer_index and
        data_column_sidecar.index == index:
      return true
  false

func popDataColumns*(
    quarantine: var DataColumnQuarantine, digest: Eth2Digest,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock):
    seq[ref DataColumnSidecar] =
  var r: seq[ref DataColumnSidecar]
  for idx in 0..<NUMBER_OF_COLUMNS:
    var c: ref DataColumnSidecar
    if quarantine.data_columns.pop((digest, ColumnIndex idx), c):
      r.add(c)
  r

func checkForInitialDcSidecars*(quarantine: DataColumnQuarantine,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock): bool =
  for idx in 0..<len(blck.message.body.blob_kzg_commitments):
    if (blck.root, ColumnIndex idx) notin quarantine.data_columns:
      return false
  true

func hasDataColumns*(quarantine: DataColumnQuarantine,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock): bool =
  for idx in 0..<NUMBER_OF_COLUMNS:
    if (blck.root, ColumnIndex idx) notin quarantine.data_columns:
      return false
  true

func dataColumnFetchRecord*(quarantine: DataColumnQuarantine,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock): DataColumnFetchRecord =
  var indices: seq[ColumnIndex]
  for i in 0..<NUMBER_OF_COLUMNS:
    let idx = ColumnIndex(i)
    if not quarantine.data_columns.hasKey(
        (blck.root, idx)):
      indices.add(idx)
  DataColumnFetchRecord(block_root: blck.root, indices: indices)

func init*(
    T: type DataColumnQuarantine): T = T()

