# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec
import
  std/[algorithm, hashes],
  results,
  eth/p2p/discoveryv5/[node],
  ./[helpers, digest],
  ./datatypes/[eip7594]

proc sortedColumnIndices*(columnsPerSubnet: ColumnIndex,
                          subnetIds: HashSet[uint64]):
                          seq[ColumnIndex] =
  var res: seq[ColumnIndex] = @[]
  for i in 0'u64 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort
  res

proc sortedColumnIndexList*(columnsPerSubnet: ColumnIndex, 
                            subnetIds: HashSet[uint64]): 
                            List[ColumnIndex, NUMBER_OF_COLUMNS] =
  var
    res: seq[ColumnIndex]
    list: List[ColumnIndex, NUMBER_OF_COLUMNS]
  for i in 0'u64 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort()
  for elem in res:
    discard list.add(ColumnIndex(elem))
  list

proc get_custody_column_subnets*(node_id: NodeId, 
                                custody_subnet_count: uint64): 
                                Result[HashSet[uint64], cstring] =

  # Decouples the custody subnet computation part from
  # `get_custody_columns`, in order to later use this subnet list
  # in order to maintain subscription to specific column subnets.

  if not (custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT):
    return err("Eip7594: Custody subnet count exceeds the DATA_COLUMN_SIDECAR_SUBNET_COUNT")

  var 
    subnet_ids: HashSet[uint64]
    current_id = node_id

  while subnet_ids.lenu64 < custody_subnet_count:
    var
      current_id_bytes: array[32, byte]
      hashed_bytes: array[8, byte]
      
    current_id_bytes = current_id.toBytesBE()
    current_id_bytes.reverse()

    let
      hashed_current_id = eth2digest(current_id_bytes)
      
    hashed_bytes[0..7] = hashed_current_id.data.toOpenArray(0,7)
    let subnet_id = bytes_to_uint64(hashed_bytes) mod 
      DATA_COLUMN_SIDECAR_SUBNET_COUNT
    
    discard subnet_ids.containsOrIncl(subnet_id)

    if current_id == UInt256.high.NodeId:
      # Overflow prevention
      current_id = NodeId(StUint[256].zero)
    current_id += NodeId(StUint[256].one)

  ok(subnet_ids)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#get_custody_columns
proc get_custody_columns*(node_id: NodeId, 
                          custody_subnet_count: uint64): 
                          seq[ColumnIndex] =
  let
    subnet_ids = 
      get_custody_column_subnets(node_id, custody_subnet_count).get
  const
    columns_per_subnet = 
      NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT

  sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids)


proc get_custody_column_list*(node_id: NodeId, 
                          custody_subnet_count: uint64): 
                          List[ColumnIndex, NUMBER_OF_COLUMNS] =

  # Not in spec in the exact format, but it is useful in sorting custody columns 
  # before sending, data_column_sidecars_by_range requests
  let
    subnet_ids = 
      get_custody_column_subnets(node_id, custody_subnet_count).get
  const
    columns_per_subnet = 
      NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
  
  sortedColumnIndexList(ColumnIndex(columns_per_subnet), subnet_ids)
