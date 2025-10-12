# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[sets]
import chronicles
import ssz_serialization/[proofs, types]
import
  ../validators/action_tracker,
  ../spec/[beaconstate, forks, network, helpers, peerdas_helpers],
  ../networking/eth2_network,
  ../consensus_object_pools/blockchain_dag,
  ../consensus_object_pools/block_dag,
  ../consensus_object_pools/blob_quarantine

from std/algorithm import sort
from std/sequtils import toSeq
from ../beacon_clock import GetBeaconTimeFn

logScope: topics = "validator_custody"


type
  ValidatorCustody* = object
    network: Eth2Node
    dag*: ChainDAGRef
    older_column_set: HashSet[ColumnIndex]
    newer_column_set*: HashSet[ColumnIndex]
    diff_set*: seq[ColumnIndex]
    dataColumnQuarantine: ref ColumnQuarantine

  ValidatorCustodyRef* = ref ValidatorCustody

func init*(T: type ValidatorCustodyRef, network: Eth2Node,
           dag: ChainDAGRef,
           older_column_set: HashSet[ColumnIndex],
           dataColumnQuarantine: ref ColumnQuarantine): ValidatorCustodyRef =
  (ValidatorCustodyRef)(
    network: network,
    dag: dag,
    older_column_set: older_column_set,
    dataColumnQuarantine: dataColumnQuarantine)

proc detectNewValidatorCustody*(vcus: ValidatorCustodyRef,
                                current_slot: Slot,
                                total_node_balance: Gwei) =
  debug "Total node balance before applying validator custody",
    total_node_balance = total_node_balance
  let
    vcustody =
      vcus.dag.cfg.get_validators_custody_requirement(total_node_balance)
    newer_columns =
      vcus.dag.cfg.resolve_columns_from_custody_groups(
        vcus.network.nodeId,
        max(vcus.dag.cfg.CUSTODY_REQUIREMENT.uint64,
        vcustody))

  # update data column quarantine custody requirements
  vcus.dataColumnQuarantine[].custodyColumns = newer_columns.toSeq()
  sort(vcus.dataColumnQuarantine[].custodyColumns)
  # check which custody set is larger
  if newer_columns.len >= vcus.older_column_set.len:
    vcus.diff_set = toSeq(newer_columns.difference(vcus.older_column_set))
  vcus.older_column_set = newer_columns
  vcus.newer_column_set = newer_columns
  vcus.dag.eaSlot = max(vcus.dag.eaSlot, current_slot)
