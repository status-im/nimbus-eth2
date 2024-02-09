# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import results

from ../beacon_chain/consensus_object_pools/block_clearance import
  addHeadBlockWithParent
from ../beacon_chain/consensus_object_pools/block_dag import BlockRef
from ../beacon_chain/consensus_object_pools/block_pools_types import
  ChainDAGRef, OnForkyBlockAdded, VerifierError
from ../beacon_chain/spec/forks import ForkySignedBeaconBlock
from ../beacon_chain/spec/signatures_batch import BatchVerifier

proc addHeadBlock*(
    dag: ChainDAGRef, verifier: var BatchVerifier,
    signedBlock: ForkySignedBeaconBlock,
    onBlockAdded: OnForkyBlockAdded
    ): Result[BlockRef, VerifierError] =
  addHeadBlockWithParent(
    dag, verifier, signedBlock, ? dag.checkHeadBlock(signedBlock),
    executionValid = true, onBlockAdded)
