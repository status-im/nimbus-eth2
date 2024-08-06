# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ../datatypes/stable
export stable

type
  StableBlindedBeaconBlockBody* {.
      sszStableContainer: MAX_BEACON_BLOCK_BODY_FIELDS.} = object
    randao_reveal*: Opt[ValidatorSig]
    eth1_data*: Opt[Eth1Data]
      ## Eth1 data vote

    graffiti*: Opt[GraffitiBytes]
      ## Arbitrary data

    # Operations
    proposer_slashings*: Opt[List[ProposerSlashing,
      Limit MAX_PROPOSER_SLASHINGS]]
    attester_slashings*: Opt[List[StableAttesterSlashing,
      Limit MAX_ATTESTER_SLASHINGS_ELECTRA]]
    attestations*: Opt[List[StableAttestation, Limit MAX_ATTESTATIONS_ELECTRA]]
    deposits*: Opt[List[Deposit, Limit MAX_DEPOSITS]]
    voluntary_exits*: Opt[List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]]

    sync_aggregate*: Opt[SyncAggregate]

    # Execution
    execution_payload_header*: Opt[StableExecutionPayloadHeader]
    bls_to_execution_changes*: Opt[SignedBLSToExecutionChangeList]
    blob_kzg_commitments*: Opt[KzgCommitments]
