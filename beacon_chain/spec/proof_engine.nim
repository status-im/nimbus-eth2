# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## ProofEngine for EIP-8025

import ssz_serialization

from ./datatypes/eip8025 import
  ProofType, ExecutionProof, NewPayloadRequestHeader, NewPayloadRequest

export ProofType, ExecutionProof, NewPayloadRequestHeader, NewPayloadRequest

type
  ProofGenId* = uint8

  ProofAttributes* = object
    proof_types: List[ProofType, 8]

  ProofEngine* = object
    stored_proofs: Table[ProofGenId, ProofAttributes] # TODO...

## Proof verification functions

func verify_execution_proof*(
    engine: ProofEngine, execution_proof: ExecutionProof
): bool =
  # Verify an execution proof.
  # Return ``True`` if proof is valid.
  # TODO:
  # This will hold actual verification logic for different proof types
  # Can use Engine API to external prover (verification)
  true

func verify_new_payload_request_header*(
    engine: ProofEngine, new_payload_request_header: NewPayloadRequestHeader
): bool =
  # Verify the corresponding new payload request execution is valid.
  # Return ``True`` if proof requirements are satisfied.
  # TODO:
  # This will hold actual verification logic for different proof types
  # Can use Engine API to external prover (verification)
  true

## Proof generation functions

func request_proofs*(
    engine: ProofEngine,
    new_payload_request: NewPayloadRequest,
    proof_attributes: ProofAttributes,
): ProofGenId =
  # Request proofs to be generated for a given proof generation ID and attributes.
  # Return ``True`` if the request is accepted.
  # Generated proofs are delivered asynchronously via the beacon API endpoint
  # ``POST /eth/v1/prover/execution_proofs``.
  # actual proof creation would be via engine API to external prover (generation)...?
  ProofGenId(0)
