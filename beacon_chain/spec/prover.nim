# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  ssz_serialization,
  ./proof_engine,
  ./crypto,
  ./helpers # get_domain, compute_signing_root

from std/sequtils import mapIt
from std/tables import Table

from ./datatypes/eip8025 import
  ExecutionProof, SignedExecutionProof, NewPayloadRequest, DOMAIN_EXECUTION_PROOF
from ./datatypes/electra import BeaconBlockBody
from ./beaconstate import ForkyBeaconState
from ./state_transition_block import kzg_commitment_to_versioned_hash
from ./beacon_time import epoch

## Prover for EIP-8025
##
## Prover (Prover/Relay) is the Beacon Node component responsible for managing proof
## generation for EIP-8025 execution proofs. It interacts with a external ProofEngine to
## request proof generation and handles signing of proofs for broadcasting on the
## execution proof gossip topic.
## This compontent is not to be confused with the external component that actually creates
## the proofs.
##

type Prover = object
  proof_engine: ProofEngine
  # TODO: here or in ProofEngine? Depends a bit on how we design this.
  # - track response in ProofEngine and just await this here.
  # - or track response here with some callback.
  pending_proofs: Table[ProofGenId, ProofAttributes]

# https://github.com/ethereum/consensus-specs/blob/f73487b93bfcf6a047766187578e513a69ee8c7f/specs/_features/eip8025/prover.md#new-get_execution_proof_signature
# Not using state here but fork + genesis_validators_root + slot, similar as is done in signatures.nim code.
func get_execution_proof_signature(
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    proof: ExecutionProof,
    privkey: ValidatorPrivKey,
    slot: Slot,
): ValidatorSig =
  let domain =
    get_domain(fork, DOMAIN_EXECUTION_PROOF, epoch(slot), genesis_validators_root)
  let signing_root = compute_signing_root(proof, domain)

  blsSign(privkey, signing_root.data).toValidatorSig()

# https://github.com/ethereum/consensus-specs/blob/9e00036e7a4596c5858187e4473ec4bbbb5ee3cc/specs/_features/eip8025/prover.md#constructing-signedexecutionproof
func createSignedExecutionProof(
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    proof: ExecutionProof,
    privkey: ValidatorPrivKey,
    slot: Slot,
): SignedExecutionProof =
  let signature =
    get_execution_proof_signature(fork, genesis_validators_root, proof, privkey, slot)
  # let pubkey = privkey.toPubKey()
  # TODO: get actual validator index here from state
  # This used to be the pubkey but it got changed to index as this was easier
  # in the verification code to check if the validator is active...
  # But here it is making things more ugly as we need state access

  let validator_index = 0'u64

  SignedExecutionProof(
    message: proof, validator_index: validator_index, signature: signature
  )

proc RequestExecutionProof(
    prover: var Prover,
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    state: ForkyBeaconState,
    beaconBlockBody: fulu.BeaconBlockBody,
    proof_attributes: ProofAttributes,
    privkey: ValidatorPrivKey,
    slot: Slot,
): ProofGenId =
  # Extract NewPayloadRequest from BeaconBlockBody
  let new_payload_request = NewPayloadRequest(
    execution_payload: beaconBlockBody.execution_payload,
    versioned_hashes:
      mapIt(beaconBlockBody.blob_kzg_commitments, kzg_commitment_to_versioned_hash(it)),
    parent_beacon_block_root: state.latest_block_header.parent_root,
    execution_requests: beaconBlockBody.execution_requests,
  )

  # Create ProofAttributes with desired proof types and request proofs
  let proof_gen_id =
    prover.proof_engine.request_proofs(new_payload_request, proof_attributes)

  # Track pending proof generation so responses can be matched later
  prover.pending_proofs[proof_gen_id] = proof_attributes

  proof_gen_id

proc handleExecutionProof*(
    prover: var Prover,
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    proof_gen_id: ProofGenId,
    proof: ExecutionProof,
    privkey: ValidatorPrivKey,
    slot: Slot,
    broadcast: proc(signed: SignedExecutionProof) {.gcsafe, raises: [].},
) =
  # Validate the proof matches a pending proof_gen_id
  if proof_gen_id notin prover.pending_proofs:
    return

  prover.pending_proofs.del(proof_gen_id)

  # Set message to the ExecutionProof and sign it
  let signed =
    createSignedExecutionProof(fork, genesis_validators_root, proof, privkey, slot)

  # Broadcast the SignedExecutionProof on the execution_proof gossip topic
  broadcast(signed)
