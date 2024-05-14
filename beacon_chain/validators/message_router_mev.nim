# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/macros
import metrics
import stew/assign2
import ../beacon_node

from ../spec/datatypes/bellatrix import SignedBeaconBlock
from ../spec/mev/rest_deneb_mev_calls import submitBlindedBlock
from ../spec/mev/rest_electra_mev_calls import submitBlindedBlock

const
  BUILDER_BLOCK_SUBMISSION_DELAY_TOLERANCE = 5.seconds

declareCounter beacon_block_builder_proposed,
  "Number of beacon chain blocks produced using an external block builder"

func getFieldNames*(x: typedesc[auto]): seq[string] {.compileTime.} =
  var res: seq[string]
  for name, _ in fieldPairs(default(x)):
    res.add name
  res

macro copyFields*(
    dst: untyped, src: untyped, fieldNames: static[seq[string]]): untyped =
  result = newStmtList()
  for name in fieldNames:
    debugComment "deposit_receipts_root and exits_root are not currently filled in anywhere properly, so blinded electra proposals will fail"
    if name notin [
        # These fields are the ones which vary between the blinded and
        # unblinded objects, and can't simply be copied.
        "transactions_root", "execution_payload",
        "execution_payload_header", "body", "withdrawals_root",
        "deposit_receipts_root", "withdrawal_requests_root"]:
      # TODO use stew/assign2
      result.add newAssignment(
        newDotExpr(dst, ident(name)), newDotExpr(src, ident(name)))

proc unblindAndRouteBlockMEV*(
    node: BeaconNode, payloadBuilderRestClient: RestClientRef,
    blindedBlock:
      deneb_mev.SignedBlindedBeaconBlock |
      electra_mev.SignedBlindedBeaconBlock):
    Future[Result[Opt[BlockRef], string]] {.async: (raises: [CancelledError]).} =
  const consensusFork = typeof(blindedBlock).kind

  info "Proposing blinded Builder API block",
    blindedBlock = shortLog(blindedBlock)

  # By time submitBlindedBlock is called, must already have done slashing
  # protection check
  let response =
    try:
      await payloadBuilderRestClient.submitBlindedBlock(blindedBlock).
        wait(BUILDER_BLOCK_SUBMISSION_DELAY_TOLERANCE)
      # From here on, including error paths, disallow local EL production by
      # returning Opt.some, regardless of whether on head or newBlock.
    except AsyncTimeoutError:
      return err("Submitting blinded block timed out")
    except RestEncodingError as exc:
      return err(
        "REST encoding error submitting blinded block, reason " & exc.msg)
    except RestDnsResolveError as exc:
      return err(
        "REST unable to resolve remote host, reason " & exc.msg)
    except RestCommunicationError as exc:
      return err(
        "REST unable to communicate with remote host, reason " & exc.msg)

  const httpOk = 200
  if response.status != httpOk:
    # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/validator.md#proposer-slashing
    # This means if a validator publishes a signature for a
    # `BlindedBeaconBlock` (via a dissemination of a
    # `SignedBlindedBeaconBlock`) then the validator **MUST** not use the
    # local build process as a fallback, even in the event of some failure
    # with the external builder network.
    return err("submitBlindedBlock failed with HTTP error code " &
      $response.status & ": " & $shortLog(blindedBlock))

  when blindedBlock is deneb_mev.SignedBlindedBeaconBlock:
    let res = decodeBytes(
      SubmitBlindedBlockResponseDeneb, response.data, response.contentType)
  elif blindedBlock is electra_mev.SignedBlindedBeaconBlock:
    let res = decodeBytes(
      SubmitBlindedBlockResponseElectra, response.data, response.contentType)
  else:
    static: doAssert false

  let bundle = res.valueOr:
    return err("Could not decode " & $consensusFork & " blinded block: " & $res.error &
      " with HTTP status " & $response.status & ", Content-Type " &
      $response.contentType & " and content " & $response.data)

  template execution_payload: untyped = bundle.data.execution_payload

  if hash_tree_root(blindedBlock.message.body.execution_payload_header) !=
      hash_tree_root(execution_payload):
    return err("unblinded payload doesn't match blinded payload header: " &
      $blindedBlock.message.body.execution_payload_header)

  # Signature provided is consistent with unblinded execution payload,
  # so construct full beacon block
  # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/validator.md#block-proposal
  var signedBlock = consensusFork.SignedBeaconBlock(
    signature: blindedBlock.signature)
  copyFields(
    signedBlock.message, blindedBlock.message,
    getFieldNames(typeof(signedBlock.message)))
  copyFields(
    signedBlock.message.body, blindedBlock.message.body,
    getFieldNames(typeof(signedBlock.message.body)))
  assign(signedBlock.message.body.execution_payload, execution_payload)
  signedBlock.root = hash_tree_root(signedBlock.message)
  doAssert signedBlock.root == hash_tree_root(blindedBlock.message)

  let blobsOpt =
    when consensusFork >= ConsensusFork.Deneb:
      template blobs_bundle: untyped = bundle.data.blobs_bundle
      if blindedBlock.message.body.blob_kzg_commitments !=
          bundle.data.blobs_bundle.commitments:
        return err("unblinded blobs bundle has unexpected commitments")
      let ok = verifyProofs(
          asSeq blobs_bundle.blobs,
          asSeq blobs_bundle.commitments,
          asSeq blobs_bundle.proofs).valueOr:
        return err("unblinded blobs bundle fails verification")
      if not ok:
        return err("unblinded blobs bundle is invalid")
      Opt.some(signedBlock.create_blob_sidecars(
        blobs_bundle.proofs, blobs_bundle.blobs))
    else:
      Opt.none(seq[BlobSidecar])

  debug "unblindAndRouteBlockMEV: proposing unblinded block",
    blck = shortLog(signedBlock)

  let newBlockRef =
    (await node.router.routeSignedBeaconBlock(signedBlock, blobsOpt)).valueOr:
      # submitBlindedBlock has run, so don't allow fallback to run
      return err("routeSignedBeaconBlock error") # Errors logged in router

  if newBlockRef.isSome:
    beacon_block_builder_proposed.inc()
    notice "Block proposed (MEV)",
      blockRoot = shortLog(signedBlock.root), blck = shortLog(signedBlock),
      signature = shortLog(signedBlock.signature)

  ok newBlockRef
