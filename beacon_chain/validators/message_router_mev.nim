# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import ../beacon_node

from ../spec/datatypes/bellatrix import SignedBeaconBlock
from ../spec/mev/rest_mev_calls import submitBlindedBlock

const BUILDER_BLOCK_SUBMISSION_DELAY_TOLERANCE = 5.seconds

proc unblindAndRouteBlockMEV*(
    node: BeaconNode, payloadBuilderRestClient: RestClientRef,
    blindedBlock: fulu_mev.SignedBlindedBeaconBlock):
    Future[Result[Opt[BlockRef], string]] {.async: (raises: [CancelledError]).} =
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

  if response.status == 202:
    ok(Opt.none(BlockRef))
  else:
    # https://github.com/ethereum/builder-specs/blob/v0.5.0/specs/bellatrix/validator.md#proposer-slashing
    # This means if a validator publishes a signature for a
    # `BlindedBeaconBlock` (via a dissemination of a
    # `SignedBlindedBeaconBlock`) then the validator **MUST** not use the
    # local build process as a fallback, even in the event of some failure
    # with the external builder network.
    err("submitBlindedBlock failed with HTTP error code " &
      $response.status & ": " & $shortLog(blindedBlock))
