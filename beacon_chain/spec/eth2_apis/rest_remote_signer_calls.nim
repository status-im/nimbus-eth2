# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, metrics,
  chronos, chronos/apps/http/httpclient, presto, presto/client,
  serialization, json_serialization,
  json_serialization/std/[options, net, sets],
  stew/[results, base10, byteutils],
  "."/[rest_types, eth2_rest_serialization]

export chronos, httpclient, client, rest_types, eth2_rest_serialization, results

type
  Web3SignerResult*[T] = Result[T, string]
  Web3SignerDataResponse* = Web3SignerResult[CookedSig]

declareCounter nbc_remote_signer_requests,
  "Number of remote signer requests"

declareCounter nbc_remote_signer_signatures,
  "Number of remote signer signatures"

declareCounter nbc_remote_signer_failures,
  "Number of remote signer signatures"

declareCounter nbc_remote_signer_200_responses,
  "Number of 200 responses (signature)"

declareCounter nbc_remote_signer_400_responses,
  "Number of 400 responses (bad request format error)"

declareCounter nbc_remote_signer_404_responses,
  "Number of 404 responses (validator not found error)"

declareCounter nbc_remote_signer_412_responses,
  "Number of 412 responses (slashing protection error)"

declareCounter nbc_remote_signer_500_responses,
  "Number of 500 responses (internal server error)"

declareCounter nbc_remote_signer_unknown_responses,
  "Number of unrecognized responses (unknown response code)"

declareCounter nbc_remote_signer_communication_errors,
  "Number of communication errors"

declareHistogram nbc_remote_signer_time,
  "Time(s) used to generate signature usign remote signer",
   buckets = [0.050, 0.100, 0.500, 1.0, 5.0, 10.0]

proc getUpcheck*(): RestResponse[Web3SignerStatusResponse] {.
     rest, endpoint: "/upcheck",
     meth: MethodGet, accept: "application/json" .}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Server-Status

proc getKeys*(): RestResponse[Web3SignerKeysResponse] {.
     rest, endpoint: "/api/v1/eth2/publicKeys",
     meth: MethodGet, accept: "application/json" .}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Public-Key

proc signDataPlain*(identifier: ValidatorPubKey,
                    body: Web3SignerRequest): RestPlainResponse {.
     rest, endpoint: "/api/v1/eth2/sign/{identifier}",
     meth: MethodPost, accept: "application/json" .}
  # https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing

proc signData*(client: RestClientRef, identifier: ValidatorPubKey,
               body: Web3SignerRequest
              ): Future[Web3SignerDataResponse] {.async.} =
  let startSignTick = Moment.now()
  inc(nbc_remote_signer_requests)
  let response =
    try:
      await client.signDataPlain(identifier, body,
                                 restAcceptType = "application/json")
    except RestError as exc:
      let msg = "[" & $exc.name & "] " & $exc.msg
      debug "Error occured while generating signature",
            validator = shortLog(identifier),
            remote_signer = $client.address.getUri(),
            error_name = $exc.name, error_msg = $exc.msg,
            signDur = Moment.now() - startSignTick
      inc(nbc_remote_signer_communication_errors)
      return Web3SignerDataResponse.err(msg)
    except CatchableError as exc:
      let msg = "[" & $exc.name & "] " & $exc.msg
      debug "Unexpected error occured while generating signature",
            validator = shortLog(identifier),
            remote_signer = $client.address.getUri(),
            error_name = $exc.name, error_msg = $exc.msg,
            signDur = Moment.now() - startSignTick
      inc(nbc_remote_signer_communication_errors)
      return Web3SignerDataResponse.err(msg)

  let res =
    case response.status
    of 200:
      inc(nbc_remote_signer_200_responses)
      let sig =
        if response.contentType.isNone() or
           isWildCard(response.contentType.get().mediaType):
          return Web3SignerDataResponse.err(
            "Unable to decode signature from missing or incorrect content")
        else:
          let mediaType = response.contentType.get().mediaType
          if mediaType == TextPlainMediaType:
            let asStr = fromBytes(string, response.data)
            let sigFromText = fromHex(ValidatorSig, asStr)
            if sigFromText.isErr:
              return Web3SignerDataResponse.err(
                "Unable to decode signature from plain text")
            sigFromText.get.load
          else:
            let res = decodeBytes(Web3SignerSignatureResponse, response.data,
                                  response.contentType)
            if res.isErr:
              let msg = "Unable to decode remote signer response [" &
                        $res.error() & "]"
              inc(nbc_remote_signer_failures)
              return Web3SignerDataResponse.err(msg)
            res.get.signature.load

      if sig.isNone:
        let msg = "Remote signer returns invalid signature"
        inc(nbc_remote_signer_failures)
        return Web3SignerDataResponse.err(msg)

      Web3SignerDataResponse.ok(sig.get)
    of 400:
      inc(nbc_remote_signer_400_responses)
      let res = decodeBytes(Web3SignerErrorResponse, response.data,
                            response.contentType)
      let msg =
        if res.isErr():
          "Remote signer returns 400 Bad Request Format Error"
        else:
          "Remote signer returns 400 Bad Request Format Error [" &
          res.get().error & "]"
      Web3SignerDataResponse.err(msg)
    of 404:
      let res = decodeBytes(Web3SignerErrorResponse, response.data,
                            response.contentType)
      let msg =
        if res.isErr():
          "Remote signer returns 404 Validator's Key Not Found Error"
        else:
          "Remote signer returns 404 Validator's Key Not Found Error [" &
          res.get().error & "]"
      inc(nbc_remote_signer_404_responses)
      Web3SignerDataResponse.err(msg)
    of 412:
      let res = decodeBytes(Web3SignerErrorResponse, response.data,
                            response.contentType)
      let msg =
        if res.isErr():
          "Remote signer returns 412 Slashing Protection Error"
        else:
          "Remote signer returns 412 Slashing Protection Error [" &
          res.get().error & "]"
      inc(nbc_remote_signer_412_responses)
      Web3SignerDataResponse.err(msg)
    of 500:
      let res = decodeBytes(Web3SignerErrorResponse, response.data,
                            response.contentType)
      let msg =
        if res.isErr():
          "Remote signer returns 500 Internal Server Error"
        else:
          "Remote signer returns 500 Internal Server Error [" &
          res.get().error & "]"
      inc(nbc_remote_signer_500_responses)
      Web3SignerDataResponse.err(msg)
    else:
      let msg = "Remote signer returns unexpected status code " &
                Base10.toString(uint64(response.status))
      inc(nbc_remote_signer_unknown_responses)
      Web3SignerDataResponse.err(msg)

  if res.isOk():
    let delay = Moment.now() - startSignTick
    inc(nbc_remote_signer_signatures)
    nbc_remote_signer_time.observe(float(milliseconds(delay)) / 1000.0)
    debug "Signature was successfully generated",
          validator = shortLog(identifier),
          remote_signer = $client.address.getUri(),
          signDur = delay
  else:
    inc(nbc_remote_signer_failures)
    debug "Signature generation was failed",
          validator = shortLog(identifier),
          remote_signer = $client.address.getUri(),
          error_msg = res.error(),
          signDur = Moment.now() - startSignTick

  return res
