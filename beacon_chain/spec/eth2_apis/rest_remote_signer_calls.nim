# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, metrics,
  chronos, presto/client,
  stew/[results, base10, byteutils],
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization, results

type
  Web3SignerErrorKind* {.pure.} = enum
    Error400, Error404, Error412, Error500, CommError, UnexpectedError,
    UknownStatus, InvalidContentType, InvalidPlain, InvalidContent,
    InvalidSignature, TimeoutError

  Web3SignerError* = object
    kind*: Web3SignerErrorKind
    message*: string

  Web3SignerResult*[T] = Result[T, Web3SignerError]
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

declareHistogram nbc_remote_signer_duration,
  "Time(s) used to generate signature usign remote signer",
   buckets = [0.050, 0.100, 0.500, 1.0, 5.0, 10.0]

proc getUpcheck*(): RestResponse[Web3SignerStatusResponse] {.
     rest, endpoint: "/upcheck",
     meth: MethodGet, accept: "application/json" .}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Server-Status

proc reload*(): RestPlainResponse {.
     rest, endpoint: "/reload",
     meth: MethodPost, accept: "application/json" .}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Reload-Signer-Keys/operation/RELOAD

proc getKeys*(): RestResponse[Web3SignerKeysResponse] {.
     rest, endpoint: "/api/v1/eth2/publicKeys",
     meth: MethodGet, accept: "application/json" .}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Public-Key

proc getKeysPlain*(): RestPlainResponse {.
     rest, endpoint: "/api/v1/eth2/publicKeys",
     meth: MethodGet, accept: "application/json" .}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Public-Key

proc signDataPlain*(identifier: ValidatorPubKey,
                    body: Web3SignerRequest): RestPlainResponse {.
     rest, endpoint: "/api/v1/eth2/sign/{identifier}",
     meth: MethodPost, accept: "application/json" .}
  # https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing

proc init(t: typedesc[Web3SignerError], kind: Web3SignerErrorKind,
          message: string): Web3SignerError =
  Web3SignerError(kind: kind, message: message)

proc signData*(client: RestClientRef, identifier: ValidatorPubKey,
               body: Web3SignerRequest
              ): Future[Web3SignerDataResponse] {.async.} =
  inc(nbc_remote_signer_requests)

  let
    startSignMoment = Moment.now()
    response =
      try:
        let
          res = await client.signDataPlain(identifier, body,
                                           restAcceptType = "application/json")
          duration = Moment.now() - startSignMoment
        nbc_remote_signer_duration.observe(
          float(milliseconds(duration)) / 1000.0)
        res
      except RestError as exc:
        return Web3SignerDataResponse.err(
          Web3SignerError.init(Web3SignerErrorKind.CommError, $exc.msg))
      except CancelledError as exc:
        raise exc
      except CatchableError as exc:
        return Web3SignerDataResponse.err(
          Web3SignerError.init(Web3SignerErrorKind.UnexpectedError, $exc.msg))

  return
    case response.status
    of 200:
      inc(nbc_remote_signer_200_responses)
      let sig =
        if response.contentType.isNone() or
           isWildCard(response.contentType.get().mediaType):
          inc(nbc_remote_signer_failures)
          return Web3SignerDataResponse.err(
            Web3SignerError.init(
              Web3SignerErrorKind.InvalidContentType,
              "Unable to decode signature from missing or incorrect content"
            )
          )
        else:
          let mediaType = response.contentType.get().mediaType
          if mediaType == TextPlainMediaType:
            let
              asStr = fromBytes(string, response.data)
              sigFromText = fromHex(ValidatorSig, asStr).valueOr:
                inc(nbc_remote_signer_failures)
                return Web3SignerDataResponse.err(
                  Web3SignerError.init(
                    Web3SignerErrorKind.InvalidPlain,
                    "Unable to decode signature from plain text"
                  )
                )
            sigFromText.load()
          else:
            let res = decodeBytes(Web3SignerSignatureResponse, response.data,
                                  response.contentType).valueOr:
              inc(nbc_remote_signer_failures)
              return Web3SignerDataResponse.err(
                Web3SignerError.init(
                  Web3SignerErrorKind.InvalidContent,
                  "Unable to decode remote signer response [" & $error & "]"
                )
              )
            res.signature.load()

      if sig.isNone():
        inc(nbc_remote_signer_failures)
        return Web3SignerDataResponse.err(
          Web3SignerError.init(
            Web3SignerErrorKind.InvalidSignature,
            "Remote signer returns invalid signature"
          )
        )

      inc(nbc_remote_signer_signatures)
      Web3SignerDataResponse.ok(sig.get())
    of 400:
      inc(nbc_remote_signer_400_responses)
      let message =
        block:
          let res = decodeBytes(Web3SignerErrorResponse, response.data,
                                response.contentType)
          if res.isErr():
            "Remote signer returns 400 Bad Request Format Error"
          else:
            res.get().error
      Web3SignerDataResponse.err(
        Web3SignerError.init(Web3SignerErrorKind.Error400, message))
    of 404:
      inc(nbc_remote_signer_404_responses)
      let message =
        block:
          let res = decodeBytes(Web3SignerErrorResponse, response.data,
                                response.contentType)
          if res.isErr():
            "Remote signer returns 404 Validator's Key Not Found Error"
          else:
            res.get().error
      Web3SignerDataResponse.err(
        Web3SignerError.init(Web3SignerErrorKind.Error404, message))
    of 412:
      inc(nbc_remote_signer_412_responses)
      let message =
        block:
          let res = decodeBytes(Web3SignerErrorResponse, response.data,
                                response.contentType)
          if res.isErr():
            "Remote signer returns 412 Slashing Protection Error"
          else:
            res.get().error
      Web3SignerDataResponse.err(
        Web3SignerError.init(Web3SignerErrorKind.Error412, message))
    of 500:
      inc(nbc_remote_signer_500_responses)
      let message =
        block:
          let res = decodeBytes(Web3SignerErrorResponse, response.data,
                                response.contentType)
          if res.isErr():
            "Remote signer returns 500 Internal Server Error"
          else:
            res.get().error
      Web3SignerDataResponse.err(
        Web3SignerError.init(Web3SignerErrorKind.Error500, message))
    else:
      inc(nbc_remote_signer_unknown_responses)
      let message =
        block:
          let res = decodeBytes(Web3SignerErrorResponse, response.data,
                                response.contentType)
          if res.isErr():
            "Remote signer returns unexpected status code " &
              Base10.toString(uint64(response.status))
          else:
            res.get().error
      Web3SignerDataResponse.err(
        Web3SignerError.init(Web3SignerErrorKind.UknownStatus, message))

proc signData*(
       client: RestClientRef,
       identifier: ValidatorPubKey,
       timerFut: Future[void],
       attemptsCount: int,
       body: Web3SignerRequest
     ): Future[Web3SignerDataResponse] {.async.} =
  doAssert(attemptsCount >= 1)

  const BackoffTimeouts = [
    10.milliseconds, 100.milliseconds, 1.seconds, 2.seconds, 5.seconds
  ]

  var
    attempt = 0
    currentTimeout = 0

  while true:
    var
      operationFut: Future[Web3SignerDataResponse]
      lastError: Opt[Web3SignerError]
    try:
      operationFut = signData(client, identifier, body)
      if isNil(timerFut):
        await allFutures(operationFut)
      else:
        discard await race(timerFut, operationFut)
    except CancelledError as exc:
      if not(operationFut.finished()):
        await operationFut.cancelAndWait()
      raise exc

    if not(operationFut.finished()):
      await operationFut.cancelAndWait()
      if lastError.isSome():
        # We return last know error instead of timeout error.
        return Web3SignerDataResponse.err(lastError.get())
      else:
        return Web3SignerDataResponse.err(
          Web3SignerError.init(
            Web3SignerErrorKind.TimeoutError,
            "Operation timed out"
          )
        )
    else:
      let resp = operationFut.read()
      if resp.isOk():
        return resp

      case resp.error.kind
      of Web3SignerErrorKind.Error404,
         Web3SignerErrorKind.Error412,
         Web3SignerErrorKind.Error500,
         Web3SignerErrorKind.CommError,
         Web3SignerErrorKind.UnexpectedError:
        ## Non-critical errors
        if attempt == attemptsCount:
          # Number of attempts exceeded, so we return result we have.
          return resp
        else:
          # We have some attempts left, so we show debug log about current
          # attempt
          debug "Unable to get signature using remote signer",
                kind = resp.error.kind, reason = resp.error.message,
                attempts_count = attemptsCount, attempt = attempt
          lastError = Opt.some(resp.error)
          inc(attempt)
          await sleepAsync(BackoffTimeouts[currentTimeout])
          if currentTimeout < len(BackoffTimeouts) - 1:
            inc currentTimeout
      of Web3SignerErrorKind.Error400,
         Web3SignerErrorKind.UknownStatus,
         Web3SignerErrorKind.InvalidContentType,
         Web3SignerErrorKind.InvalidPlain,
         Web3SignerErrorKind.InvalidContent,
         Web3SignerErrorKind.InvalidSignature:
        # Critical errors
        return resp
      of Web3SignerErrorKind.TimeoutError:
        raiseAssert "Timeout error should not be happened"
