# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/strutils,
  chronos, chronos/apps/http/httpclient, presto/client,
  nimcrypto/utils as ncrutils,
  stew/[results, base10],
  "."/[rest_types, eth2_rest_serialization]

export chronos, httpclient, client, rest_types, eth2_rest_serialization, results

type
  Web3SignerResult*[T] = Result[T, string]
  Web3SignerDataResponse* = Web3SignerResult[CookedSig]

proc getUpcheck*(): RestResponse[Web3SignerStatusResponse] {.
     rest, endpoint: "/upcheck", meth: MethodGet.}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Server-Status

proc getKeys*(): RestResponse[Web3SignerKeysResponse] {.
     rest, endpoint: "/api/v1/eth2/publicKeys", meth: MethodGet.}
  ## https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Public-Key

proc signDataPlain*(identifier: ValidatorPubKey,
                    body: Web3SignerRequest): RestPlainResponse {.
     rest, endpoint: "/api/v1/eth2/sign/{identifier}", meth: MethodPost.}
  # https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing

proc signData*(client: RestClientRef, identifier: ValidatorPubKey,
               body: Web3SignerRequest
              ): Future[Web3SignerDataResponse] {.async.} =
  let response =
    try:
      await client.signDataPlain(identifier, body)
    except RestError as exc:
      let msg = "[" & $exc.name & "] " & $exc.msg
      return Web3SignerDataResponse.err(msg)
    except CatchableError as exc:
      let msg = "[" & $exc.name & "] " & $exc.msg
      return Web3SignerDataResponse.err(msg)

  return
    case response.status
    of 200:
      let res = decodeBytes(Web3SignerSignatureResponse, response.data,
                            response.contentType)
      if res.isErr():
        let msg = "Unable to decode remote signer response [" &
                  $res.error() & "]"
        return Web3SignerDataResponse.err(msg)
      let sig = res.get().signature.load()
      if sig.isNone():
        let msg = "Remote signer returns invalid signature"
        return Web3SignerDataResponse.err(msg)
      Web3SignerDataResponse.ok(sig.get())
    of 400:
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
      Web3SignerDataResponse.err(msg)
    else:
      let msg = "Remote signer returns unexpected status code " &
                Base10.toString(uint64(response.status))
      Web3SignerDataResponse.err(msg)
