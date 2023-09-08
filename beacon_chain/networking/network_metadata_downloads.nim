# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/uri,
  stew/io2, chronos, chronos/apps/http/httpclient, snappy,
  ../spec/digest

import network_metadata
export network_metadata

type
  HttpFetchError* = object of CatchableError
    status*: int

  DigestMismatchError* = object of CatchableError

proc downloadFile(url: Uri): Future[seq[byte]] {.async.} =
  var httpSession = HttpSessionRef.new()
  let response = await httpSession.fetch(url)
  if response[0] == 200:
    return response[1]
  else:
    raise (ref HttpFetchError)(
      msg: "Unexpected status code " & $response[0] & " when fetching " & $url,
      status: response[0])

proc fetchBytes*(metadata: GenesisMetadata,
                 genesisStateUrlOverride = none(Uri)): Future[seq[byte]] {.async.} =
  case metadata.kind
  of NoGenesis:
    raiseAssert "fetchBytes should be called only when metadata.hasGenesis is true"
  of BakedIn:
    result = @(metadata.bakedBytes)
  of BakedInUrl:
    result = decodeFramed(await downloadFile(genesisStateUrlOverride.get(parseUri metadata.url)))
    if eth2digest(result) != metadata.digest:
      raise (ref DigestMismatchError)(
        msg: "The downloaded genesis state cannot be verified (checksum mismatch)")
  of UserSuppliedFile:
    result = readAllBytes(metadata.path).tryGet()

proc sourceDesc*(metadata: GenesisMetadata): string =
  case metadata.kind
  of NoGenesis:
    "no genesis"
  of BakedIn:
    metadata.networkName
  of BakedInUrl:
    metadata.url
  of UserSuppliedFile:
    metadata.path

when isMainModule:
  let holeskyMetadata = getMetadataForNetwork("holesky")
  io2.writeFile(
    "holesky-genesis.ssz",
    waitFor holeskyMetadata.genesis.fetchBytes()
  ).expect("success")
