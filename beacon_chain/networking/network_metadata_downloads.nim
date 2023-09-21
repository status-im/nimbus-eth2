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
    result = await downloadFile(genesisStateUrlOverride.get(parseUri metadata.url))
    # Under the built-in default URL, we serve a snappy-encoded BeaconState in order
    # to reduce the size of the downloaded file with roughly 50% (this precise ratio
    # depends on the number of validator recors). The user is still free to provide
    # any URL which may serve an uncompressed state (e.g. a Beacon API endpoint)
    #
    # Since a SSZ-encoded BeaconState will start with a LittleEndian genesis time
    # (64 bits) while a snappy framed stream will always start with a fixed header
    # that will decoded as a timestamp with the value 5791996851603375871 (year 2153).
    #
    # TODO: A more complete solution will implement compression on the HTTP level,
    #       by relying on the Content-Encoding header to determine the compression
    #       algorithm. The detection method used here will not interfere with such
    #       an implementation and it may remain useful when dealing with misconfigured
    #       HTTP servers.
    if result.isSnappyFramedStream:
      result = decodeFramed(result)
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
