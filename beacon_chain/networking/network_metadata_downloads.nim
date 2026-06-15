# beacon_chain
# Copyright (c) 2023-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/uri,
  stew/io2, chronos, chronos/apps/http/httpclient, snappy,
  ../spec/[digest, forks], ../spec/datatypes/base

import ./network_metadata
export network_metadata

type
  HttpFetchError* = object of CatchableError
    status*: int

  DigestMismatchError* = object of CatchableError

proc downloadFile(url: Uri): Future[seq[byte]] {.
    async: (raises: [CancelledError, HttpError, HttpFetchError]).} =
  let httpSession = HttpSessionRef.new()
  defer:
    await httpSession.closeWait()

  let response = await httpSession.fetch(url)
  if response[0] == 200:
    return response[1]
  else:
    raise (ref HttpFetchError)(
      msg: "Unexpected status code " & $response[0] & " when fetching " & $url,
      status: response[0])

proc fetchGenesisState*(
    metadata: Eth2NetworkMetadata, genesisStateUrlOverride = none(Uri)
): Future[ref ForkedHashedBeaconState] {.
    async: (raises: [CancelledError, HttpError, HttpFetchError,
                     SerializationError, DigestMismatchError, IOError]).} =
  ## Fetch and parse the genesis beacon state from the configured source, which
  ## may include downloading it.
  case metadata.genesis.kind
  of NoGenesis:
    raiseAssert "fetchGenesisState should be called only when metadata.hasGenesis is true"
  of BakedIn:
    try:
      newClone(
        readSszForkedHashedBeaconState(metadata.cfg, metadata.genesis.bakedBytes)
      )
    except SerializationError as err:
      raiseAssert "Invalid baked-in state: " & err.msg
  of BakedInUrl:
    var tmp = await downloadFile(genesisStateUrlOverride.get(metadata.genesis.url))
    # Under the built-in default URL, we serve a snappy-encoded BeaconState in order
    # to reduce the size of the downloaded file with roughly 50% (this precise ratio
    # depends on the number of validator records). The user is still free to provide
    # any URL which may serve an uncompressed state (e.g. a Beacon API endpoint)
    #
    # Since a SSZ-encoded BeaconState will start with a LittleEndian genesis time
    # (64 bits) while a snappy framed stream will always start with a fixed header
    # that will decoded as a timestamp with the value 5791996851603375871 (year 2153).
    if tmp.isSnappyFramedStream:
      tmp = decodeFramed(tmp)

    let state = newClone(readSszForkedHashedBeaconState(metadata.cfg, tmp))
    if state[].root != metadata.genesis.digest:
      raise (ref DigestMismatchError)(
        msg: "The downloaded genesis state cannot be verified (checksum mismatch)")
    state
  of UserSuppliedFile:
    var tmp: seq[byte]
    io2.readFile(metadata.genesis.path, tmp).isOkOr:
      raise (ref IOError)(msg: error.ioErrorMsg())

    newClone(readSszForkedHashedBeaconState(metadata.cfg, tmp))

proc sourceDesc*(metadata: GenesisMetadata): string =
  case metadata.kind
  of NoGenesis:
    "no genesis"
  of BakedIn:
    metadata.networkName
  of BakedInUrl:
    $metadata.url
  of UserSuppliedFile:
    metadata.path
