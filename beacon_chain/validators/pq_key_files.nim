# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## The files of precomputed trees of PQ validator keys, see `--vrf-state-url`
## and `--xmss-cache-url`, for the validators of a beacon node or of a
## validator client.

import
  std/[algorithm, options, sequtils, strutils, tables, uri],
  stew/io2,
  chronos, chronos/apps/http/httpclient,
  chronicles,
  ../spec/[crypto, digest, pq_vrf, xmss],
  ./validator_pool

export options, tables, validator_pool

const
  XMSS_TREE_CACHE_SIZE* =
    XMSS_CACHED_TOP_TREE_SIZE + 2 * XMSS_CACHED_BOTTOM_TREE_SIZE
    ## A record of the file of `--xmss-cache-url`: the top tree of a key, the
    ## bottom tree of its first attestations and that of its first slot duties

  vrfStateSuffix = ".vrf"
  xmssCacheSuffix = ".xmss"

type
  XmssCacheRun* = tuple[first, count: uint64]
    ## Consecutive records of the file of `--xmss-cache-url`

  XmssCacheOwner* = tuple[pubkey: ValidatorPubKey, xmss: XMSSPubkey]
    ## The local validator a record of the file of `--xmss-cache-url` is
    ## expected to be of, and its XMSS public key

  XmssCacheSource* = tuple[source: string, guessed: bool]

func isRemote(source: string): bool =
  source.startsWith("http://") or source.startsWith("https://")

proc fetchVrfTreeStates*(source: string): Future[seq[byte]] {.
    async: (raises: [CancelledError]).} =
  ## The file of `--vrf-state-url`, empty when unavailable.
  if not source.isRemote:
    return io2.readAllBytes(source).valueOr:
      error "Unable to read VRF tree states",
        path = source, err = ioErrorMsg(error)
      return @[]

  let session = HttpSessionRef.new()
  defer:
    await session.closeWait()
  try:
    let response = await session.fetch(parseUri(source))
    if response.status != 200:
      error "Unable to download VRF tree states",
        url = source, status = response.status
      return @[]
    info "Downloaded VRF tree states",
      url = source, validators = response.data.len div VRF_TREE_STATE_SIZE
    response.data
  except HttpError as exc:
    error "Unable to download VRF tree states", url = source, err = exc.msg
    @[]

func findVrfTreeStates*(
    data: openArray[byte], secondLeaves: Table[Eth2Digest, ValidatorPubKey]
): Table[ValidatorPubKey, uint64] =
  ## The index of the record of each validator in ``data``, a file of
  ## `VRF_TREE_STATE_SIZE` bytes per record, see `VrfTreeState`. A record is
  ## the branch of leaf 0 of a VRF tree, so it starts with leaf 1, which is
  ## what ``secondLeaves`` names the validators by. The files are made for
  ## the keys of a mnemonic in order, which is the order of the validators of
  ## a devnet, but a validator client does not know its indices before it has
  ## its keys.
  var res: Table[ValidatorPubKey, uint64]
  for index in 0 ..< data.len div VRF_TREE_STATE_SIZE:
    let start = index * VRF_TREE_STATE_SIZE + 36
    var leaf {.noinit.}: Eth2Digest
    leaf.data[0 ..< 32] = data.toOpenArray(start, start + 31)
    secondLeaves.withValue(leaf, pubkey):
      discard res.hasKeyOrPut(pubkey, uint64(index))
  res

func xmssCacheSource*(
    xmssCacheUrl, vrfStateUrl: Option[string]): Opt[XmssCacheSource] =
  ## Where the XMSS tree caches are. The devnet tooling publishes them next
  ## to the VRF tree states, as `<name>.xmss` beside `<name>.vrf`, and
  ## launchers that predate `--xmss-cache-url` pass the latter only: the file
  ## is then guessed. A file that turns out not to hold the caches of the
  ## local keys is ignored, as any other.
  if xmssCacheUrl.isSome:
    Opt.some((xmssCacheUrl.get, false))
  elif vrfStateUrl.isSome and vrfStateUrl.get.endsWith(vrfStateSuffix):
    Opt.some((
      vrfStateUrl.get[0 ..^ (vrfStateSuffix.len + 1)] & xmssCacheSuffix, true))
  else:
    Opt.none(XmssCacheSource)

func toRuns*(indices: openArray[uint64]): seq[XmssCacheRun] =
  ## ``indices``, sorted, as runs of consecutive indices.
  var res: seq[XmssCacheRun]
  for index in indices:
    if res.len > 0 and res[^1].first + res[^1].count == index:
      inc res[^1].count
    else:
      res.add (index, 1'u64)
  res

proc readXmssCacheRun(path: string, run: XmssCacheRun): Opt[seq[byte]] =
  ## The records of ``run`` in the local file at ``path``.
  var res = newSeq[byte](run.count * XMSS_TREE_CACHE_SIZE)
  try:
    let file = open(path, fmRead)
    defer: file.close()
    file.setFilePos(int64(run.first * XMSS_TREE_CACHE_SIZE))
    if file.readBytes(res, 0, res.len) != res.len:
      return Opt.none(seq[byte])
  except IOError:
    return Opt.none(seq[byte])
  Opt.some res

proc downloadXmssCacheRun(
    session: HttpSessionRef, url: string,
    run: XmssCacheRun): Future[Opt[seq[byte]]] {.
    async: (raises: [CancelledError]).} =
  ## The records of ``run`` in the file at ``url``, with a range request.
  let
    first = run.first * XMSS_TREE_CACHE_SIZE
    size = run.count * XMSS_TREE_CACHE_SIZE
    request = HttpClientRequestRef.new(
      session, url, headers = [
        ("Range", "bytes=" & $first & "-" & $(first + size - 1)),
        ("Accept-Encoding", "identity")]).valueOr:
      warn "Invalid XMSS tree cache URL", url, err = error
      return Opt.none(seq[byte])
  try:
    let response = await request.fetch()
    if response.status == 206 and response.data.lenu64 == size:
      Opt.some response.data
    elif response.status == 200 and response.data.lenu64 >= first + size:
      # The server ignored the range and sent the whole file
      Opt.some response.data[first ..< first + size]
    else:
      warn "Unable to download XMSS tree caches",
        url, status = response.status, received = response.data.len,
        expected = size
      Opt.none(seq[byte])
  except HttpError as exc:
    warn "Unable to download XMSS tree caches", url, err = exc.msg
    Opt.none(seq[byte])

proc fetchXmssTreeCaches*(
    cacheSource: XmssCacheSource, owners: Table[uint64, XmssCacheOwner],
    localValidators: int): Future[XmssTreeCaches] {.
    async: (raises: [CancelledError]).} =
  ## The tree caches of the validators of ``owners``, by the index of their
  ## record in the file at ``cacheSource``. A validator without a usable
  ## record is left out: its trees are hashed instead.
  var res: XmssTreeCaches
  if owners.len == 0:
    return res

  let
    source = cacheSource.source
    remote = source.isRemote
    session = if remote: HttpSessionRef.new() else: nil
    start = Moment.now()
  defer:
    if not session.isNil:
      await session.closeWait()

  for run in toRuns(sorted(toSeq(owners.keys))):
    let records =
      if remote:
        await session.downloadXmssCacheRun(source, run)
      else:
        let records = readXmssCacheRun(source, run)
        if records.isNone:
          warn "Unable to read XMSS tree caches",
            path = source, first_validator = run.first, validators = run.count
        records
    if records.isNone:
      continue
    for i in 0'u64 ..< run.count:
      let (pubkey, xmss) = owners.getOrDefault(run.first + i)
      res[pubkey] = XmssTreeCache(
        pubkey: xmss,
        trees: records.get[
          i * XMSS_TREE_CACHE_SIZE ..< (i + 1) * XMSS_TREE_CACHE_SIZE])
  info "Fetched XMSS tree caches",
    source, from_vrf_state_url = cacheSource.guessed, validators = res.len,
    local_validators = localValidators, dur = Moment.now() - start
  res
