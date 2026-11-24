# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## STARK proofs of many XMSS signatures (the spec's `stark` module).
##
## https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/beacon-chain.md#stark-proofs
##
## Two backends:
##
## - `sidecar`: proofs from leanVM's `leanvm-sidecar` over its Unix socket
##   (protocol version 1). A proof's bytes are the sidecar's proof alone; the
##   claims are rebuilt from the statements as the sorted, de-duplicated list of
##   `(pubkey, message)` pairs. The leaf index is not part of a claim. The empty
##   proof stands for "nothing to prove". This is the wire format of the PQ
##   devnet.
## - `reference`: the spec's stand-in, where a proof is the signatures
##   concatenated. For single-client testing only.

import
  std/[algorithm, net],
  chronicles, chronos, results,
  stew/endians2,
  ./digest, ./xmss

export results, xmss, digest

logScope: topics = "pq_stark"

const
  SidecarMagic = "leanvmsc"
  SidecarVersion = 1'u32
  SidecarVerifierTag = "leanvm-v1"
  OpAggregate = 1'u8
  OpVerify = 2'u8
  MaxChildrenPerAggregate* = 16
  DefaultLogInvRate* = 2'u8

type
  XMSSAggregateStatement* = object
    pubkeys*: seq[XMSSPubkey]
    leaf_index*: uint64
    message*: Eth2Digest

  StarkBackendKind* {.pure.} = enum
    Reference = "reference"
    Sidecar = "sidecar"

  StarkConfig* = object
    kind*: StarkBackendKind
    socketPath*: string
    logInvRate*: uint8
    verifyTimeoutMs*: int
    proveTimeout*: Duration

  Claim = array[64, byte]

  StarkError* = object of CatchableError

var
  starkConfig {.global.} = StarkConfig(
    kind: StarkBackendKind.Reference, logInvRate: DefaultLogInvRate,
    verifyTimeoutMs: 30_000, proveTimeout: 300.seconds)
  verifySocket {.global.}: Socket
  proveLock {.global.}: AsyncLock

proc configureStark*(config: StarkConfig) =
  {.cast(gcsafe).}:
    starkConfig = config
    if verifySocket != nil:
      verifySocket.close()
      verifySocket = nil

proc starkBackend*(): StarkBackendKind =
  {.cast(gcsafe).}:
    starkConfig.kind

# ----------------------------------------------------------------------------
# Claims

func cmpClaim(a, b: Claim): int =
  for i in 0 ..< a.len:
    if a[i] != b[i]:
      return (if a[i] < b[i]: -1 else: 1)
  0

func sortedClaims(statements: openArray[XMSSAggregateStatement]): seq[Claim] =
  var claims: seq[Claim]
  for statement in statements:
    for pubkey in statement.pubkeys:
      var claim: Claim
      claim[0 ..< 32] = pubkey.blob
      claim[32 ..< 64] = statement.message.data
      claims.add claim
  claims.sort(cmpClaim)
  var res: seq[Claim]
  for claim in claims:
    if res.len == 0 or res[^1] != claim:
      res.add claim
  res

func encodeClaims(claims: openArray[Claim]): seq[byte] =
  ## `AggregateClaims::to_bytes`: XMSS claims, no SPHINCS claims, no DA root.
  var res = newSeqOfCap[byte](8 + 64 * claims.len + 8 + 1)
  res.add claims.len.uint64.toBytesLE()
  for claim in claims:
    res.add claim
  res.add 0'u64.toBytesLE()
  res.add 0'u8
  res

func statementsToClaimsBytes*(
    statements: openArray[XMSSAggregateStatement]): seq[byte] =
  encodeClaims(sortedClaims(statements))

func mergeClaims(children: openArray[seq[Claim]]): seq[Claim] =
  var all: seq[Claim]
  for c in children:
    all.add c
  all.sort(cmpClaim)
  var res: seq[Claim]
  for claim in all:
    if res.len == 0 or res[^1] != claim:
      res.add claim
  res

# ----------------------------------------------------------------------------
# Wire format

type FrameBuilder = object
  data: seq[byte]

func init(T: type FrameBuilder): FrameBuilder =
  FrameBuilder(data: newSeq[byte](8))

func addU8(f: var FrameBuilder, x: uint8) = f.data.add x
func addU64(f: var FrameBuilder, x: uint64) = f.data.add x.toBytesLE()
func addRaw(f: var FrameBuilder, x: openArray[byte]) = f.data.add x
func addBytes(f: var FrameBuilder, x: openArray[byte]) =
  f.addU64(x.len.uint64)
  f.addRaw(x)
func finish(f: var FrameBuilder): seq[byte] =
  let len = uint64(f.data.len - 8).toBytesLE()
  f.data[0 ..< 8] = len
  move(f.data)

type Cursor = object
  data: seq[byte]
  pos: int

func take(c: var Cursor, n: int): Opt[seq[byte]] =
  if n < 0 or c.pos + n > c.data.len:
    return Opt.none(seq[byte])
  let res = c.data[c.pos ..< c.pos + n]
  c.pos += n
  Opt.some res

func u8(c: var Cursor): Opt[uint8] =
  let b = ? c.take(1)
  Opt.some b[0]

func u32(c: var Cursor): Opt[uint32] =
  let b = ? c.take(4)
  Opt.some uint32.fromBytesLE(b)

func u64(c: var Cursor): Opt[uint64] =
  let b = ? c.take(8)
  Opt.some uint64.fromBytesLE(b)

func bytes(c: var Cursor): Opt[seq[byte]] =
  let n = ? c.u64()
  if n > uint64(c.data.len - c.pos):
    return Opt.none(seq[byte])
  c.take(int(n))

func encodeVerify(claims: openArray[byte], proof: openArray[byte]): seq[byte] =
  var f = FrameBuilder.init()
  f.addU8(OpVerify)
  f.addBytes(claims)
  f.addBytes(proof)
  f.finish()

func encodeAggregate(
    children: openArray[(seq[byte], seq[byte])],
    rawXmss: openArray[(XMSSPubkey, Eth2Digest, XMSSSignature)],
    logInvRate: uint8): seq[byte] =
  var f = FrameBuilder.init()
  f.addU8(OpAggregate)
  f.addU8(logInvRate)
  f.addU64(children.len.uint64)
  for (claims, proof) in children:
    f.addBytes(claims)
    f.addBytes(proof)
  f.addU64(rawXmss.len.uint64)
  for (pubkey, message, signature) in rawXmss:
    f.addRaw(pubkey.blob)
    f.addRaw(message.data)
    f.addRaw(signature.blob)
  f.addU64(0) # leanSPHINCS signatures
  f.addU64(0) # blobs
  f.addU8(0)  # output: every covered claim
  f.finish()

func checkHello(body: seq[byte]): Result[void, string] =
  var c = Cursor(data: body)
  let magic = c.take(8).valueOr:
    return err("short hello")
  if magic != @(SidecarMagic.toOpenArrayByte(0, SidecarMagic.high)):
    return err("not a leanVM sidecar")
  let version = c.u32().valueOr:
    return err("short hello")
  if version != SidecarVersion:
    return err("unsupported sidecar protocol version " & $version)
  discard c.u64().valueOr:
    return err("short hello")
  let tag = c.bytes().valueOr:
    return err("short hello")
  if tag != @(SidecarVerifierTag.toOpenArrayByte(0, SidecarVerifierTag.high)):
    return err("sidecar proves for another verifier")
  ok()

func rejection(c: var Cursor, status: uint8): string =
  let msg = c.bytes().valueOr:
    return "status " & $status
  var s = newString(msg.len)
  for i, b in msg:
    s[i] = char(b)
  "status " & $status & ": " & s

# ----------------------------------------------------------------------------
# Blocking transport (verification)

proc recvExact(sock: Socket, n: int, timeoutMs: int): seq[byte] {.
    raises: [OSError, TimeoutError, IOError].} =
  var res = newSeq[byte](n)
  var got = 0
  while got < n:
    var buf = newString(min(n - got, 65536))
    let r = sock.recv(buf, buf.len, timeoutMs)
    if r <= 0:
      raise newException(IOError, "sidecar closed the connection")
    for i in 0 ..< r:
      res[got + i] = byte(buf[i])
    got += r
  res

proc recvFrame(sock: Socket, timeoutMs: int): seq[byte] {.
    raises: [OSError, TimeoutError, IOError].} =
  let len = uint64.fromBytesLE(sock.recvExact(8, timeoutMs))
  if len > 64'u64 * 1024 * 1024:
    raise newException(IOError, "sidecar frame too large")
  sock.recvExact(int(len), timeoutMs)

proc openVerifySocket(): Result[Socket, string] =
  {.cast(gcsafe).}:
    try:
      let sock = newSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP, buffered = false)
      sock.connectUnix(starkConfig.socketPath)
      let hello = sock.recvFrame(starkConfig.verifyTimeoutMs)
      let res = checkHello(hello)
      if res.isErr:
        sock.close()
        return err(res.error)
      ok sock
    except CatchableError as exc:
      err("cannot connect to sidecar at " & starkConfig.socketPath & ": " &
        exc.msg)

proc sidecarVerify(claims, proof: seq[byte]): Result[bool, string] =
  {.cast(gcsafe).}:
    let request = encodeVerify(claims, proof)
    for attempt in 0 .. 1:
      if verifySocket == nil:
        verifySocket = ? openVerifySocket()
      try:
        var data = newString(request.len)
        copyMem(addr data[0], unsafeAddr request[0], request.len)
        verifySocket.send(data)
        let body = verifySocket.recvFrame(starkConfig.verifyTimeoutMs)
        var c = Cursor(data: body)
        let status = c.u8().valueOr:
          return err("malformed sidecar response")
        if status != 0:
          return err("sidecar rejected verification: " & c.rejection(status))
        let verdict = c.u8().valueOr:
          return err("malformed sidecar response")
        return ok(verdict == 1)
      except CatchableError as exc:
        try: verifySocket.close() except CatchableError: discard
        verifySocket = nil
        if attempt == 1:
          return err("sidecar verification failed: " & exc.msg)
    err("unreachable")

# ----------------------------------------------------------------------------
# Async transport (proving)

proc sidecarAggregate(
    children: seq[(seq[byte], seq[byte])],
    rawXmss: seq[(XMSSPubkey, Eth2Digest, XMSSSignature)],
    expectedClaims: seq[byte]
): Future[Result[seq[byte], string]] {.async: (raises: [CancelledError]).} =
  let config = block:
    {.cast(gcsafe).}:
      starkConfig
  {.cast(gcsafe).}:
    if proveLock == nil:
      proveLock = newAsyncLock()
  let lock = block:
    {.cast(gcsafe).}:
      proveLock
  try:
    await lock.acquire()
  except CancelledError as exc:
    raise exc
  defer:
    lock.release2()

  var transp: StreamTransport
  try:
    transp = await connect(initTAddress(config.socketPath))
  except CatchableError as exc:
    return err("cannot connect to sidecar at " & config.socketPath & ": " &
      exc.msg)
  defer:
    await transp.closeWait()

  proc readFrame(): Future[seq[byte]] {.
      async: (raises: [CancelledError, TransportError, AsyncTimeoutError]).} =
    var lenBuf: array[8, byte]
    await transp.readExactly(addr lenBuf[0], 8).wait(config.proveTimeout)
    let len = uint64.fromBytesLE(lenBuf)
    if len > 64'u64 * 1024 * 1024:
      raise newException(TransportError, "sidecar frame too large")
    var body = newSeq[byte](int(len))
    if len > 0:
      await transp.readExactly(addr body[0], int(len)).wait(config.proveTimeout)
    body

  try:
    let hello = await readFrame()
    ? checkHello(hello)
    let request = encodeAggregate(children, rawXmss, config.logInvRate)
    discard await transp.write(request)
    let body = await readFrame()
    var c = Cursor(data: body)
    let status = c.u8().valueOr:
      return err("malformed sidecar response")
    if status != 0:
      return err("sidecar rejected aggregation: " & c.rejection(status))
    let claims = c.bytes().valueOr:
      return err("malformed sidecar response")
    let proof = c.bytes().valueOr:
      return err("malformed sidecar response")
    if claims != expectedClaims:
      return err("sidecar proved other claims than requested")
    ok proof
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    err("sidecar aggregation failed: " & exc.msg)

# ----------------------------------------------------------------------------
# Spec functions

func referenceVerify(
    statements: openArray[XMSSAggregateStatement],
    proof: openArray[byte]): bool =
  var count = 0
  for statement in statements:
    count += statement.pubkeys.len
  if proof.len != count * XMSS_SIGNATURE_SIZE:
    return false
  var offset = 0
  for statement in statements:
    for pubkey in statement.pubkeys:
      var sig: XMSSSignature
      sig.blob[0 ..< XMSS_SIGNATURE_SIZE] =
        proof.toOpenArray(offset, offset + XMSS_SIGNATURE_SIZE - 1)
      offset += XMSS_SIGNATURE_SIZE
      if not verify(pubkey, statement.leaf_index, statement.message.data, sig):
        return false
  true

proc verifyAggregatesImpl(
    statements: openArray[XMSSAggregateStatement],
    proof: openArray[byte]): Result[bool, string] =
  case starkBackend()
  of StarkBackendKind.Reference:
    ok referenceVerify(statements, proof)
  of StarkBackendKind.Sidecar:
    let claims = sortedClaims(statements)
    if claims.len == 0 or proof.len == 0:
      return ok(claims.len == 0 and proof.len == 0)
    sidecarVerify(encodeClaims(claims), @proof)

func verifyAggregates*(
    statements: openArray[XMSSAggregateStatement],
    proof: openArray[byte]): bool =
  ## `stark.VerifyAggregates(statements, proof)`.
  ##
  ## With the sidecar backend, the statements' leaf indices are not checked
  ## (leanVM claims do not include them), and an unreachable sidecar counts as
  ## an invalid proof.
  {.noSideEffect.}:
    let res = verifyAggregatesImpl(statements, proof)
    if res.isErr:
      {.cast(gcsafe).}:
        warn "Cannot verify STARK proof", error = res.error
      false
    else:
      res.get

proc proveAggregates*(
    statements: seq[XMSSAggregateStatement],
    signatures: seq[seq[XMSSSignature]]
): Future[Result[seq[byte], string]] {.async: (raises: [CancelledError]).} =
  ## `stark.ProveAggregates(statements, signatures)`: `signatures` has one
  ## group per statement, one signature per public key, in order.
  if statements.len != signatures.len:
    return err("statements and signature groups differ in number")
  for i, statement in statements:
    if statement.pubkeys.len != signatures[i].len:
      return err("statement " & $i & " has " & $statement.pubkeys.len &
        " public keys but " & $signatures[i].len & " signatures")
    for sig in signatures[i]:
      if sig.getLeafIndex() != statement.leaf_index:
        return err("signature at leaf " & $sig.getLeafIndex() &
          ", expected " & $statement.leaf_index)

  case starkBackend()
  of StarkBackendKind.Reference:
    var proof: seq[byte]
    for i, statement in statements:
      for j, pubkey in statement.pubkeys:
        if not verify(pubkey, statement.leaf_index, statement.message.data,
                      signatures[i][j]):
          return err("invalid signature " & $j & " of statement " & $i)
        proof.add signatures[i][j].blob
    ok proof
  of StarkBackendKind.Sidecar:
    let claims = sortedClaims(statements)
    if claims.len == 0:
      return ok(newSeq[byte]())
    var raw: seq[(XMSSPubkey, Eth2Digest, XMSSSignature)]
    for i, statement in statements:
      for j, pubkey in statement.pubkeys:
        raw.add (pubkey, statement.message, signatures[i][j])
    await sidecarAggregate(@[], raw, encodeClaims(claims))

proc mergeProofs*(
    children: seq[(seq[XMSSAggregateStatement], seq[byte])]
): Future[Result[seq[byte], string]] {.async: (raises: [CancelledError]).} =
  ## `stark.MergeProofs(proofs)`, given each child's statements and proof.
  ## Children are assumed valid: verify untrusted ones first.
  case starkBackend()
  of StarkBackendKind.Reference:
    var proof: seq[byte]
    for (_, childProof) in children:
      proof.add childProof
    ok proof
  of StarkBackendKind.Sidecar:
    var level: seq[(seq[Claim], seq[byte])]
    for i, (statements, proof) in children:
      let claims = sortedClaims(statements)
      if claims.len == 0 and proof.len == 0:
        continue
      if claims.len == 0 or proof.len == 0:
        return err("child " & $i & " has claims without proof or vice versa")
      level.add (claims, proof)
    while level.len > 1:
      var next: seq[(seq[Claim], seq[byte])]
      var i = 0
      while i < level.len:
        let chunk = level[i ..< min(i + MaxChildrenPerAggregate, level.len)]
        i += MaxChildrenPerAggregate
        if chunk.len == 1:
          next.add chunk[0]
          continue
        var
          children: seq[(seq[byte], seq[byte])]
          claimSets: seq[seq[Claim]]
        for (claims, proof) in chunk:
          children.add (encodeClaims(claims), proof)
          claimSets.add claims
        let union = mergeClaims(claimSets)
        let proof = ? await sidecarAggregate(children, @[], encodeClaims(union))
        next.add (union, proof)
      level = next
    if level.len == 0:
      ok(newSeq[byte]())
    else:
      ok(level[0][1])
