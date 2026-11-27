# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## STARK proofs of many XMSS signatures (the spec's `stark` module).
##
## https://github.com/ethereum/consensus-specs/blob/4c296784bb6ff54cbdcf72ebdda2a1057cce8893/specs/_features/pq/beacon-chain.md#new-stark_prove_aggregates
##
## Two backends:
##
## - `leanvm`: proofs of leanVM, which proves and verifies in this process
##   (see `beacon_chain/pq/leanxmss_ffi`). A proof's bytes are leanVM's proof
##   alone; the claims are rebuilt from the statements as the sorted,
##   de-duplicated list of `(pubkey, message)` pairs. The leaf index is not
##   part of a claim. The empty proof stands for "nothing to prove". This is
##   the wire format of the PQ devnet.
## - `reference`: the spec's stand-in, where a proof is the signatures
##   concatenated. For single-client testing only.

import
  std/algorithm,
  chronicles, chronos, chronos/threadsync, results,
  stew/endians2,
  ./digest, ./xmss

export results, xmss, digest

logScope: topics = "pq_stark"

const
  MaxChildrenPerAggregate* = 16
  DefaultLogInvRate* = 2'u8

type
  XMSSAggregateStatement* = object
    pubkeys*: seq[XMSSPubkey]
    leaf_index*: uint64
    message*: Eth2Digest

  StarkBackendKind* {.pure.} = enum
    Reference = "reference"
    LeanVM = "leanvm"

  StarkConfig* = object
    kind*: StarkBackendKind
    logInvRate*: uint8
    threads*: int
      ## Threads of the leanVM prover; 0: one per physical core

  Claim = array[64, byte]

  StarkError* = object of CatchableError

proc leanvm_setup(threads: csize_t): cint {.importc, cdecl.}
proc leanvm_protocol_version(): uint32 {.importc, cdecl.}
proc leanvm_max_children(): csize_t {.importc, cdecl.}
proc leanvm_aggregate(
  request: ptr byte, request_len: csize_t, expected_claims: ptr byte,
  expected_claims_len: csize_t, log_inv_rate: uint8, output: ptr ptr byte,
  output_len: ptr csize_t): cint {.importc, cdecl.}
proc leanvm_free(data: ptr byte, len: csize_t) {.importc, cdecl.}
proc leanvm_verify(
  claims: ptr byte, claims_len: csize_t, proof: ptr byte,
  proof_len: csize_t): cint {.importc, cdecl.}

var
  starkConfig {.global.} = StarkConfig(
    kind: StarkBackendKind.Reference, logInvRate: DefaultLogInvRate)
  proveLock {.global.}: AsyncLock

proc configureStark*(config: StarkConfig): Result[void, string] =
  ## Select the backend. The leanVM prover is started with its threads the
  ## first time it is selected, which takes a moment, and keeps that number
  ## of threads for the life of the process.
  if config.kind == StarkBackendKind.LeanVM:
    if leanvm_max_children() != csize_t(MaxChildrenPerAggregate):
      return err("leanVM merges another number of proofs at a time")
    if leanvm_setup(csize_t(max(config.threads, 0))) != 1:
      return err("the leanVM prover did not start with " & $config.threads &
        " threads")
  {.cast(gcsafe).}:
    starkConfig = config
  ok()

proc starkBackend*(): StarkBackendKind =
  {.cast(gcsafe).}:
    starkConfig.kind

proc starkProtocolVersion*(): uint32 =
  ## The version of leanVM's proof system: proofs of another do not verify.
  leanvm_protocol_version()

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
# leanVM

func addU64(data: var seq[byte], x: uint64) = data.add x.toBytesLE()
func addBytes(data: var seq[byte], x: openArray[byte]) =
  data.addU64(x.len.uint64)
  data.add x

func encodeAggregate(
    children: openArray[(seq[byte], seq[byte])],
    rawXmss: openArray[(XMSSPubkey, Eth2Digest, XMSSSignature)]): seq[byte] =
  ## The request of `leanvm_aggregate`: children as claims and proof, then
  ## signatures as public key, message and signature.
  var res: seq[byte]
  res.addU64(children.len.uint64)
  for (claims, proof) in children:
    res.addBytes(claims)
    res.addBytes(proof)
  res.addU64(rawXmss.len.uint64)
  for (pubkey, message, signature) in rawXmss:
    res.add pubkey.blob
    res.add message.data
    res.add signature.blob
  res

proc leanVerify(claims, proof: openArray[byte]): Result[bool, string] =
  if claims.len == 0 or proof.len == 0:
    return ok(false)
  case leanvm_verify(
    unsafeAddr claims[0], csize_t(claims.len), unsafeAddr proof[0],
    csize_t(proof.len))
  of 1: ok(true)
  of 0: ok(false)
  else: err("leanVM could not verify the proof")

type LeanAggregateTask = object
  request, claims: ptr UncheckedArray[byte]
  requestLen, claimsLen: int
  logInvRate: uint8
  status: cint
  output: ptr byte
  outputLen: csize_t
  signal: ThreadSignalPtr
  thread: Thread[ptr LeanAggregateTask]

proc leanAggregateThread(task: ptr LeanAggregateTask) {.thread.} =
  # A thread of its own that waits for the prover, which works on its own
  # threads: no GC
  task[].status = leanvm_aggregate(
    addr task[].request[0], csize_t(task[].requestLen), addr task[].claims[0],
    csize_t(task[].claimsLen), task[].logInvRate, addr task[].output,
    addr task[].outputLen)
  discard task[].signal.fireSync()

proc leanAggregate(
    children: seq[(seq[byte], seq[byte])],
    rawXmss: seq[(XMSSPubkey, Eth2Digest, XMSSSignature)],
    expectedClaims: seq[byte]
): Future[Result[seq[byte], string]] {.async: (raises: [CancelledError]).} =
  ## Prove off the event loop: a proof takes seconds. The prover makes one
  ## proof at a time, and so do the callers of this.
  let logInvRate = block:
    {.cast(gcsafe).}:
      starkConfig.logInvRate
  {.cast(gcsafe).}:
    if proveLock == nil:
      proveLock = newAsyncLock()
  let lock = block:
    {.cast(gcsafe).}:
      proveLock
  await lock.acquire()
  defer:
    lock.release2()

  let request = encodeAggregate(children, rawXmss)
  if expectedClaims.len == 0:
    return err("nothing to prove")
  let signal = ThreadSignalPtr.new().valueOr:
    return err("cannot create a thread signal: " & error)

  let task = createShared(LeanAggregateTask)
  task[].request = cast[ptr UncheckedArray[byte]](
    createShared(byte, request.len))
  task[].claims = cast[ptr UncheckedArray[byte]](
    createShared(byte, expectedClaims.len))
  copyMem(addr task[].request[0], unsafeAddr request[0], request.len)
  copyMem(addr task[].claims[0], unsafeAddr expectedClaims[0],
    expectedClaims.len)
  task[].requestLen = request.len
  task[].claimsLen = expectedClaims.len
  task[].logInvRate = logInvRate
  task[].signal = signal

  template release() =
    freeShared(task[].request)
    freeShared(task[].claims)
    freeShared(task)
    discard signal.close()

  try:
    createThread(task[].thread, leanAggregateThread, task)
  except ResourceExhaustedError as exc:
    release()
    return err("cannot start a thread: " & exc.msg)
  let fired =
    try:
      await noCancel signal.wait()
      true
    except AsyncError:
      false
  if not fired:
    # The thread may still read the task: the memory is left to it
    return err("lost the thread that proves")
  joinThread(task[].thread)

  var output = newSeq[byte](int(task[].outputLen))
  if output.len > 0:
    copyMem(addr output[0], task[].output, output.len)
  leanvm_free(task[].output, task[].outputLen)
  let status = task[].status
  release()

  if status != 1:
    var reason = newString(output.len)
    for i, b in output:
      reason[i] = char(b)
    return err("leanVM did not prove: " & reason)
  if output.len == 0:
    return err("leanVM returned an empty proof")
  ok output

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
  of StarkBackendKind.LeanVM:
    let claims = sortedClaims(statements)
    if claims.len == 0 or proof.len == 0:
      return ok(claims.len == 0 and proof.len == 0)
    leanVerify(encodeClaims(claims), proof)

func verifyAggregates*(
    statements: openArray[XMSSAggregateStatement],
    proof: openArray[byte]): bool =
  ## `stark.VerifyAggregates(statements, proof)`.
  ##
  ## With the leanVM backend, the statements' leaf indices are not checked
  ## (leanVM claims do not include them), and a verifier that fails counts as
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
  of StarkBackendKind.LeanVM:
    let claims = sortedClaims(statements)
    if claims.len == 0:
      return ok(newSeq[byte]())
    var raw: seq[(XMSSPubkey, Eth2Digest, XMSSSignature)]
    for i, statement in statements:
      for j, pubkey in statement.pubkeys:
        raw.add (pubkey, statement.message, signatures[i][j])
    await leanAggregate(@[], raw, encodeClaims(claims))

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
  of StarkBackendKind.LeanVM:
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
        let proof = ? await leanAggregate(children, @[], encodeClaims(union))
        next.add (union, proof)
      level = next
    if level.len == 0:
      ok(newSeq[byte]())
    else:
      ok(level[0][1])
