import spec/digest

type Randao* = object
  seed: Eth2Digest

const MaxRandaoLevels = 10000

proc initRandao*(seed: Eth2Digest): Randao =
  result.seed = seed

proc initRandao*(bytes: openarray[byte]): Randao =
  if bytes.len != sizeof(Eth2Digest):
    raise newException(Exception, "Wrong randao size")
  var s: Eth2Digest
  s.data[0 .. ^1] = bytes
  initRandao(bytes)

func repeatHash*(h: Eth2Digest, n: int): Eth2Digest =
  if n == 0: h
  else: repeatHash(eth2Hash(h.data), n - 1)

iterator items(r: Randao): Eth2Digest =
  var h = r.seed
  for i in 0 .. MaxRandaoLevels:
    yield h
    h = eth2hash(h.data)

proc initialCommitment*(r: Randao): Eth2Digest =
  var i = 0
  for h in r:
    if i == MaxRandaoLevels:
      return h
    inc i

  assert(false, "Unreachable")
  
proc reveal*(r: Randao, commitment: Eth2Digest): Eth2Digest =
  if commitment == r.seed:
    raise newException(Exception, "Randao: cannot reveal for seed")
  result = r.seed
  for h in r:
    if h == commitment:
      return
    result = h

  raise newException(Exception, "Randao: commitment not found")

when isMainModule:
  import times, nimcrypto
  var seed: Eth2Digest
  let r = initRandao(seed)

  var s = epochTime()
  var ic = r.initialCommitment()
  var e = epochTime()
  echo "initialCommitment: ", ic
  echo "Took time: ", e - s
  s = epochTime()
  let rev = r.reveal(ic)
  e = epochTime()
  echo "reveal: ", rev
  echo "Took time: ", e - s

  echo r.reveal(eth2hash([1.byte, 2, 3]))
