import
  ../spec/[crypto, digest]

func parseCmdArg*(T: type Eth2Digest, input: string): T
                 {.raises: [ValueError, Defect].} =
  Eth2Digest.fromHex(input)

func completeCmdArg*(T: type Eth2Digest, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type ValidatorPubKey, input: string): T
                 {.raises: [ValueError, Defect].} =
  let res = ValidatorPubKey.fromHex(input)
  if res.isErr(): raise (ref ValueError)(msg: $res.error())
  res.get()

func completeCmdArg*(T: type ValidatorPubKey, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type ValidatorSig, input: string): T
                 {.raises: [ValueError, Defect].} =
  let res = ValidatorSig.fromHex(input)
  if res.isErr(): raise (ref ValueError)(msg: $res.error())
  res.get()

func completeCmdArg*(T: type ValidatorSig, input: string): seq[string] =
  return @[]
