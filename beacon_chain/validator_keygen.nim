import
  os, ospaths, strutils, strformat,
  milagro_crypto, nimcrypto, json_serialization,
  spec/[datatypes, digest, crypto], conf, randao, time, ssz,
  ../tests/testutil

proc writeFile(filename: string, value: auto) =
  Json.saveFile(filename, value, pretty = true)
  echo &"Wrote {filename}"

proc genSingleValidator(path: string): (ValidatorPubKey,
                                        ValidatorPrivKey,
                                        Eth2Digest) =
  var v: PrivateValidatorData
  v.privKey = newSigKey()
  if randomBytes(v.randao.seed.data) != sizeof(v.randao.seed.data):
    raise newException(Exception, "Could not generate randao seed")

  writeFile(path, v)

  return (v.privKey.pubKey(), v.privKey, v.randao.initialCommitment)

proc printUsage() =
  echo "Usage: validator_keygen <number-of-validators> <out-path>"

# TODO: Make these more comprehensive and find them a new home
type
  Ether* = distinct int64
  GWei* = distinct int64

template eth*(x: SomeInteger): Ether = Ether(x)
template gwei*(x: Ether): Gwei = Gwei(int(x) * 1000000000)

proc main() =
  if paramCount() != 2:
    printUsage()
    return

  let totalValidators = parseInt paramStr(1)
  if totalValidators < 64:
    echo "The number of validators must be higher than ", EPOCH_LENGTH, " (EPOCH_LENGTH)"
    echo "There must be at least one validator assigned per slot."
    quit 1

  let outPath = paramStr(2)

  var startupData: ChainStartupData

  for i in 1 .. totalValidators:
    let (pubKey, privKey, randaoCommitment) =

      genSingleValidator(outPath / &"validator-{i:02}.json")

    let withdrawalCredentials = makeFakeHash(i)
    let proofOfPossession = signMessage(privkey, hash_tree_root_final(
      (pubKey, withdrawalCredentials, randaoCommitment)).data)

    startupData.validatorDeposits.add Deposit(
      deposit_data: DepositData(
        value: MAX_DEPOSIT * GWEI_PER_ETH,
        timestamp: now(),
        deposit_input: DepositInput(
          pubkey: pubKey,
          proof_of_possession: proofOfPossession,
          withdrawal_credentials: withdrawalCredentials,
          randao_commitment: randaoCommitment)))

  startupData.genesisTime = now()

  writeFile(outPath / "startup.json", startupData)

when isMainModule:
  main()

